// Package service implements administrator-issued password resets: an Admin (or
// anyone holding users:edit, or the Owner) mints a one-time token for a
// user, the user redeems it to set a new password.
//
// Only the SHA-256 hash of the token is stored, and redemption is single-use.
package service

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/reset/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/password"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/passwordresettokens"
	tokencustoms "github.com/alora/auth/internal/database/services/passwordresettokens/customs"
	"github.com/alora/auth/internal/database/services/sessions"
	"github.com/alora/auth/internal/database/services/users"
	usercustoms "github.com/alora/auth/internal/database/services/users/customs"
	userscopecustoms "github.com/alora/auth/internal/database/services/userscopes/customs"
	"github.com/alora/auth/internal/exceptions"
)

// ResetTTL is deliberately short — a reset token is a full account takeover
// primitive, so its window is measured in minutes, not days like an invite.
const ResetTTL = 60 * time.Minute

// invalidReset is the one answer for every failed redemption.
const invalidReset = "Invalid or expired reset token"

// Mailer sends the reset email. *infrastructure.Mailer implements it.
type Mailer interface {
	Enabled() bool
	SendPasswordReset(to, resetURL string, expiresAt time.Time) error
}

// ResetService issues and redeems password resets.
type ResetService interface {
	// Issue mints a reset link for a user in the scope's company.
	Issue(ctx context.Context, scope shared.Scope, userID string) (models.Issued, error)
	// Consume redeems a reset token and sets the new password.
	Consume(ctx context.Context, rawToken, newPassword string) error
}

type resetService struct {
	db          *contexts.DbContext
	mail        Mailer
	audit       auditservice.AuditService
	log         *slog.Logger
	frontendURL string
	isProd      bool
}

// NewResetService builds the reset service. log is the base logger; the email
// goroutine tags it with the request id. In production a reset link is only
// ever emailed, never returned.
func NewResetService(db *contexts.DbContext, mail Mailer, audit auditservice.AuditService, log *slog.Logger, frontendURL string, isProd bool) ResetService {
	return &resetService{db: db, mail: mail, audit: audit, log: log, frontendURL: frontendURL, isProd: isProd}
}

// errNoMail is the answer in production when there is no way to deliver a link:
// handing it back over the API instead would put an account-takeover primitive
// in a response body.
var errNoMail = exceptions.NewAPIError(http.StatusServiceUnavailable, "Email delivery is not configured", nil)

// Issue mints a reset token for a user in the SCOPE's company.
//
// Any previously outstanding token for that user is deleted first, so exactly
// one reset link is ever live: otherwise re-issuing a reset would leave the
// earlier link (possibly already leaked) still redeemable. A reset is a
// takeover of the account, so rule 2 applies: nobody resets someone with more
// access than they have (the Owner excepted).
func (s *resetService) Issue(ctx context.Context, scope shared.Scope, userID string) (models.Issued, error) {
	user, err := usercustoms.NewUserDbCustoms(s.db).TenantScoped(ctx, userID, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.Issued{}, exceptions.ErrNotFound // another company's is indistinguishable from missing
	}
	if err != nil {
		return models.Issued{}, err
	}
	// Rule 2 by reach: a group's manager counts as holding what the groups they
	// run give.
	reach, err := userscopecustoms.NewUserScopeDbCustoms(s.db).Reach(ctx, scope.ClientID, userID)
	if err != nil {
		return models.Issued{}, err
	}
	if !scope.CanManage(reach, user.IsOwner) {
		return models.Issued{}, exceptions.ErrCannotManage
	}
	if !s.mail.Enabled() && s.isProd {
		return models.Issued{}, errNoMail
	}

	raw, err := tokens.GenerateOpaque()
	if err != nil {
		return models.Issued{}, err
	}
	expires := time.Now().Add(ResetTTL)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return models.Issued{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	resets := passwordresettokens.NewPasswordResetTokenDbService(tx)
	if err := resets.DeleteUnused(ctx, userID); err != nil {
		return models.Issued{}, err
	}
	if _, err := resets.Create(ctx, userID, scope.ClientID, tokens.HashToken(raw), expires, scope.Actor.UserID); err != nil {
		return models.Issued{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.Issued{}, err
	}

	resetURL := strings.TrimRight(s.frontendURL, "/") + "/reset-password?token=" + raw
	issued := models.Issued{ExpiresAt: expires}
	if s.mail.Enabled() {
		// Detached goroutine: SMTP latency and outages stay off the response path.
		log := s.requestLog(scope.Actor)
		to, url, exp := user.Email, resetURL, expires
		go func() {
			defer func() {
				if r := recover(); r != nil && log != nil {
					log.Error("reset email panicked", "recover", r)
				}
			}()
			if err := s.mail.SendPasswordReset(to, url, exp); err != nil && log != nil {
				log.Error("reset email failed", "err", err)
			}
		}()
	} else {
		// Outside production, with no mail configured, the link is handed back so
		// a development setup can still reset a password.
		issued.ResetURL = &resetURL
	}

	s.audit.Record(scope, "password.reset_issued")
	return issued, nil
}

// Consume redeems a reset token and sets the new password.
//
// Runs in one transaction: the token row is locked with FOR UPDATE and its
// `used_at IS NULL` guard is re-evaluated under that lock, so two concurrent
// redemptions of a leaked token serialise and the second finds no row. The
// password write and the burn therefore cannot diverge.
//
// Every failure returns ONE generic message: distinguishing "unknown token" from
// "expired" from "deactivated user" would turn this public endpoint into an
// oracle for valid tokens and account states.
func (s *resetService) Consume(ctx context.Context, rawToken, newPassword string) error {
	if newPassword == "" {
		return exceptions.NewAPIError(400, invalidReset, nil)
	}
	hash, err := password.Hash(newPassword)
	if err != nil {
		return exceptions.NewAPIError(400, invalidReset, err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	row, err := tokencustoms.NewPasswordResetTokenTxCustoms(tx).ValidForUpdate(ctx, tokens.HashToken(rawToken))
	if errors.Is(err, exceptions.ErrNoRows) {
		return exceptions.NewAPIError(400, invalidReset, nil)
	}
	if err != nil {
		return err
	}
	// A deprovisioned account must not be revivable through a stale reset link.
	if !row.IsActive || row.DeletedAt != nil {
		return exceptions.NewAPIError(400, invalidReset, nil)
	}

	accounts := users.NewUserDbService(tx)
	if err := accounts.SetPassword(ctx, row.UserID, row.ClientID, hash); err != nil {
		return err
	}
	if err := passwordresettokens.NewPasswordResetTokenDbService(tx).MarkUsed(ctx, row.ID); err != nil {
		return err
	}

	// Changing a password must end every existing session — at App Central and
	// in every product: if the reset was triggered because the account was
	// compromised, leaving the attacker's sessions alive would defeat the point.
	if _, err := sessions.NewSessionDbService(tx).RevokeAllForUser(ctx, row.UserID, dbmodels.RevokeReasonLogoutAll); err != nil {
		return err
	}
	// Bump permissions_version so product introspection reports the product
	// tokens already issued as inactive.
	if err := accounts.BumpPermissionsVersion(ctx, row.UserID, row.ClientID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// requestLog is the base logger tagged with the request id, the same fields the
// request-scoped logger carries.
func (s *resetService) requestLog(actor shared.Actor) *slog.Logger {
	if s.log == nil {
		return nil
	}
	return s.log.With("reqId", actor.RequestID)
}
