// Package service handles onboarding: an Admin or the Owner invites an address
// into a company and names the groups the new account joins; the recipient
// redeems a one-time token to create their account.
//
// The raw invite token is generated once, emailed, and NEVER stored — only its
// SHA-256 hash is persisted. A database leak therefore yields no usable invites.
package service

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/invitation/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/password"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/clients"
	groupcustoms "github.com/alora/auth/internal/database/services/groups/customs"
	"github.com/alora/auth/internal/database/services/invitationgroups"
	invitationgroupcustoms "github.com/alora/auth/internal/database/services/invitationgroups/customs"
	"github.com/alora/auth/internal/database/services/invitations"
	invitationcustoms "github.com/alora/auth/internal/database/services/invitations/customs"
	"github.com/alora/auth/internal/database/services/usergroups"
	"github.com/alora/auth/internal/database/services/users"
	usercustoms "github.com/alora/auth/internal/database/services/users/customs"
	"github.com/alora/auth/internal/exceptions"
)

// InviteTTL bounds how long an outstanding invitation stays redeemable.
const InviteTTL = 7 * 24 * time.Hour

// notRedeemable is the one answer for an unknown, expired or used token, so the
// public endpoints cannot be used to probe which tokens exist.
const notRedeemable = "Invitation not found, expired, or already used"

// errPending is the refusal of a second live invitation to one address.
var errPending = exceptions.NewAPIError(http.StatusConflict, "An invitation for this email is already pending", nil)

// Mailer sends the invitation email. *infrastructure.Mailer implements it.
type Mailer interface {
	Enabled() bool
	SendInvitation(to, inviteURL, clientName string, expiresAt time.Time) error
}

// InvitationService issues and redeems invitations.
type InvitationService interface {
	// Create invites an address into the scope's company, into the given groups.
	Create(ctx context.Context, scope shared.Scope, email string, groupIDs []string) (models.Created, error)
	// List lists the scope's company's invitations.
	List(ctx context.Context, scope shared.Scope) ([]models.Listed, error)
	// Revoke cancels a pending invitation in the scope's company.
	Revoke(ctx context.Context, scope shared.Scope, invitationID string) error
	// Lookup previews an invitation for its unauthenticated landing page.
	Lookup(ctx context.Context, rawToken string) (models.Preview, error)
	// Accept redeems an invitation into a password account.
	Accept(ctx context.Context, rawToken, plaintextPassword string) error
	// AcceptFederated redeems an invitation into an account with no password.
	AcceptFederated(ctx context.Context, rawToken string) error
}

type invitationService struct {
	db            *contexts.DbContext
	mail          Mailer
	audit         auditservice.AuditService
	log           *slog.Logger
	frontendURL   string
	googleEnabled bool
}

// NewInvitationService builds the invitation service. log is the base logger;
// the email goroutine tags it with the request id.
func NewInvitationService(db *contexts.DbContext, mail Mailer, audit auditservice.AuditService, log *slog.Logger,
	frontendURL string, googleEnabled bool) InvitationService {
	return &invitationService{db: db, mail: mail, audit: audit, log: log, frontendURL: frontendURL, googleEnabled: googleEnabled}
}

// Create issues an invitation for email within the SCOPE's company. The company
// always comes from the route, never from the request body.
func (s *invitationService) Create(ctx context.Context, scope shared.Scope, email string, groupIDs []string) (models.Created, error) {
	email = shared.NormalizeEmail(email)

	// Refuse if the address already belongs to a live member of this company.
	exists, err := usercustoms.NewUserDbCustoms(s.db).ActiveEmailExists(ctx, scope.ClientID, email)
	if err != nil {
		return models.Created{}, err
	}
	if exists {
		return models.Created{}, exceptions.NewAPIError(http.StatusConflict, "A user with this email already exists", nil)
	}
	// One live invite per address per company, so a re-invite cannot create two
	// independently redeemable tokens. This check answers the common case; the
	// unique index behind the insert below decides when requests race.
	if _, err := invitationcustoms.NewInvitationDbCustoms(s.db).PendingByEmail(ctx, scope.ClientID, email); err == nil {
		return models.Created{}, errPending
	} else if !errors.Is(err, exceptions.ErrNoRows) {
		return models.Created{}, err
	}
	// Every group must be the company's own. De-duplicated first: a repeated
	// group would violate the primary key and abort the whole transaction.
	// Accepting the invitation gives the invitee every scope of every group, so
	// rule 1 applies: the inviter must hold them all (the Admins group gives
	// every scope).
	seen := map[string]bool{}
	var groupList, given []string
	for _, gid := range groupIDs {
		if seen[gid] {
			continue
		}
		seen[gid] = true
		g, err := groupcustoms.NewGroupDbCustoms(s.db).Summary(ctx, gid, scope.ClientID)
		if err != nil {
			if errors.Is(err, exceptions.ErrNoRows) {
				return models.Created{}, exceptions.NewAPIError(http.StatusBadRequest, "No such group in this company", nil)
			}
			return models.Created{}, err
		}
		groupList = append(groupList, gid)
		given = append(given, g.Scopes...)
	}
	if !scope.CanGive(given) {
		return models.Created{}, exceptions.ErrCannotGive
	}

	raw, hash, err := tokens.GenerateInviteToken()
	if err != nil {
		return models.Created{}, err
	}
	expires := time.Now().Add(InviteTTL)
	n := invitations.NewInvitation{Email: email, ClientID: scope.ClientID, TokenHash: hash, ExpiresAt: expires}
	if scope.ByOwner {
		n.InvitedByOwnerID = scope.Actor.UserID
	} else {
		n.InvitedByUserID = scope.Actor.UserID
	}

	// The invite row and its groups appear together: a committed invite without
	// its groups would onboard someone with no access.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return models.Created{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	inv, err := invitations.NewInvitationDbService(tx).Create(ctx, n)
	if exceptions.IsUniqueViolation(err) {
		return models.Created{}, errPending // another invitation to the address won the race
	}
	if err != nil {
		return models.Created{}, err
	}
	for _, gid := range groupList {
		if err := invitationgroups.NewInvitationGroupDbService(tx).Create(ctx, inv.ID, scope.ClientID, gid); err != nil {
			if exceptions.IsForeignKeyViolation(err) {
				// The group was deleted after it was checked above.
				return models.Created{}, exceptions.NewAPIError(http.StatusBadRequest, "No such group in this company", nil)
			}
			return models.Created{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return models.Created{}, err
	}

	created := models.Created{
		ID: inv.ID, Email: email,
		InviteURL: strings.TrimRight(s.frontendURL, "/") + "/accept-invitation?token=" + raw,
		ExpiresAt: expires,
	}
	// Email is best-effort and must never fail the request: when SMTP is not
	// configured the inviter shares invite_url by hand instead.
	if s.mail.Enabled() {
		clientName, _ := clients.NewClientDbService(s.db).NameByID(ctx, scope.ClientID)
		log := s.requestLog(scope.Actor)
		go func(to, url, name string, exp time.Time) {
			defer func() {
				if r := recover(); r != nil && log != nil {
					log.Error("invite email panicked", "recover", r)
				}
			}()
			if err := s.mail.SendInvitation(to, url, name, exp); err != nil && log != nil {
				log.Error("invite email failed", "err", err)
			}
		}(created.Email, created.InviteURL, clientName, created.ExpiresAt)
	}
	s.audit.Record(scope, "invitation.created")
	return created, nil
}

// List returns the company's invitations. token_hash is never projected.
func (s *invitationService) List(ctx context.Context, scope shared.Scope) ([]models.Listed, error) {
	rows, err := invitationcustoms.NewInvitationDbCustoms(s.db).List(ctx, scope.ClientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.Listed, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.Listed{
			ID: r.ID, Email: r.Email, Status: string(r.Status), ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

// Revoke cancels a PENDING invitation. Company-scoped, so an id from another
// organisation affects zero rows and reports 404 rather than acting.
func (s *invitationService) Revoke(ctx context.Context, scope shared.Scope, invitationID string) error {
	n, err := invitations.NewInvitationDbService(s.db).Revoke(ctx, invitationID, scope.ClientID, scope.Actor.UserID)
	if err != nil {
		return err
	}
	if n == 0 {
		return exceptions.ErrNotFound
	}
	s.audit.Record(scope, "invitation.revoked")
	return nil
}

// pending resolves a raw token to a live invitation and the sign-in methods the
// invitee will have.
func (s *invitationService) pending(ctx context.Context, tokenHash string) (dbmodels.PendingInvitation, models.Methods, error) {
	inv, err := invitationcustoms.NewInvitationDbCustoms(s.db).PendingByTokenHash(ctx, tokenHash)
	if errors.Is(err, exceptions.ErrNoRows) {
		return dbmodels.PendingInvitation{}, models.Methods{}, exceptions.NewAPIError(http.StatusBadRequest, notRedeemable, nil)
	}
	if err != nil {
		return dbmodels.PendingInvitation{}, models.Methods{}, err
	}
	p, err := invitationcustoms.NewInvitationDbCustoms(s.db).LoginPolicy(ctx, inv.ID, inv.ClientID)
	if err != nil {
		return dbmodels.PendingInvitation{}, models.Methods{}, err
	}
	return inv, models.Methods{
		Password: p.AllowPassword, Google: p.AllowGoogle && s.googleEnabled, SSO: p.SSOConnectionID != nil,
	}, nil
}

// Lookup renders an invite for its landing page, keyed by the RAW token (hashed
// here). One opaque error for unknown/expired/used, so the endpoint cannot be
// used to probe which tokens exist.
func (s *invitationService) Lookup(ctx context.Context, rawToken string) (models.Preview, error) {
	inv, methods, err := s.pending(ctx, tokens.HashToken(rawToken))
	if err != nil {
		return models.Preview{}, err
	}
	gs, err := invitationgroupcustoms.NewInvitationGroupDbCustoms(s.db).ListForInvitation(ctx, inv.ID)
	if err != nil {
		return models.Preview{}, err
	}
	p := models.Preview{Email: inv.Email, ClientName: inv.ClientName, ExpiresAt: inv.ExpiresAt, Methods: methods}
	for _, g := range gs {
		p.Groups = append(p.Groups, g.GroupName)
	}
	return p, nil
}

// Accept redeems an invitation into a password account — when the policy the
// invitee will sign in under allows passwords at all.
func (s *invitationService) Accept(ctx context.Context, rawToken, plaintextPassword string) error {
	hashToken := tokens.HashToken(rawToken)
	_, methods, err := s.pending(ctx, hashToken)
	if err != nil {
		return err
	}
	if !methods.Password {
		return exceptions.NewAPIError(http.StatusBadRequest, "This organisation does not sign in with a password", nil)
	}
	hash, err := password.Hash(plaintextPassword)
	if err != nil {
		// Over-length input is a client error, not a server fault.
		return exceptions.NewAPIError(http.StatusBadRequest, "Invalid request", err)
	}
	return s.acceptTx(ctx, hashToken, &hash, dbmodels.AccountTypeEmail)
}

// AcceptFederated redeems an invitation into an OAUTH_ONLY account (no
// password), for an invitee who will sign in with Google or company SSO.
//
// The account is created but NOT linked to an external identity yet: linking
// happens on the first sign-in, keyed by the provider's stable subject. That
// ordering means an account is never bound to an identity nobody has seen
// authenticate.
func (s *invitationService) AcceptFederated(ctx context.Context, rawToken string) error {
	hashToken := tokens.HashToken(rawToken)
	inv, methods, err := s.pending(ctx, hashToken)
	if err != nil {
		return err
	}
	if !methods.Google && !methods.SSO {
		return exceptions.NewAPIError(http.StatusBadRequest, "This organisation signs in with a password; set one to accept", nil)
	}
	exists, err := usercustoms.NewUserDbCustoms(s.db).ActiveEmailExists(ctx, inv.ClientID, inv.Email)
	if err != nil {
		return err
	}
	if exists {
		return exceptions.NewAPIError(http.StatusConflict, "An account with this email already exists. Please sign in instead.", nil)
	}
	return s.acceptTx(ctx, hashToken, nil, dbmodels.AccountTypeOAuthOnly)
}

// acceptTx performs the claim, the account creation and the group memberships in
// ONE transaction, so a failure can never leave a consumed invitation with no
// user behind it, nor a user without the access they were invited to. The claim
// is a single atomic UPDATE guarded on status='PENDING' AND unexpired, so two
// concurrent redemptions cannot both create an account.
func (s *invitationService) acceptTx(ctx context.Context, tokenHash string, passwordHash *string, accountType dbmodels.AccountType) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	inv, err := invitationcustoms.NewInvitationDbCustoms(tx).Claim(ctx, tokenHash)
	if errors.Is(err, exceptions.ErrNoRows) {
		return exceptions.NewAPIError(http.StatusBadRequest, notRedeemable, nil)
	}
	if err != nil {
		return err
	}
	user, err := users.NewUserDbService(tx).Create(ctx, inv.ClientID, inv.Email, passwordHash, accountType)
	if err != nil {
		// Someone registered this address between the check and now.
		if exceptions.IsUniqueViolation(err) {
			return exceptions.NewAPIError(http.StatusConflict, "A user with this email already exists", err)
		}
		return err
	}
	gs, err := invitationgroupcustoms.NewInvitationGroupDbCustoms(tx).ListForInvitation(ctx, inv.ID)
	if err != nil {
		return err
	}
	inviter := deref(inv.InvitedByUserID)
	if inviter == "" {
		inviter = deref(inv.InvitedByOwnerID)
	}
	for _, g := range gs {
		if err := usergroups.NewUserGroupDbService(tx).Add(ctx, user.ID, g.GroupID, inv.ClientID, inviter); err != nil {
			return err
		}
	}
	if err := invitations.NewInvitationDbService(tx).SetAcceptedBy(ctx, inv.ID, user.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// requestLog is the base logger tagged with the request id, the same fields the
// request-scoped logger carries.
func (s *invitationService) requestLog(actor shared.Actor) *slog.Logger {
	if s.log == nil {
		return nil
	}
	return s.log.With("reqId", actor.RequestID)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
