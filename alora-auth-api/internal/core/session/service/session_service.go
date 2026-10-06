// Package service owns session lifecycle: opening a login at App Central (a
// CENTRAL family) and a product's login under it (a PRODUCT family), rotating
// their refresh tokens, detecting replay, and revoking — by the user, by an
// administrator, or because the rules that admitted the session no longer hold.
//
// THE MODEL. Each login opens a "family". Every refresh mints a new generation
// in that family, retires its predecessor, and records prev_token_hash +
// replaced_by_id so the chain is walkable in both directions. Because a refresh
// token is single-use, presenting a token that has ALREADY been rotated means
// one of two things:
//
//   - Benign race: the legitimate client fired two refreshes at once (two
//     browser tabs). The second arrives microseconds late. → 409, keep the cookie.
//   - Theft: an attacker replays a token the victim already spent (or vice
//     versa). → burn the family, forcing re-authentication.
//
// Distinguishing these is the whole game: collapse them into one and you either
// log users out constantly, or you leave a stolen token usable.
//
// A product family lives under a central one. Revoking the central family —
// App Central logout, theft of the central token, a policy change — revokes
// every product family under it too; a product's own theft burns only that
// product's family. Every rotation re-checks the whole chain: the family and its
// parent are live, the user and the company are active, the user's login policy
// still allows how they signed in, and for a product the user still has access
// to it.
package service

import (
	"context"
	"errors"
	"time"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	policyservice "github.com/alora/auth/internal/core/policy/service"
	"github.com/alora/auth/internal/core/session/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/sessions"
	sessioncustoms "github.com/alora/auth/internal/database/services/sessions/customs"
	"github.com/alora/auth/internal/exceptions"
	"github.com/google/uuid"
)

// PrevTokenGrace is how long after rotation a superseded token is still treated
// as a benign concurrent request rather than a replay. Must be long enough to
// cover normal client races, short enough that a stolen token is near-useless.
const PrevTokenGrace = 30 * time.Second

// Lifetimes are the durations sessions are opened and renewed with.
type Lifetimes struct {
	CentralIdle     time.Duration // each central refresh extends the session by this
	CentralAbsolute time.Duration // no central session outlives this
	ProductRefresh  time.Duration // each product refresh extends its login by this
}

// SessionService manages session families.
type SessionService interface {
	// CreateCentral opens an App Central session after a sign-in succeeded.
	CreateCentral(ctx context.Context, userID, clientID string, method dbmodels.IdpProvider, connectionID string, m shared.ClientMeta) (models.Issued, error)
	// CreateProduct opens a product's login under a live central session.
	CreateProduct(ctx context.Context, parentFamilyID, userID, clientID, productID string, m shared.ClientMeta) (models.Issued, error)
	// Rotate exchanges a refresh token of the wanted kind for its successor.
	Rotate(ctx context.Context, rawToken string, want models.Want, m shared.ClientMeta) (models.Issued, error)
	// Gate reads the state of one family.
	Gate(ctx context.Context, familyID string) (models.Gate, error)
	// TokenFamily resolves a refresh token to its family, spent or not.
	TokenFamily(ctx context.Context, rawToken string) (models.TokenFamily, error)
	// RevokeTree ends a family and every family under it.
	RevokeTree(ctx context.Context, familyID string, reason dbmodels.RevokeReason) error
	// Logout ends the session a refresh token belongs to, with everything under it.
	Logout(ctx context.Context, rawToken string) error
	// ListActive lists the scope's company's live sessions.
	ListActive(ctx context.Context, scope shared.Scope) ([]models.ActiveSession, error)
	// RevokeByAdmin ends one session family (and those under it) in the scope's company.
	RevokeByAdmin(ctx context.Context, scope shared.Scope, familyID string) error
}

type sessionService struct {
	db     *contexts.DbContext
	audit  auditservice.AuditService
	policy policyservice.PolicyService
	ttl    Lifetimes
}

// NewSessionService builds the session service.
func NewSessionService(db *contexts.DbContext, audit auditservice.AuditService, policy policyservice.PolicyService, ttl Lifetimes) SessionService {
	return &sessionService{db: db, audit: audit, policy: policy, ttl: ttl}
}

func token(m shared.ClientMeta, raw string, expires time.Time) sessions.Token {
	return sessions.Token{
		SessionUUID:      uuid.NewString(),
		RefreshTokenHash: tokens.HashToken(raw), // only the HASH is stored
		ExpiresAt:        expires,
		IPAddress:        m.IP,
		DeviceLabel:      m.DeviceLabel,
		UserAgent:        m.UserAgent,
	}
}

func issued(raw string, s dbmodels.Session) models.Issued {
	out := models.Issued{RawToken: raw, SessionID: s.ID, FamilyID: s.FamilyID, UserID: s.UserID, ClientID: s.ClientID}
	if s.ExpiresAt != nil {
		out.ExpiresAt = *s.ExpiresAt
	}
	return out
}

// CreateCentral opens a NEW central family. Called only after a sign-in has
// already succeeded and its user's policy has allowed the method.
func (s *sessionService) CreateCentral(ctx context.Context, userID, clientID string, method dbmodels.IdpProvider, connectionID string, m shared.ClientMeta) (models.Issued, error) {
	raw, err := tokens.GenerateRefreshToken()
	if err != nil {
		return models.Issued{}, err
	}
	now := time.Now()
	row, err := sessions.NewSessionDbService(s.db).CreateCentral(ctx, sessions.NewCentral{
		UserID: userID, ClientID: clientID, AuthMethod: method, AuthConnectionID: connectionID,
		AbsoluteExpiresAt: now.Add(s.ttl.CentralAbsolute),
		Token:             token(m, raw, now.Add(s.ttl.CentralIdle)),
	})
	if err != nil {
		return models.Issued{}, err
	}
	return issued(raw, row), nil
}

// CreateProduct opens a product's login under a central one. The database
// refuses unless the parent is a live central session of the same user, so a
// code issued under a session that has since ended opens nothing.
func (s *sessionService) CreateProduct(ctx context.Context, parentFamilyID, userID, clientID, productID string, m shared.ClientMeta) (models.Issued, error) {
	raw, err := tokens.GenerateRefreshToken()
	if err != nil {
		return models.Issued{}, err
	}
	row, err := sessions.NewSessionDbService(s.db).CreateProduct(ctx, sessions.NewProduct{
		ParentFamilyID: parentFamilyID, UserID: userID, ClientID: clientID, ProductID: productID,
		Token: token(m, raw, time.Now().Add(s.ttl.ProductRefresh)),
	})
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.Issued{}, exceptions.ErrSessionInvalid
	}
	if err != nil {
		return models.Issued{}, err
	}
	return issued(raw, row), nil
}

// Rotate exchanges a refresh token for its successor.
//
// Runs in a single transaction anchored by SELECT ... FOR UPDATE on the presented
// token's row, which serialises concurrent rotations of the SAME token: the
// second waits for the first to commit, then observes the now-revoked row and
// takes the race branch instead of minting a second successor.
//
// Returns:
//   - exceptions.ErrRotationRace (409) for a benign concurrent rotation, with
//     FamilyID, UserID and ClientID set — the caller MUST leave the token it
//     holds in place, since the other request's successor is valid.
//   - exceptions.ErrSessionInvalid (401) for replay, expiry, an unknown token, a
//     token of another kind or product, or a session whose rules no longer hold
//     — AFTER committing any revocation that implies.
func (s *sessionService) Rotate(ctx context.Context, rawToken string, want models.Want, m shared.ClientMeta) (models.Issued, error) {
	presentedHash := tokens.HashToken(rawToken)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return models.Issued{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	// NOTE: this lookup deliberately has NO revoked_at filter — a revoked match is
	// precisely the signal that distinguishes replay from an unknown token.
	cur, err := sessioncustoms.NewSessionTxCustoms(tx).ByRefreshHashForUpdate(ctx, presentedHash)
	if errors.Is(err, exceptions.ErrNoRows) {
		// The token is not the CURRENT token of any session. It may still be the
		// immediate predecessor of a live successor — the classic two-tab race
		// where this request lost. Only a successor created inside the grace
		// window counts; anything older is a replay of a long-spent token.
		graceCutoff := time.Now().Add(-PrevTokenGrace)
		if succ, gerr := sessioncustoms.NewSessionDbCustoms(tx).GraceSuccessor(ctx, presentedHash, graceCutoff); gerr == nil {
			if g, gerr := s.gate(ctx, tx, succ.FamilyID); gerr == nil && kindMatches(g, want) {
				return models.Issued{FamilyID: succ.FamilyID, UserID: succ.UserID, ClientID: succ.ClientID}, exceptions.ErrRotationRace
			}
		}
		return models.Issued{}, exceptions.ErrSessionInvalid
	}
	if err != nil {
		return models.Issued{}, err
	}

	g, err := s.gate(ctx, tx, cur.FamilyID)
	if err != nil {
		return models.Issued{}, err
	}
	// A token is honoured only where its kind is expected: a product cannot
	// redeem the App Central cookie, nor one product another's token. Refused
	// before the replay check, so a token presented in the wrong place can never
	// be used to burn someone else's session.
	if !kindMatches(g, want) {
		return models.Issued{}, exceptions.ErrSessionInvalid
	}

	// Already-rotated token: race or theft?
	if cur.RevokedAt != nil {
		if s.isBenignRace(ctx, tx, cur) {
			return models.Issued{FamilyID: cur.FamilyID, UserID: cur.UserID, ClientID: cur.ClientID}, exceptions.ErrRotationRace
		}
		// THEFT. Burn the family — for a central token, every product login under
		// it too — then COMMIT before returning the error, or the burn would roll
		// back with the transaction.
		if err := s.commitRevoke(ctx, tx, cur.FamilyID, dbmodels.RevokeReasonReuseDetected); err != nil {
			return models.Issued{}, err
		}
		return models.Issued{}, exceptions.ErrSessionInvalid
	}

	// Expiry is checked in Go against the stored timestamptz (both UTC).
	if cur.ExpiresAt != nil && !time.Now().Before(*cur.ExpiresAt) {
		return models.Issued{}, exceptions.ErrSessionInvalid
	}
	if !g.FamilyAlive || !g.ParentAlive || !g.UserActive || !g.ClientActive {
		return models.Issued{}, exceptions.ErrSessionInvalid
	}
	// The user no longer holds any role in the product, or its subscription
	// lapsed: this login is over. Revoked, so it cannot come back if access does.
	if g.Kind == dbmodels.SessionProduct && !g.HasAccess {
		if err := s.commitRevoke(ctx, tx, g.FamilyID, dbmodels.RevokeReasonAccessLost); err != nil {
			return models.Issued{}, err
		}
		return models.Issued{}, exceptions.ErrSessionInvalid
	}
	// The policy is enforced at every refresh, not only at sign-in: an Owner who
	// switches a company to SSO-only ends its password sessions within one access
	// token's lifetime. The whole sign-in ends, product logins included.
	allowed, err := s.policy.Allows(ctx, g.UserID, g.ClientID, g.AuthMethod, deref(g.AuthConnectionID))
	if err != nil {
		return models.Issued{}, err
	}
	if !allowed {
		root := g.FamilyID
		if g.ParentFamilyID != nil {
			root = *g.ParentFamilyID
		}
		if err := s.commitRevoke(ctx, tx, root, dbmodels.RevokeReasonPolicy); err != nil {
			return models.Issued{}, err
		}
		return models.Issued{}, exceptions.ErrSessionInvalid
	}

	// Normal rotation.
	raw, err := tokens.GenerateRefreshToken()
	if err != nil {
		return models.Issued{}, err
	}
	extend := s.ttl.CentralIdle
	if g.Kind == dbmodels.SessionProduct {
		extend = s.ttl.ProductRefresh
	}
	store := sessions.NewSessionDbService(tx)
	next, err := store.CreateSuccessor(ctx, sessions.Successor{
		UserID:        cur.UserID,
		ClientID:      cur.ClientID,
		FamilyID:      cur.FamilyID, // family is inherited, never regenerated
		Generation:    cur.Generation + 1,
		PrevTokenHash: presentedHash, // enables the grace check above
		Token:         token(m, raw, time.Now().Add(extend)),
	})
	if err != nil {
		// A unique violation on (family_id, generation) means a concurrent rotation
		// won the race between our lock release and this insert. Benign → 409.
		if exceptions.IsUniqueViolation(err) {
			return models.Issued{FamilyID: cur.FamilyID, UserID: cur.UserID, ClientID: cur.ClientID}, exceptions.ErrRotationRace
		}
		return models.Issued{}, err
	}
	// Retire the predecessor. revoked_reason stays NULL: a normal rotation is not
	// a revocation event.
	if err := store.MarkReplaced(ctx, cur.ID, next.ID); err != nil {
		return models.Issued{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.Issued{}, err
	}
	return issued(raw, next), nil
}

func (s *sessionService) gate(ctx context.Context, q contexts.Querier, familyID string) (dbmodels.SessionFamilyGate, error) {
	return sessioncustoms.NewSessionDbCustoms(q).Gate(ctx, familyID)
}

func kindMatches(g dbmodels.SessionFamilyGate, want models.Want) bool {
	if string(g.Kind) != want.Kind {
		return false
	}
	return g.Kind != dbmodels.SessionProduct || (g.ProductID != nil && *g.ProductID == want.ProductID)
}

// commitRevoke revokes a family tree and commits, so the revocation survives the
// error the caller is about to return.
func (s *sessionService) commitRevoke(ctx context.Context, tx *contexts.TxContext, familyID string, reason dbmodels.RevokeReason) error {
	if err := sessions.NewSessionDbService(tx).RevokeTree(ctx, familyID, reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// isBenignRace reports whether an already-revoked session was superseded moments
// ago by a still-live successor — i.e. the legitimate client rotated twice
// concurrently, rather than an attacker replaying a spent token.
func (s *sessionService) isBenignRace(ctx context.Context, tx *contexts.TxContext, cur dbmodels.Session) bool {
	// Outside the grace window this is a replay no matter what the chain says.
	if cur.RevokedAt == nil || cur.RevokedAt.Before(time.Now().Add(-PrevTokenGrace)) {
		return false
	}
	// A session revoked WITHOUT a successor was revoked deliberately (logout,
	// admin action, expiry sweep, or an earlier family burn) — never a race.
	if cur.ReplacedByID == nil {
		return false
	}
	succ, err := sessions.NewSessionDbService(tx).GetByID(ctx, *cur.ReplacedByID)
	if err != nil {
		return false
	}
	// The successor must still be live: if it was itself revoked, the family is
	// already compromised or torn down and this is not a simple race.
	return succ.RevokedAt == nil
}

func (s *sessionService) Gate(ctx context.Context, familyID string) (models.Gate, error) {
	g, err := s.gate(ctx, s.db, familyID)
	if err != nil {
		return models.Gate{}, err
	}
	return toGate(g), nil
}

func toGate(g dbmodels.SessionFamilyGate) models.Gate {
	out := models.Gate{
		FamilyID: g.FamilyID, UserID: g.UserID, ClientID: g.ClientID, Email: g.Email,
		Kind: string(g.Kind), ProductID: deref(g.ProductID), ParentFamilyID: deref(g.ParentFamilyID),
		AuthMethod: string(g.AuthMethod), AuthConnectionID: deref(g.AuthConnectionID),
		PermVersion: g.PermissionsVersion,
		Usable:      g.FamilyAlive && g.ParentAlive && g.UserActive && g.ClientActive && g.HasAccess,
	}
	if g.AuthenticatedAt != nil {
		out.AuthenticatedAt = *g.AuthenticatedAt
	}
	return out
}

func (s *sessionService) TokenFamily(ctx context.Context, rawToken string) (models.TokenFamily, error) {
	row, err := sessioncustoms.NewSessionDbCustoms(s.db).ForLogout(ctx, tokens.HashToken(rawToken))
	if err != nil {
		return models.TokenFamily{}, err
	}
	sess, err := sessions.NewSessionDbService(s.db).GetByID(ctx, row.ID)
	if err != nil {
		return models.TokenFamily{}, err
	}
	g, err := s.Gate(ctx, row.FamilyID)
	if err != nil {
		return models.TokenFamily{}, err
	}
	live := sess.RevokedAt == nil && sess.ExpiresAt != nil && time.Now().Before(*sess.ExpiresAt)
	return models.TokenFamily{Gate: g, TokenLive: live}, nil
}

func (s *sessionService) RevokeTree(ctx context.Context, familyID string, reason dbmodels.RevokeReason) error {
	return sessions.NewSessionDbService(s.db).RevokeTree(ctx, familyID, reason)
}

// Logout ends the session a refresh token belongs to, and every session under
// it: App Central logout ends every product login the browser opened. Idempotent
// by design: logout must always succeed from the client's perspective, so an
// unknown or already-revoked token is not an error (it would leak whether a
// token existed).
func (s *sessionService) Logout(ctx context.Context, rawToken string) error {
	row, err := sessioncustoms.NewSessionDbCustoms(s.db).ForLogout(ctx, tokens.HashToken(rawToken))
	if errors.Is(err, exceptions.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if row.RevokedAt != nil {
		return nil
	}
	return s.RevokeTree(ctx, row.FamilyID, dbmodels.RevokeReasonLogout)
}

// ListActive lists the company's live sessions: App Central sessions and the
// product logins under them.
func (s *sessionService) ListActive(ctx context.Context, scope shared.Scope) ([]models.ActiveSession, error) {
	rows, err := sessioncustoms.NewSessionDbCustoms(s.db).ListFamilies(ctx, scope.ClientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.ActiveSession, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.ActiveSession{
			ID: r.ID, Email: r.Email, Kind: string(r.Kind), ProductKey: r.ProductKey, AuthMethod: string(r.AuthMethod),
			AuthenticatedAt: r.AuthenticatedAt, DeviceLabel: r.DeviceLabel, IPAddress: r.IPAddress,
			LastSeenAt: r.LastSeenAt, CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

// RevokeByAdmin ends one session family in the scope's company — and, for an App
// Central session, every product login under it. A family id from another
// company affects no rows and reports not found.
func (s *sessionService) RevokeByAdmin(ctx context.Context, scope shared.Scope, familyID string) error {
	n, err := sessions.NewSessionDbService(s.db).RevokeFamily(ctx, familyID, scope.ClientID, dbmodels.RevokeReasonAdmin)
	if err != nil {
		return err
	}
	if n == 0 {
		return exceptions.ErrNotFound
	}
	s.audit.Record(scope, "session.revoked")
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
