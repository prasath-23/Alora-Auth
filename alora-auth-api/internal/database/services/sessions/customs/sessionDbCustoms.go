// Package customs holds the session queries beyond CRUD: lookups by token hash,
// the family gate, the admin list, the expiry sweep, and the locking read that
// serialises rotations.
package customs

import (
	"context"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/services/sessions"
	"github.com/alora/auth/internal/database/sqlc"
)

// SessionDbCustoms is the custom query surface of tbl_user_sessions.
type SessionDbCustoms struct{ q *sqlc.Queries }

// NewSessionDbCustoms binds the queries to a context: the pool or a transaction.
func NewSessionDbCustoms(c contexts.Querier) *SessionDbCustoms {
	return &SessionDbCustoms{q: c.Queries()}
}

// GraceSuccessor finds a still-live successor of prevTokenHash created after
// createdAfter: the mark of a benign two-tab race.
func (s *SessionDbCustoms) GraceSuccessor(ctx context.Context, prevTokenHash string, createdAfter time.Time) (models.Session, error) {
	row, err := s.q.GetGraceSuccessor(ctx, sqlc.GetGraceSuccessorParams{
		PPrevtokenhash: prevTokenHash, PCreatedafter: services.Timestamptz(createdAfter),
	})
	if err != nil {
		return models.Session{}, err
	}
	return sessions.FromRow(row), nil
}

// ForLogout finds the session a refresh token belongs to, revoked or not.
func (s *SessionDbCustoms) ForLogout(ctx context.Context, tokenHash string) (models.SessionOwner, error) {
	r, err := s.q.GetSessionForLogout(ctx, tokenHash)
	if err != nil {
		return models.SessionOwner{}, err
	}
	return models.SessionOwner{
		ID: r.ID, FamilyID: r.FamilyID, UserID: r.UserID, ClientID: r.ClientID,
		RevokedAt: services.TimePtr(r.RevokedAt), RefreshTokenHash: r.RefreshTokenHash,
	}, nil
}

// Gate reads everything that decides whether a family may still be used: its own
// and its parent's liveness, the user's and the company's, access to its
// product, and what the user may do: their App Central scopes, and whether they
// administer the company or the platform.
func (s *SessionDbCustoms) Gate(ctx context.Context, familyID string) (models.SessionFamilyGate, error) {
	r, err := s.q.GetSessionFamilyGate(ctx, familyID)
	if err != nil {
		return models.SessionFamilyGate{}, err
	}
	return models.SessionFamilyGate{
		FamilyID: r.FamilyID, UserID: r.UserID, ClientID: r.ClientID, Kind: models.SessionKind(r.Kind),
		ProductID: services.StringPtr(r.ProductID), ParentFamilyID: services.StringPtr(r.ParentFamilyID),
		AuthMethod: models.IdpProvider(r.AuthMethod), AuthConnectionID: services.StringPtr(r.AuthConnectionID),
		AuthenticatedAt:   services.TimePtr(r.AuthenticatedAt),
		AbsoluteExpiresAt: services.TimePtr(r.AbsoluteExpiresAt),
		FamilyAlive:       r.FamilyAlive, ParentAlive: r.ParentAlive,
		UserActive: r.UserActive, ClientActive: r.ClientActive,
		Email: r.Email, PermissionsVersion: r.PermissionsVersion,
		IsTenantAdmin: r.IsTenantAdmin, IsPlatformOwner: r.IsPlatformOwner, HasAccess: r.HasAccess,
		AdminVersion: r.AdminVersion, Scopes: r.Scopes,
	}, nil
}

// ListFamilies lists a company's live session families, most recently used first.
func (s *SessionDbCustoms) ListFamilies(ctx context.Context, clientID string) ([]models.SessionFamilySummary, error) {
	rows, err := s.q.ListSessionFamilies(ctx, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.SessionFamilySummary, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.SessionFamilySummary{
			ID: r.ID, ClientID: r.ClientID, Kind: models.SessionKind(r.Kind),
			ProductKey: services.StringPtr(r.ProductKey), AuthMethod: models.IdpProvider(r.AuthMethod),
			AuthenticatedAt: services.TimePtr(r.AuthenticatedAt), CreatedAt: services.TimePtr(r.CreatedAt),
			DeviceLabel: r.DeviceLabel, IPAddress: r.IpAddress, LastSeenAt: services.TimePtr(r.LastSeenAt),
			Email: r.Email,
		})
	}
	return out, nil
}

// ExpireStale marks up to batch timed-out sessions, and families past their
// absolute expiry, revoked.
func (s *SessionDbCustoms) ExpireStale(ctx context.Context, batch int32) error {
	return s.q.ExpireSessions(ctx, batch)
}

// SessionTxCustoms holds the queries that take row locks. It can only be built
// from a transaction, so a FOR UPDATE read outside one is a compile error rather
// than a lock silently released the moment the statement ends.
type SessionTxCustoms struct{ q *sqlc.Queries }

// NewSessionTxCustoms binds the locking queries to a transaction.
func NewSessionTxCustoms(tx *contexts.TxContext) *SessionTxCustoms {
	return &SessionTxCustoms{q: tx.Queries()}
}

// ByRefreshHashForUpdate locks the session holding a refresh token. It has no
// revoked_at filter: a revoked match is exactly what tells replay from an
// unknown token.
func (s *SessionTxCustoms) ByRefreshHashForUpdate(ctx context.Context, tokenHash string) (models.Session, error) {
	row, err := s.q.GetSessionByRefreshHashForUpdate(ctx, tokenHash)
	if err != nil {
		return models.Session{}, err
	}
	return sessions.FromRow(row), nil
}
