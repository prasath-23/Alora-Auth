// Package sessions is the table service for tbl_user_sessions and the session
// families they belong to. A CENTRAL family is a login at App Central; a PRODUCT
// family is one product's login held under it. Lookups by token hash, the gate,
// the locking read and the sweeps live in customs.
package sessions

import (
	"context"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// SessionDbService is the CRUD surface of tbl_user_sessions and
// tbl_session_families.
type SessionDbService struct{ q *sqlc.Queries }

// NewSessionDbService binds the service to a context: the pool or a transaction.
func NewSessionDbService(c contexts.Querier) *SessionDbService {
	return &SessionDbService{q: c.Queries()}
}

// Token is one refresh token to store. Only its hash is stored, never the token.
// An empty IPAddress, DeviceLabel or UserAgent stores NULL.
type Token struct {
	SessionUUID      string
	RefreshTokenHash string
	ExpiresAt        time.Time // capped in SQL at the family's absolute expiry
	IPAddress        string
	DeviceLabel      string
	UserAgent        string
}

// NewCentral is a login at App Central: a new CENTRAL family and its first token.
type NewCentral struct {
	UserID            string
	ClientID          string
	AuthMethod        models.IdpProvider
	AuthConnectionID  string // the SSO connection for an OIDC login, else ""
	AbsoluteExpiresAt time.Time
	Token
}

// CreateCentral opens a CENTRAL family and returns its first session.
func (s *SessionDbService) CreateCentral(ctx context.Context, n NewCentral) (models.Session, error) {
	row, err := s.q.CreateCentralFamily(ctx, sqlc.CreateCentralFamilyParams{
		UserID:            n.UserID,
		ClientID:          n.ClientID,
		AuthMethod:        sqlc.IdpProvider(n.AuthMethod),
		AuthConnectionID:  services.TextOrNull(n.AuthConnectionID),
		AbsoluteExpiresAt: services.Timestamptz(n.AbsoluteExpiresAt),
		SessionUuid:       n.SessionUUID,
		RefreshTokenHash:  n.RefreshTokenHash,
		ExpiresAt:         services.Timestamptz(n.ExpiresAt),
		IpAddress:         services.TextOrNull(n.IPAddress),
		DeviceLabel:       services.TextOrNull(n.DeviceLabel),
		UserAgent:         services.TextOrNull(n.UserAgent),
	})
	if err != nil {
		return models.Session{}, err
	}
	return FromRow(row), nil
}

// NewProduct is a product's login: a PRODUCT family under a central one.
type NewProduct struct {
	ParentFamilyID string
	UserID         string
	ClientID       string
	ProductID      string
	Token
}

// CreateProduct opens a PRODUCT family under a live CENTRAL family of the same
// user and returns its first session. It inherits the parent's sign-in method,
// time and absolute expiry. When the parent is no longer a live central login of
// that user it yields no rows, and nothing is written.
func (s *SessionDbService) CreateProduct(ctx context.Context, n NewProduct) (models.Session, error) {
	row, err := s.q.CreateProductFamily(ctx, sqlc.CreateProductFamilyParams{
		ParentFamilyID:   n.ParentFamilyID,
		UserID:           n.UserID,
		ClientID:         n.ClientID,
		ProductID:        n.ProductID,
		SessionUuid:      n.SessionUUID,
		RefreshTokenHash: n.RefreshTokenHash,
		ExpiresAt:        services.Timestamptz(n.ExpiresAt),
		IpAddress:        services.TextOrNull(n.IPAddress),
		DeviceLabel:      services.TextOrNull(n.DeviceLabel),
		UserAgent:        services.TextOrNull(n.UserAgent),
	})
	if err != nil {
		return models.Session{}, err
	}
	return FromRow(row), nil
}

// Successor is the next generation of an existing family.
type Successor struct {
	UserID        string
	ClientID      string
	FamilyID      string
	Generation    int32
	PrevTokenHash string
	Token
}

// CreateSuccessor inserts the next generation of a family. A unique violation on
// (family_id, generation) means a concurrent rotation already won.
func (s *SessionDbService) CreateSuccessor(ctx context.Context, n Successor) (models.Session, error) {
	row, err := s.q.CreateSuccessorSession(ctx, sqlc.CreateSuccessorSessionParams{
		UserID:           n.UserID,
		ClientID:         n.ClientID,
		SessionUuid:      n.SessionUUID,
		FamilyID:         n.FamilyID,
		Generation:       n.Generation,
		RefreshTokenHash: n.RefreshTokenHash,
		PrevTokenHash:    services.Text(n.PrevTokenHash),
		ExpiresAt:        services.Timestamptz(n.ExpiresAt),
		IpAddress:        services.TextOrNull(n.IPAddress),
		DeviceLabel:      services.TextOrNull(n.DeviceLabel),
		UserAgent:        services.TextOrNull(n.UserAgent),
	})
	if err != nil {
		return models.Session{}, err
	}
	return FromRow(row), nil
}

// GetByID reads one session, revoked or not.
func (s *SessionDbService) GetByID(ctx context.Context, sessionID string) (models.Session, error) {
	row, err := s.q.GetSessionById(ctx, sessionID)
	if err != nil {
		return models.Session{}, err
	}
	return FromRow(row), nil
}

// MarkReplaced retires a rotated session and links it to its successor. The
// revocation reason stays NULL: a rotation is not a revocation event.
func (s *SessionDbService) MarkReplaced(ctx context.Context, sessionID, replacedByID string) error {
	return s.q.MarkSessionReplaced(ctx, sqlc.MarkSessionReplacedParams{PSessionid: sessionID, PReplacedbyid: replacedByID})
}

// RevokeFamily ends a family within a company, together with every family under
// it, and reports how many families it ended: zero means no such live family in
// that company.
func (s *SessionDbService) RevokeFamily(ctx context.Context, familyID, clientID string, reason models.RevokeReason) (int32, error) {
	return s.q.RevokeSessionFamily(ctx, sqlc.RevokeSessionFamilyParams{
		FamilyID: familyID, ClientID: clientID, Reason: sqlc.SessionRevokedReason(reason),
	})
}

// RevokeTree ends a family and every family under it, by id alone. It is for the
// paths that reached the family through one of its own tokens, which is what
// proves the family is the caller's to end.
func (s *SessionDbService) RevokeTree(ctx context.Context, familyID string, reason models.RevokeReason) error {
	return s.q.RevokeTokenFamily(ctx, sqlc.RevokeTokenFamilyParams{PFamilyid: familyID, PReason: string(reason)})
}

// RevokeAllForUser ends every live session of a user, central and product alike.
func (s *SessionDbService) RevokeAllForUser(ctx context.Context, userID string, reason models.RevokeReason) (int32, error) {
	return s.q.RevokeAllUserSessions(ctx, sqlc.RevokeAllUserSessionsParams{
		UserID: userID, Reason: sqlc.SessionRevokedReason(reason),
	})
}

// RevokeAllForClient ends every live session of a whole company, central and
// product alike. It is used when a company is suspended, deactivated or
// cancelled, so its logins END rather than merely being gated by is_active and
// revived the moment the company is reinstated.
func (s *SessionDbService) RevokeAllForClient(ctx context.Context, clientID string, reason models.RevokeReason) (int32, error) {
	return s.q.RevokeAllClientSessions(ctx, sqlc.RevokeAllClientSessionsParams{
		ClientID: clientID, Reason: sqlc.SessionRevokedReason(reason),
	})
}

// FromRow converts a tbl_user_sessions row. Exported for the customs queries,
// which return the same row type.
func FromRow(r sqlc.TblUserSession) models.Session {
	return models.Session{
		ID: r.ID, UserID: r.UserID, ClientID: r.ClientID, SessionUUID: r.SessionUuid,
		FamilyID: r.FamilyID, Generation: r.Generation, RefreshTokenHash: r.RefreshTokenHash,
		PrevTokenHash: services.StringPtr(r.PrevTokenHash), ExpiresAt: services.TimePtr(r.ExpiresAt),
		RevokedAt: services.TimePtr(r.RevokedAt), RevokedReason: services.RevokeReasonPtr(r.RevokedReason),
		IPAddress: services.StringPtr(r.IpAddress), DeviceLabel: services.StringPtr(r.DeviceLabel),
		UserAgent: services.StringPtr(r.UserAgent), LastSeenAt: services.TimePtr(r.LastSeenAt),
		CreatedAt: services.TimePtr(r.CreatedAt), ReplacedByID: services.StringPtr(r.ReplacedByID),
	}
}
