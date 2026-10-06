// Package loginstates is the table service for tbl_login_states: the pending
// sign-ins (a round trip to Google or an SSO provider) and account choices. Only
// a state's hash is stored, and each is redeemed once.
package loginstates

import (
	"context"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// LoginStateDbService is the surface of tbl_login_states.
type LoginStateDbService struct{ q *sqlc.Queries }

// NewLoginStateDbService binds the service to a context: the pool or a
// transaction.
func NewLoginStateDbService(c contexts.Querier) *LoginStateDbService {
	return &LoginStateDbService{q: c.Queries()}
}

// NewState is a pending sign-in to store. An empty string or a nil slice or
// pointer stores NULL.
type NewState struct {
	StateHash        string
	Kind             models.LoginStateKind
	ConnectionID     string
	Nonce            string
	CodeVerifier     string
	ReturnTo         string
	CandidateUserIDs []string
	AuthMethod       *models.IdpProvider
	ExpiresAt        time.Time
}

// Create stores a pending sign-in.
func (s *LoginStateDbService) Create(ctx context.Context, n NewState) error {
	return s.q.CreateLoginState(ctx, sqlc.CreateLoginStateParams{
		StateHash: n.StateHash, Kind: sqlc.LoginStateKind(n.Kind),
		ConnectionID: services.TextOrNull(n.ConnectionID), Nonce: services.TextOrNull(n.Nonce),
		CodeVerifier: services.TextOrNull(n.CodeVerifier), ReturnTo: services.TextOrNull(n.ReturnTo),
		CandidateUserIds: n.CandidateUserIDs, AuthMethod: services.NullProvider(n.AuthMethod),
		ExpiresAt: services.Timestamptz(n.ExpiresAt),
	})
}

// Take consumes a live state of the given kind in one DELETE ... RETURNING, so a
// replayed callback finds nothing.
func (s *LoginStateDbService) Take(ctx context.Context, stateHash string, kind models.LoginStateKind) (models.LoginState, error) {
	r, err := s.q.TakeLoginState(ctx, sqlc.TakeLoginStateParams{StateHash: stateHash, Kind: sqlc.LoginStateKind(kind)})
	if err != nil {
		return models.LoginState{}, err
	}
	return fromRow(r), nil
}

// Get reads a live state WITHOUT consuming it: the account chooser shows its
// candidates before the choice is made.
func (s *LoginStateDbService) Get(ctx context.Context, stateHash string, kind models.LoginStateKind) (models.LoginState, error) {
	r, err := s.q.GetLoginState(ctx, sqlc.GetLoginStateParams{StateHash: stateHash, Kind: sqlc.LoginStateKind(kind)})
	if err != nil {
		return models.LoginState{}, err
	}
	return fromRow(r), nil
}

// Cleanup deletes expired states and reports how many.
func (s *LoginStateDbService) Cleanup(ctx context.Context) (int32, error) {
	return s.q.CleanupLoginStates(ctx)
}

func fromRow(r sqlc.TblLoginState) models.LoginState {
	return models.LoginState{
		StateHash: r.StateHash, Kind: models.LoginStateKind(r.Kind),
		ConnectionID: services.StringPtr(r.ConnectionID), Nonce: services.StringPtr(r.Nonce),
		CodeVerifier: services.StringPtr(r.CodeVerifier), ReturnTo: services.StringPtr(r.ReturnTo),
		CandidateUserIDs: r.CandidateUserIds, AuthMethod: services.ProviderPtr(r.AuthMethod),
		ExpiresAt: services.TimePtr(r.ExpiresAt), CreatedAt: services.TimePtr(r.CreatedAt),
	}
}
