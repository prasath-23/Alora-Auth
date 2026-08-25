// Package session owns refresh-token lifecycle: issuing a token family at login,
// rotating it on refresh, detecting replay, and revoking on logout.
//
// THE MODEL. Each login opens a "family" (family_id). Every refresh mints a new
// generation in that family, revokes its predecessor, and records
// prev_token_hash + replaced_by_id so the chain is walkable in both directions.
// Because a refresh token is single-use, presenting a token that has ALREADY been
// rotated means one of two things:
//
//   - Benign race: the legitimate client fired two refreshes at once (two browser
//     tabs). The second arrives microseconds late. → 409, keep the cookie.
//   - Theft: an attacker replays a token the victim already spent (or vice
//     versa). → burn the ENTIRE family, forcing re-authentication everywhere.
//
// Distinguishing these is the whole game: collapse them into one and you either
// log users out constantly, or you leave a stolen token usable.
package session

import (
	"context"
	"errors"
	"time"

	"github.com/alora/auth/internal/crypto/tokens"
	"github.com/alora/auth/internal/platform/database"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PrevTokenGrace is how long after rotation a superseded token is still treated
// as a benign concurrent request rather than a replay. Must be long enough to
// cover normal client races, short enough that a stolen token is near-useless.
const PrevTokenGrace = 30 * time.Second

type Service struct {
	pool       *pgxpool.Pool
	q          *sqlc.Queries
	refreshTTL time.Duration
}

func NewService(pool *pgxpool.Pool, q *sqlc.Queries, refreshTTL time.Duration) *Service {
	return &Service{pool: pool, q: q, refreshTTL: refreshTTL}
}

// RefreshTTL is the lifetime handed to the refresh cookie, so the cookie and the
// stored session always expire together.
func (s *Service) RefreshTTL() time.Duration { return s.refreshTTL }

// Meta is the request fingerprint stored with a session for the admin UI.
type Meta struct {
	IP          string
	UserAgent   string
	DeviceLabel string
}

// Issued is a freshly minted refresh token plus the session backing it.
type Issued struct {
	RawToken  string
	SessionID string
	FamilyID  string
	ExpiresAt time.Time
}

// Create opens a NEW token family. Called only after primary authentication
// (password or federated login) has already succeeded.
func (s *Service) Create(ctx context.Context, userID, clientID string, m Meta) (Issued, error) {
	raw, err := tokens.GenerateRefreshToken()
	if err != nil {
		return Issued{}, err
	}
	expires := time.Now().Add(s.refreshTTL)

	row, err := s.q.CreateSession(ctx, sqlc.CreateSessionParams{
		UserID:      userID,
		ClientID:    clientID,
		SessionUuid: uuid.NewString(),
		FamilyID:    uuid.NewString(),
		// Only the HASH is stored: a database leak must not yield usable tokens.
		RefreshTokenHash: tokens.HashToken(raw),
		ExpiresAt:        database.Timestamptz(expires),
		IpAddress:        database.TextOrNull(m.IP),
		DeviceLabel:      database.TextOrNull(m.DeviceLabel),
		UserAgent:        database.TextOrNull(m.UserAgent),
	})
	if err != nil {
		return Issued{}, err
	}
	return Issued{RawToken: raw, SessionID: row.ID, FamilyID: row.FamilyID, ExpiresAt: expires}, nil
}

// Rotate exchanges a refresh token for its successor.
//
// Runs in a single transaction anchored by SELECT ... FOR UPDATE on the presented
// token's row, which serialises concurrent rotations of the SAME token: the
// second waits for the first to commit, then observes the now-revoked row and
// takes the race branch instead of minting a second successor.
//
// Returns:
//   - httpx.ErrRotationRace (409) for a benign concurrent rotation — the caller
//     MUST leave the cookie intact, since the other request's token is valid.
//   - httpx.ErrSessionInvalid (401) for replay/expiry/unknown, AFTER committing
//     the family burn where applicable.
func (s *Service) Rotate(ctx context.Context, rawToken string, m Meta) (Issued, string, error) {
	presentedHash := tokens.HashToken(rawToken)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Issued{}, "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	qtx := s.q.WithTx(tx)

	// NOTE: this lookup deliberately has NO revoked_at filter — a revoked match is
	// precisely the signal that distinguishes replay from an unknown token.
	cur, err := qtx.GetSessionByRefreshHashForUpdate(ctx, presentedHash)
	if errors.Is(err, pgx.ErrNoRows) {
		// The token is not the CURRENT token of any session. It may still be the
		// immediate predecessor of a live successor — the classic two-tab race
		// where this request lost. Only a successor created inside the grace
		// window counts; anything older is a replay of a long-spent token.
		graceCutoff := time.Now().Add(-PrevTokenGrace)
		if _, gerr := qtx.GetGraceSuccessor(ctx, sqlc.GetGraceSuccessorParams{
			PPrevtokenhash: presentedHash,
			PCreatedafter:  database.Timestamptz(graceCutoff),
		}); gerr == nil {
			return Issued{}, "", httpx.ErrRotationRace
		}
		return Issued{}, "", httpx.ErrSessionInvalid
	}
	if err != nil {
		return Issued{}, "", err
	}

	// Already-rotated token: race or theft?
	if cur.RevokedAt.Valid {
		if s.isBenignRace(ctx, qtx, cur) {
			return Issued{}, "", httpx.ErrRotationRace
		}
		// THEFT. Burn every live session in the family, then COMMIT before
		// returning the error. (The Node original ran this inside a transaction
		// that then threw, so Prisma rolled the revocation back and the family was
		// never actually burned — the bug this port exists to fix.)
		if rerr := qtx.RevokeTokenFamily(ctx, sqlc.RevokeTokenFamilyParams{
			PFamilyid: cur.FamilyID, PReason: string(sqlc.SessionRevokedReasonREUSEDETECTED),
		}); rerr != nil {
			return Issued{}, "", rerr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return Issued{}, "", cerr
		}
		return Issued{}, "", httpx.ErrSessionInvalid
	}

	// Expiry is checked in Go against the stored timestamptz (both UTC).
	if cur.ExpiresAt.Valid && !time.Now().Before(cur.ExpiresAt.Time) {
		return Issued{}, "", httpx.ErrSessionInvalid
	}

	// Normal rotation.
	raw, err := tokens.GenerateRefreshToken()
	if err != nil {
		return Issued{}, "", err
	}
	expires := time.Now().Add(s.refreshTTL)

	next, err := qtx.CreateSuccessorSession(ctx, sqlc.CreateSuccessorSessionParams{
		UserID:           cur.UserID,
		ClientID:         cur.ClientID,
		SessionUuid:      uuid.NewString(),
		FamilyID:         cur.FamilyID, // family is inherited, never regenerated
		Generation:       cur.Generation + 1,
		RefreshTokenHash: tokens.HashToken(raw),
		PrevTokenHash:    database.Text(presentedHash), // enables the grace check above
		ExpiresAt:        database.Timestamptz(expires),
		IpAddress:        database.TextOrNull(m.IP),
		DeviceLabel:      database.TextOrNull(m.DeviceLabel),
		UserAgent:        database.TextOrNull(m.UserAgent),
	})
	if err != nil {
		// A unique violation on (family_id, generation) means a concurrent rotation
		// won the race between our lock release and this insert. Benign → 409.
		if httpx.IsUniqueViolation(err) {
			return Issued{}, "", httpx.ErrRotationRace
		}
		return Issued{}, "", err
	}

	// Retire the predecessor. revoked_reason stays NULL: a normal rotation is not
	// a revocation event, and the parity tests distinguish the two.
	if err := qtx.MarkSessionReplaced(ctx, sqlc.MarkSessionReplacedParams{
		PSessionid: cur.ID, PReplacedbyid: next.ID,
	}); err != nil {
		return Issued{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return Issued{}, "", err
	}

	return Issued{RawToken: raw, SessionID: next.ID, FamilyID: next.FamilyID, ExpiresAt: expires},
		cur.UserID, nil
}

// isBenignRace reports whether an already-revoked session was superseded moments
// ago by a still-live successor — i.e. the legitimate client rotated twice
// concurrently, rather than an attacker replaying a spent token.
func (s *Service) isBenignRace(ctx context.Context, qtx *sqlc.Queries, cur sqlc.TblUserSession) bool {
	// Outside the grace window this is a replay no matter what the chain says.
	if !cur.RevokedAt.Valid || cur.RevokedAt.Time.Before(time.Now().Add(-PrevTokenGrace)) {
		return false
	}
	// A session revoked WITHOUT a successor was revoked deliberately (logout,
	// admin action, expiry sweep, or an earlier family burn) — never a race.
	if !cur.ReplacedByID.Valid {
		return false
	}
	succ, err := qtx.GetSessionById(ctx, cur.ReplacedByID.String)
	if err != nil {
		return false
	}
	// The successor must still be live: if it was itself revoked, the family is
	// already compromised or torn down and this is not a simple race.
	return !succ.RevokedAt.Valid
}

// Revoke ends one session by its raw refresh token. Idempotent by design: logout
// must always succeed from the client's perspective, so an unknown or
// already-revoked token is not an error (it would leak whether a token existed).
func (s *Service) Revoke(ctx context.Context, rawToken string) error {
	row, err := s.q.GetSessionForLogout(ctx, tokens.HashToken(rawToken))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if row.RevokedAt.Valid {
		return nil
	}
	_, err = s.q.RevokeSession(ctx, sqlc.RevokeSessionParams{
		SessionID: row.ID, ClientID: row.ClientID, Reason: sqlc.SessionRevokedReasonLOGOUT,
	})
	return err
}
