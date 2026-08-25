package audit

import (
	"context"

	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/jackc/pgx/v5/pgtype"
)

// Repo is the sqlc-backed audit Writer. INSERT-ONLY by construction: the
// generated query surface contains no UPDATE or DELETE for tbl_audit_logs, so
// the append-only guarantee cannot be violated from application code.
type Repo struct{ q *sqlc.Queries }

func NewRepo(q *sqlc.Queries) *Repo { return &Repo{q: q} }

func (r *Repo) Insert(ctx context.Context, e Entry) error {
	return r.q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		ClientID:      e.ClientID,
		ActorUserID:   text(e.ActorUserID),
		EventType:     e.EventType,
		EventMetadata: e.Metadata,
		IpAddress:     text(e.IP),
		UserAgent:     text(e.UserAgent),
		RequestID:     text(e.RequestID),
	})
}

// text maps a *string to pgtype.Text so a Go nil becomes SQL NULL rather than "".
func text(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *s, Valid: true}
}
