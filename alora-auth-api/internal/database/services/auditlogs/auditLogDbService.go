// Package auditlogs is the table service for tbl_audit_logs. It is INSERT-ONLY by
// construction: the query surface has no update or delete for this table, so the
// append-only guarantee cannot be broken from application code.
package auditlogs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// AuditLogDbService is the (insert-only) surface of tbl_audit_logs.
type AuditLogDbService struct{ q *sqlc.Queries }

// NewAuditLogDbService binds the service to a context: the pool or a transaction.
func NewAuditLogDbService(c contexts.Querier) *AuditLogDbService {
	return &AuditLogDbService{q: c.Queries()}
}

// Insert appends one row. A nil pointer stores NULL; a pointer to "" stores "".
func (s *AuditLogDbService) Insert(ctx context.Context, a models.AuditLog) error {
	return s.q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		ClientID:      a.ClientID,
		ActorUserID:   services.TextPtr(a.ActorUserID),
		EventType:     a.EventType,
		EventMetadata: a.EventMetadata,
		IpAddress:     services.TextPtr(a.IPAddress),
		UserAgent:     services.TextPtr(a.UserAgent),
		RequestID:     services.TextPtr(a.RequestID),
	})
}
