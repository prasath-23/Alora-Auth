// Package service writes append-only audit records without ever blocking or
// failing the request that triggered them.
package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/alora/auth/internal/core/audit/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/auditlogs"
)

// AuditService records audit events.
type AuditService interface {
	// Log records one event fire-and-forget.
	Log(e models.Entry)
	// Record logs an event performed in a scope: the shape every audited action
	// uses.
	Record(scope shared.Scope, event string)
	// RecordWith is Record with details of what was done, kept in the event's
	// metadata beside who did it.
	RecordWith(scope shared.Scope, event string, details map[string]any)
}

type auditService struct {
	db  *contexts.DbContext
	log *slog.Logger
}

// NewAuditService builds the audit writer.
func NewAuditService(db *contexts.DbContext, log *slog.Logger) AuditService {
	return &auditService{db: db, log: log}
}

// Log records an audit event fire-and-forget.
//
// It deliberately does NOT take the request context: that context is cancelled
// the moment the response is written, which would abort the insert
// non-deterministically. A detached context with its own timeout is used instead,
// and any panic is recovered so an audit failure can never crash the process or
// fail the user's request.
func (a *auditService) Log(e models.Entry) {
	if a == nil || a.db == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil && a.log != nil {
				a.log.Error("audit write panicked", "recover", r, "eventType", e.EventType)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := auditlogs.NewAuditLogDbService(a.db).Insert(ctx, dbmodels.AuditLog{
			ClientID: e.ClientID, ActorUserID: e.ActorUserID, EventType: e.EventType,
			EventMetadata: e.Metadata, IPAddress: e.IP, UserAgent: e.UserAgent, RequestID: e.RequestID,
		}); err != nil && a.log != nil {
			a.log.Error("audit log write failed", "err", err, "eventType", e.EventType)
		}
	}()
}

// Record logs event as the actor, correlated to the request. The request id is
// stored even when empty, never as NULL.
//
// An Owner acting on another company leaves TWO rows. One sits in the platform
// company's trail, naming the Owner and the company acted on. The other sits in
// the target company's own trail, so its Admins can see what was done to their
// organisation, with no actor: the actor key is tied to the company it is
// recorded under, and the Owner is not a member of that company. Its metadata
// says an Owner did it, and which one.
func (a *auditService) Record(scope shared.Scope, event string) {
	a.RecordWith(scope, event, nil)
}

// RecordWith records the event as Record does, each row's metadata carrying the
// details as well.
func (a *auditService) RecordWith(scope shared.Scope, event string, details map[string]any) {
	actor := scope.Actor
	if !scope.ByOwner || scope.ClientID == actor.ClientID {
		a.Log(models.Entry{
			ClientID: scope.ClientID, ActorUserID: &actor.UserID, EventType: event,
			Metadata: metadata(details, nil), RequestID: &actor.RequestID,
		})
		return
	}
	a.Log(models.Entry{
		ClientID: actor.ClientID, ActorUserID: &actor.UserID, EventType: event,
		Metadata: metadata(details, map[string]any{"target_client_id": scope.ClientID}), RequestID: &actor.RequestID,
	})
	a.Log(models.Entry{
		ClientID: scope.ClientID, EventType: event,
		Metadata: metadata(details, map[string]any{"by_owner": actor.UserID}), RequestID: &actor.RequestID,
	})
}

// metadata merges an event's details with what the row itself must say; nil
// when there is nothing to say.
func metadata(details, row map[string]any) json.RawMessage {
	if len(details) == 0 && len(row) == 0 {
		return nil
	}
	m := make(map[string]any, len(details)+len(row))
	for k, v := range details {
		m[k] = v
	}
	for k, v := range row {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}
