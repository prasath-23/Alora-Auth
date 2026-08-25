// Package audit writes append-only audit records without ever blocking or
// failing the request that triggered them.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// Writer persists one audit row. Implemented by the sqlc-backed repo.
type Writer interface {
	Insert(ctx context.Context, e Entry) error
}

type Entry struct {
	ClientID    string
	ActorUserID *string
	EventType   string
	Metadata    json.RawMessage
	IP          *string
	UserAgent   *string
	RequestID   *string
}

type Logger struct {
	w   Writer
	log *slog.Logger
}

func New(w Writer, log *slog.Logger) *Logger { return &Logger{w: w, log: log} }

// Log records an audit event fire-and-forget.
//
// It deliberately does NOT take the request context: that context is cancelled
// the moment the response is written, which would abort the insert
// non-deterministically. A detached context with its own timeout is used instead,
// and any panic is recovered so an audit failure can never crash the process or
// fail the user's request.
func (a *Logger) Log(e Entry) {
	if a == nil || a.w == nil {
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
		if err := a.w.Insert(ctx, e); err != nil && a.log != nil {
			a.log.Error("audit log write failed", "err", err, "eventType", e.EventType)
		}
	}()
}
