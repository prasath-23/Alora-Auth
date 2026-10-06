package models

import (
	"encoding/json"
	"time"
)

// AuditLog is a row of tbl_audit_logs. The table is append-only.
type AuditLog struct {
	ID            string
	ClientID      string
	ActorUserID   *string
	EventType     string
	EventMetadata json.RawMessage
	IPAddress     *string
	UserAgent     *string
	RequestID     *string
	CreatedAt     *time.Time
}
