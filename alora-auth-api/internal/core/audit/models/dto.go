// Package models holds the audit feature's DTOs.
package models

import "encoding/json"

// Entry is one audit event. A nil pointer stores NULL.
type Entry struct {
	ClientID    string
	ActorUserID *string
	EventType   string
	Metadata    json.RawMessage
	IP          *string
	UserAgent   *string
	RequestID   *string
}
