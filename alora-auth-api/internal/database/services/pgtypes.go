// Package services is the table-based data-access layer: one package per table
// (users, sessions, clients, ...) wrapping the generated sqlc queries, so no
// feature ever touches SQL. This parent package holds the conversions between
// Go values and pgtype that every table service shares.
package services

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// Conversion helpers between Go values and pgtype. Centralised so a nil pointer
// always becomes SQL NULL rather than a zero value — writing "" where NULL is
// meant would defeat every `IS NULL` predicate in the query layer.

func Text(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

// TextOrNull maps "" → NULL, for optional free-text columns.
func TextOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

func Timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// TimePtr returns nil when the column is SQL NULL, so callers must branch rather
// than silently reading a zero time (which would compare as "long ago").
func TimePtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// TextPtr maps nil → NULL; any non-nil pointer, even to "", is stored as is.
func TextPtr(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *s, Valid: true}
}

// StringPtr returns nil when the column is SQL NULL.
func StringPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	v := t.String
	return &v
}

// TimestamptzPtr maps nil → NULL.
func TimestamptzPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

// Int32Ptr returns nil when the column is SQL NULL.
func Int32Ptr(i pgtype.Int4) *int32 {
	if !i.Valid {
		return nil
	}
	v := i.Int32
	return &v
}

// Int4Ptr maps nil → NULL.
func Int4Ptr(i *int32) pgtype.Int4 {
	if i == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: *i, Valid: true}
}

// BoolPtr maps nil → NULL.
func BoolPtr(b *bool) pgtype.Bool {
	if b == nil {
		return pgtype.Bool{}
	}
	return pgtype.Bool{Bool: *b, Valid: true}
}
