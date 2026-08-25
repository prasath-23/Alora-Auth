package database

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
