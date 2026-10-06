// Package models holds the database's own model: one skeleton per table, and one
// per view built on that table, in plain Go types. NULL is a nil pointer, never a
// zero value, and a Postgres enum is a typed string. Only the table services in
// internal/database/services produce these, from the generated sqlc rows, so no
// feature ever sees pgtype or generated code.
package models
