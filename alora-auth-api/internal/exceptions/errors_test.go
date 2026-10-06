package exceptions

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// What the database refuses maps to what it means for the caller: text it
// cannot store, or cannot index, is the caller's 400, a duplicate a 409, and
// anything else a 500 whose text is never shown.
func TestDatabaseErrorsMapToWhatTheyMean(t *testing.T) {
	for _, c := range []struct {
		err    error
		status int
		msg    string
	}{
		{&pgconn.PgError{Code: "22021", Message: "invalid byte sequence for encoding \"UTF8\": 0x00"}, http.StatusBadRequest, "Invalid request"},
		{&pgconn.PgError{Code: "22P05", Message: "untranslatable character"}, http.StatusBadRequest, "Invalid request"},
		{fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "22021"}), http.StatusBadRequest, "Invalid request"},
		{&pgconn.PgError{Code: "54000", Message: "index row size 3024 exceeds btree version 4 maximum 2704"}, http.StatusBadRequest, "Invalid request"},
		{&pgconn.PgError{Code: "54001", Message: "stack depth limit exceeded"}, http.StatusInternalServerError, "Internal Server Error"},
		{&pgconn.PgError{Code: "23505", Message: "duplicate key"}, http.StatusConflict, "Conflict"},
		{&pgconn.PgError{Code: "23514", Message: "check violation"}, http.StatusInternalServerError, "Internal Server Error"},
		{errors.New("something broke"), http.StatusInternalServerError, "Internal Server Error"},
	} {
		status, msg := MapError(c.err)
		if status != c.status || msg != c.msg {
			t.Errorf("MapError(%v) = %d %q, want %d %q", c.err, status, msg, c.status, c.msg)
		}
	}
}
