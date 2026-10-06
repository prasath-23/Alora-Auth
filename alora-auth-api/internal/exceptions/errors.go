// Package exceptions holds the application's domain errors and the rules that map
// them to HTTP responses. Services return these errors; the ErrorHandler
// middleware renders them. Nothing here depends on another internal package, so
// every layer can use it.
package exceptions

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNoRows is pgx.ErrNoRows, re-exported so services can branch on "no such
// row" without importing the driver. It is deliberately NOT a safe message: a
// no-rows a service did not handle is a bug, and it still renders as a 500.
var ErrNoRows = pgx.ErrNoRows

// ErrorResponse is the error envelope every failure renders as. The message is
// always a fixed, client-safe label; internal error text is never serialized. A
// 404 from an unmatched ROUTE omits reqId entirely.
type ErrorResponse struct {
	Error string `json:"error" example:"Invalid request"`
	ReqID string `json:"reqId,omitempty" example:"0b7c0f1e-6a19-4f3f-9a2d-1f9d0f3a6c21"`
} //@name ErrorResponse

// Sentinel errors services return; the handler layer maps them to status codes.
// Using sentinels (not HTTP codes) keeps services free of transport concerns.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidRequest     = errors.New("invalid request")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrAccountInactive    = errors.New("account inactive")
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("conflict")
	ErrRotationRace       = errors.New("concurrent rotation")
	ErrSessionInvalid     = errors.New("session invalid or expired")
)

// APIError is an error carrying the exact status and client-safe message to emit.
// Anything that is NOT an APIError and NOT a known sentinel is treated as a 500
// and its message is never shown to the client.
type APIError struct {
	Status  int
	Message string
	Err     error // wrapped cause, logged but never serialized
}

func (e *APIError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}
func (e *APIError) Unwrap() error { return e.Err }

// NewAPIError builds a client-visible error with an explicit status.
func NewAPIError(status int, msg string, cause error) *APIError {
	return &APIError{Status: status, Message: msg, Err: cause}
}

// safeMessages maps sentinels to the EXACT wire strings the parity oracle asserts.
// Any message not sourced here is suppressed, so an internal error string can
// never leak through the envelope.
var safeMessages = map[error]struct {
	status int
	msg    string
}{
	ErrInvalidCredentials: {http.StatusUnauthorized, "Invalid email or password"},
	ErrInvalidRequest:     {http.StatusBadRequest, "Invalid request"},
	ErrUnauthorized:       {http.StatusUnauthorized, "Unauthorized"},
	ErrForbidden:          {http.StatusForbidden, "Forbidden"},
	ErrAccountInactive:    {http.StatusForbidden, "Account inactive"},
	ErrNotFound:           {http.StatusNotFound, "Not Found"},
	ErrConflict:           {http.StatusConflict, "Conflict"},
	ErrRotationRace:       {http.StatusConflict, "Concurrent rotation — retry"},
	ErrSessionInvalid:     {http.StatusUnauthorized, "Session invalid or expired"},
}

// IsUniqueViolation reports whether err is a Postgres 23505 (unique violation),
// which the API surfaces as 409 rather than a 500.
func IsUniqueViolation(err error) bool { return pgCode(err) == "23505" }

// IsForeignKeyViolation reports whether err is a Postgres 23503: a reference to
// a row that does not exist (or no longer may be removed). Services map it to
// the client error it means in context; unmapped, it is a 500.
func IsForeignKeyViolation(err error) bool { return pgCode(err) == "23503" }

// IsCheckViolation reports whether err is a Postgres 23514: a row a table's own
// CHECK constraint refuses.
func IsCheckViolation(err error) bool { return pgCode(err) == "23514" }

// SeatLimitSQLState is the custom SQLSTATE a seat-enforcing stored procedure
// raises when a change would exceed a company's max_seats or a subscription's
// seat_limit. It is raised inside the same transaction as the change (under a
// row lock), so two concurrent additions cannot both slip under the limit.
const SeatLimitSQLState = "AL001"

// IsSeatLimit reports whether err is a seat-limit refusal raised by the
// database. The API surfaces it as 409, not a 500.
func IsSeatLimit(err error) bool { return pgCode(err) == SeatLimitSQLState }

// IsUnstorableText reports whether err is PostgreSQL refusing text it cannot
// store — 22021 (a NUL, or bytes that are not UTF-8), 22P05 (untranslatable) or
// 54000 (a value too large for its index to hold). Such text only ever comes
// from a caller, so it is a 400, never a 500: the backstop behind the checks at
// every edge where input arrives.
func IsUnstorableText(err error) bool {
	code := pgCode(err)
	return code == "22021" || code == "22P05" || code == "54000"
}

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// Fail records an error for the ErrorHandler middleware to render, and aborts the
// chain. Handlers should `exceptions.Fail(c, err); return` rather than writing bodies.
func Fail(c *gin.Context, err error) {
	_ = c.Error(err)
	c.Abort()
}

// FailWith is Fail with an explicit status and client-safe message.
func FailWith(c *gin.Context, status int, msg string) {
	Fail(c, NewAPIError(status, msg, nil))
}

// MapError turns any error into (status, client-safe message).
func MapError(err error) (int, string) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status, apiErr.Message
	}
	for sentinel, m := range safeMessages {
		if errors.Is(err, sentinel) {
			return m.status, m.msg
		}
	}
	if IsSeatLimit(err) {
		return http.StatusConflict, "Seat limit reached"
	}
	if IsUniqueViolation(err) {
		return http.StatusConflict, "Conflict"
	}
	if IsUnstorableText(err) {
		return http.StatusBadRequest, "Invalid request"
	}
	// Unknown error: never expose its text.
	return http.StatusInternalServerError, "Internal Server Error"
}

// The two scope rules' refusals. Rule 1: nobody gives or takes away a scope they
// do not hold themselves. Rule 2: nobody acts on someone with more access than
// they have. The Owner is bound by neither.
var (
	ErrCannotGive   = NewAPIError(http.StatusForbidden, "You can only give or take away scopes you hold yourself", nil)
	ErrCannotManage = NewAPIError(http.StatusForbidden, "You can only manage people who have no more access than you", nil)
)
