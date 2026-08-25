// Package httpx holds the shared HTTP plumbing: the error envelope, request ids,
// security headers, signed cookies, strict JSON binding, body limits, rate
// limiting and dynamic CORS. Handlers depend on this package; it depends on no
// feature package.
package httpx

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
)

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
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Fail records an error for the ErrorHandler middleware to render, and aborts the
// chain. Handlers should `httpx.Fail(c, err); return` rather than writing bodies.
func Fail(c *gin.Context, err error) {
	_ = c.Error(err)
	c.Abort()
}

// FailWith is Fail with an explicit status and client-safe message.
func FailWith(c *gin.Context, status int, msg string) {
	Fail(c, NewAPIError(status, msg, nil))
}

// resolve turns any error into (status, client-safe message).
func resolve(err error) (int, string) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status, apiErr.Message
	}
	for sentinel, m := range safeMessages {
		if errors.Is(err, sentinel) {
			return m.status, m.msg
		}
	}
	if IsUniqueViolation(err) {
		return http.StatusConflict, "Conflict"
	}
	// Unknown error: never expose its text.
	return http.StatusInternalServerError, "Internal Server Error"
}

// ErrorHandler renders any error recorded via Fail into the standard envelope.
// It runs LAST in the chain (registered early, executes on the way out) so it can
// observe errors from every downstream handler.
//
// Envelope rules (MIGRATION_SPEC §2):
//   - >=500 → {"error":"Internal Server Error","reqId":...} — cause never leaked
//   - 4xx   → {"error":<safe label>,"reqId":...}
//   - 404 route-miss → {"error":"Not Found"} with NO reqId (see NotFound)
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) == 0 {
			return
		}
		err := c.Errors.Last().Err
		status, msg := resolve(err)

		// Log the true cause exactly once, with the request id for correlation.
		// The logger from WithLogger already carries reqId; re-adding it here
		// would emit the field twice in every line.
		if logger := LoggerFrom(c); logger != nil {
			if status >= http.StatusInternalServerError {
				logger.Error("request failed", "err", err, "path", c.FullPath())
			} else {
				logger.Debug("request rejected", "err", err, "status", status, "path", c.FullPath())
			}
		}

		// If a handler already began writing, we cannot re-render the body.
		if c.Writer.Written() {
			return
		}
		c.AbortWithStatusJSON(status, gin.H{"error": msg, "reqId": RequestIDFrom(c)})
	}
}

// NotFound renders unmatched routes. Deliberately omits reqId to match the
// Fastify 404 body byte-for-byte.
func NotFound() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Not Found"})
	}
}

// MethodNotAllowed mirrors NotFound for a matched path with the wrong verb.
func MethodNotAllowed() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{"error": "Method Not Allowed"})
	}
}
