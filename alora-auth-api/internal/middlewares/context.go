package middlewares

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Context keys. Unexported string constants keep feature packages from writing
// these slots directly — they must go through the setters here.
const (
	ctxRequestID = "alora.requestID"
	ctxLogger    = "alora.logger"
)

// RequestID assigns a uuid v4 to every request and echoes it as X-Request-Id.
// It runs FIRST so that every later log line and error envelope can be correlated
// to a single request. An inbound X-Request-Id is deliberately IGNORED: trusting a
// client-supplied id would let a caller forge or collide log correlation.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := uuid.NewString()
		c.Set(ctxRequestID, id)
		c.Header("X-Request-Id", id)
		c.Next()
	}
}

// RequestIDFrom returns the request id, or "" when called outside the chain.
func RequestIDFrom(c *gin.Context) string {
	if v, ok := c.Get(ctxRequestID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// WithLogger stores a base logger on the context, pre-tagged with the request id
// so every downstream log line carries it without the caller re-adding it.
func WithLogger(base *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ctxLogger, base.With("reqId", RequestIDFrom(c)))
		c.Next()
	}
}

// LoggerFrom returns the request-scoped logger, or nil if none was installed.
func LoggerFrom(c *gin.Context) *slog.Logger {
	if v, ok := c.Get(ctxLogger); ok {
		if l, ok := v.(*slog.Logger); ok {
			return l
		}
	}
	return nil
}
