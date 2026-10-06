package middlewares

import (
	"net/http"

	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// ErrorHandler renders any error recorded via exceptions.Fail into the standard
// envelope. It runs LAST in the chain (registered early, executes on the way out)
// so it can observe errors from every downstream handler.
//
// Envelope rules (SPEC §2):
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
		status, msg := exceptions.MapError(err)

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
		c.AbortWithStatusJSON(status, exceptions.ErrorResponse{Error: msg, ReqID: RequestIDFrom(c)})
	}
}

// NotFound renders unmatched routes. Deliberately omits reqId to match the
// Fastify 404 body byte-for-byte.
func NotFound() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusNotFound, exceptions.ErrorResponse{Error: "Not Found"})
	}
}

// MethodNotAllowed mirrors NotFound for a matched path with the wrong verb.
func MethodNotAllowed() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, exceptions.ErrorResponse{Error: "Method Not Allowed"})
	}
}
