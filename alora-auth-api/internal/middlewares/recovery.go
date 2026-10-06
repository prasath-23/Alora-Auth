package middlewares

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// Recovery turns a panic in any later handler into the standard 500 envelope,
// logged once through the request's logger with the panic value and its stack.
//
// It replaces gin.Recovery, which answered a panic with an empty-bodied 500 and
// wrote the trace to stderr outside the structured log — so the failure most
// worth correlating was the one that carried no reqId. gin's broken-connection
// handling is kept: a client that hung up gets neither a response nor a trace.
//
// It must run after RequestID and WithLogger, so the log line and the envelope
// both carry the request id. The panic value never reaches the client.
func Recovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, rec any) {
		logger := LoggerFrom(c)
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("panic recovered", "panic", fmt.Sprint(rec), "path", c.FullPath(), "stack", string(debug.Stack()))

		// Once the handler has begun writing, the status line is gone and a
		// second body would corrupt the first: all that is left is to stop.
		if c.Writer.Written() {
			c.Abort()
			return
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, exceptions.ErrorResponse{
			Error: http.StatusText(http.StatusInternalServerError), ReqID: RequestIDFrom(c),
		})
	})
}
