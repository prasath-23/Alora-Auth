package middlewares

import (
	"net/http"
	"sync/atomic"

	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// PressureMonitor reports whether the process is over its memory ceilings.
// Implemented by the health service, which owns the reading; declared here so
// middlewares never imports a feature.
type PressureMonitor interface {
	Overloaded() bool
}

// pressureRetryAfter is @fastify/under-pressure's default retryAfter, in seconds.
const pressureRetryAfter = "10"

// UnderPressure sheds every request with a 503 while the process is over its
// memory ceilings, so a loaded instance degrades instead of being OOM-killed
// mid-request (SPEC §3, D9). It runs after the rate limiter and before any
// route, authentication included, so a shed request costs next to nothing.
//
// The body is the ≥500 envelope, which SPEC §2 fixes as "Internal Server Error"
// whatever the cause; the 503 and Retry-After are what tell the client to back
// off. Nothing is logged per request — an instance short of memory has no room
// for a log line per rejection — only when shedding starts and stops.
func UnderPressure(m PressureMonitor) gin.HandlerFunc {
	var shedding atomic.Bool
	return func(c *gin.Context) {
		over := m.Overloaded()
		if over != shedding.Load() && shedding.CompareAndSwap(!over, over) {
			if logger := LoggerFrom(c); logger != nil {
				if over {
					logger.Warn("memory over its ceiling: shedding every request with 503")
				} else {
					logger.Info("memory back under its ceiling: serving requests again")
				}
			}
		}
		if over {
			c.Header("Retry-After", pressureRetryAfter)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, exceptions.ErrorResponse{
				Error: http.StatusText(http.StatusInternalServerError), ReqID: RequestIDFrom(c),
			})
			return
		}
		c.Next()
	}
}
