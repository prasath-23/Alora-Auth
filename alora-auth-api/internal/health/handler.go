// Package health serves liveness and readiness probes.
package health

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/gin-gonic/gin"
)

// Memory ceilings ported from the Node under-pressure config. Go has no
// event-loop-delay analogue, so only the heap/RSS guards carry over.
const (
	maxHeapBytes = 500 * 1024 * 1024
	maxRSSBytes  = 600 * 1024 * 1024
)

type Handler struct{ q *sqlc.Queries }

func New(q *sqlc.Queries) *Handler { return &Handler{q: q} }

// Live is a pure process check — it must NOT touch the database, or a transient
// DB blip would make an orchestrator kill an otherwise healthy process.
func (h *Handler) Live(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Ready reports whether this instance can serve traffic, which requires the DB.
func (h *Handler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	if _, err := h.q.HealthCheck(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// Pressure sheds load when memory is exhausted, so the process degrades with a
// 503 instead of being OOM-killed mid-request.
func (h *Handler) Pressure(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if m.HeapAlloc > maxHeapBytes || m.Sys > maxRSSBytes {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "unavailable", "heap": m.HeapAlloc, "rss": m.Sys,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "heap": m.HeapAlloc, "rss": m.Sys})
}
