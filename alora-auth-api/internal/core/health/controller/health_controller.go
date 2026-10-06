// Package controller serves the liveness and readiness probes.
package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/health/models"
	"github.com/alora/auth/internal/core/health/service"
	"github.com/gin-gonic/gin"
)

// HealthController serves /health, /health/ready and /health/pressure.
type HealthController struct{ svc service.HealthService }

// NewHealthController builds the controller.
func NewHealthController(svc service.HealthService) *HealthController {
	return &HealthController{svc: svc}
}

// Live is a pure process check — it must NOT touch the database, or a transient
// DB blip would make an orchestrator kill an otherwise healthy process.
//
//	@Summary		Liveness probe
//	@Description	Reports that the process is running. Deliberately does not touch the database: a transient DB fault must not make an orchestrator kill an otherwise healthy process. Use /health/ready to decide whether to send traffic.
//	@Tags			health
//	@Produce		json
//	@Success		200	{object}	models.HealthResponse
//	@Router			/health [get]
func (h *HealthController) Live(c *gin.Context) {
	c.JSON(http.StatusOK, models.HealthResponse{Status: "ok"})
}

// Ready reports whether this instance can serve traffic, which requires the DB.
//
//	@Summary		Readiness probe
//	@Description	Reports whether this instance can serve traffic, which requires a reachable database. The check is bounded at two seconds so a hung connection fails the probe instead of hanging it.
//	@Tags			health
//	@Produce		json
//	@Success		200	{object}	models.HealthResponse
//	@Failure		503	{object}	models.HealthResponse	"Database unreachable"
//	@Router			/health/ready [get]
func (h *HealthController) Ready(c *gin.Context) {
	if err := h.svc.Ready(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, models.HealthResponse{Status: "unavailable"})
		return
	}
	c.JSON(http.StatusOK, models.HealthResponse{Status: "ready"})
}

// Pressure sheds load when memory is exhausted, so the process degrades with a
// 503 instead of being OOM-killed mid-request.
//
//	@Summary		Memory-pressure probe
//	@Description	Returns 503 once heap or RSS crosses the ceiling, so a loaded process degrades by shedding traffic instead of being OOM-killed mid-request. Both counters are reported either way.
//	@Tags			health
//	@Produce		json
//	@Success		200	{object}	models.PressureResponse
//	@Failure		503	{object}	models.PressureResponse	"Over the heap or RSS ceiling"
//	@Router			/health/pressure [get]
func (h *HealthController) Pressure(c *gin.Context) {
	p := h.svc.Pressure()
	status := http.StatusOK
	if p.Overloaded {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, models.NewPressureResponse(p))
}
