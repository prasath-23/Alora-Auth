package models

// Response models. Fields are declared in alphabetical order of their JSON names:
// the order the map-based bodies these replaced serialised in, so the bytes on
// the wire are unchanged.

// HealthResponse is the liveness/readiness body.
type HealthResponse struct {
	Status string `json:"status" example:"ok"`
} //@name HealthResponse

// PressureResponse reports the memory counters behind the load-shedding check.
type PressureResponse struct {
	Heap   uint64 `json:"heap" example:"12582912"`
	RSS    uint64 `json:"rss" example:"31457280"`
	Status string `json:"status" example:"ok"`
} //@name PressureResponse

// NewPressureResponse renders a reading with the status its outcome implies.
func NewPressureResponse(p Pressure) PressureResponse {
	status := "ok"
	if p.Overloaded {
		status = "unavailable"
	}
	return PressureResponse{Heap: p.Heap, RSS: p.RSS, Status: status}
}
