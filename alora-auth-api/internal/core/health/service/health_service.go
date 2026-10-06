// Package service holds the health probes' logic.
package service

import (
	"context"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/alora/auth/internal/core/health/models"
	"github.com/alora/auth/internal/database/contexts"
)

// Memory ceilings ported from the Node under-pressure config. Go has no
// event-loop-delay analogue, so only the heap/RSS guards carry over.
const (
	maxHeapBytes = 500 * 1024 * 1024
	maxRSSBytes  = 600 * 1024 * 1024
)

// sampleInterval bounds how often the load-shedding verdict re-reads the memory
// counters. runtime.ReadMemStats stops the world, so it must never run once per
// request — least of all when the process is busiest.
const sampleInterval = time.Second

// HealthService answers the liveness, readiness and pressure probes.
type HealthService interface {
	// Ready reports whether the database can serve, within two seconds.
	Ready(ctx context.Context) error
	// Pressure reads the process's memory counters against the ceilings.
	Pressure() models.Pressure
	// Overloaded is the load-shedding verdict every request consults, from a
	// reading at most sampleInterval old.
	Overloaded() bool
}

type healthService struct {
	db   *contexts.DbContext
	read func() (heap, rss uint64) // the memory counters; replaced in tests

	nextSample atomic.Int64 // unix nanos after which the cached verdict is stale
	overloaded atomic.Bool
}

// NewHealthService builds the probes.
func NewHealthService(db *contexts.DbContext) HealthService {
	return &healthService{db: db, read: readMemStats}
}

func readMemStats() (heap, rss uint64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc, m.Sys
}

// Ready is bounded at two seconds so a hung connection fails the probe instead
// of hanging it.
func (s *healthService) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.db.Ping(ctx)
}

// Pressure lets a loaded process degrade by shedding traffic (503) instead of
// being OOM-killed mid-request.
func (s *healthService) Pressure() models.Pressure {
	heap, rss := s.read()
	return models.Pressure{
		Overloaded: heap > maxHeapBytes || rss > maxRSSBytes,
		Heap:       heap,
		RSS:        rss,
	}
}

// Overloaded re-reads the counters at most once per sampleInterval: the one
// request that wins the swap pays for the read, and every other request reuses
// the cached verdict.
func (s *healthService) Overloaded() bool {
	now := time.Now().UnixNano()
	if next := s.nextSample.Load(); now >= next && s.nextSample.CompareAndSwap(next, now+int64(sampleInterval)) {
		s.overloaded.Store(s.Pressure().Overloaded)
	}
	return s.overloaded.Load()
}
