package httpx

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter is a fixed-window counter keyed by an arbitrary string (usually the
// client IP, or ip|email on the login routes so one attacker cannot burn a
// victim's budget by guessing their address).
//
// Fixed-window (not token bucket) is a deliberate match for @fastify/rate-limit's
// semantics, which the parity tests assert against.
type RateLimiter struct {
	mu     sync.Mutex
	hits   map[string]*window
	max    int
	window time.Duration
	lastGC time.Time
	Skip   bool // test harness escape hatch (mirrors _skipRateLimit)
}

type window struct {
	count int
	reset time.Time
}

func NewRateLimiter(max int, per time.Duration) *RateLimiter {
	return &RateLimiter{hits: make(map[string]*window), max: max, window: per, lastGC: time.Now()}
}

// Allow reports whether key may proceed, and how long until the window resets.
func (r *RateLimiter) Allow(key string) (bool, time.Duration) {
	if r.Skip {
		return true, 0
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	// Opportunistic sweep so the map cannot grow without bound under a
	// distributed attack (every distinct IP would otherwise leak an entry).
	if now.Sub(r.lastGC) > r.window {
		for k, w := range r.hits {
			if now.After(w.reset) {
				delete(r.hits, k)
			}
		}
		r.lastGC = now
	}

	w, ok := r.hits[key]
	if !ok || now.After(w.reset) {
		r.hits[key] = &window{count: 1, reset: now.Add(r.window)}
		return true, 0
	}
	w.count++
	if w.count > r.max {
		return false, time.Until(w.reset)
	}
	return true, 0
}

// Limit builds middleware keyed by client IP. keyFn may extend the key (e.g. with
// a submitted email) for credential-stuffing resistance on auth routes.
func (r *RateLimiter) Limit(keyFn func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP()
		if keyFn != nil {
			key += "|" + keyFn(c)
		}
		ok, retry := r.Allow(key)
		if !ok {
			c.Header("Retry-After", retryAfterSeconds(retry))
			c.AbortWithStatusJSON(http.StatusTooManyRequests,
				gin.H{"error": "Too Many Requests", "reqId": RequestIDFrom(c)})
			return
		}
		c.Next()
	}
}

// retryAfterSeconds renders a Retry-After value, floored at 1s (0 would tell the
// client to retry immediately and defeat the limit).
func retryAfterSeconds(d time.Duration) string {
	s := int(d.Seconds())
	if s < 1 {
		s = 1
	}
	return strconv.Itoa(s)
}
