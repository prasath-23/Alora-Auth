package middlewares

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// RateLimiter is a fixed-window counter keyed by an arbitrary string (usually the
// client IP, or ip|email on the login routes so one attacker cannot burn a
// victim's budget by guessing their address).
//
// Fixed-window (not token bucket) is a deliberate match for @fastify/rate-limit's
// semantics, which the parity tests assert against.
//
// The counters live in a Store. The default is in-process (memStore), so one
// instance's behaviour is unchanged; a shared Store makes several instances
// enforce one budget together. A limiter built on a shared Store carries a name,
// which namespaces its keys so two limiters on the same store do not collide.
type RateLimiter struct {
	store  Store
	name   string
	max    int
	window time.Duration
	Skip   bool // test harness escape hatch (mirrors _skipRateLimit)
}

// NewRateLimiter builds a limiter with its own in-process counters.
func NewRateLimiter(max int, per time.Duration) *RateLimiter {
	return &RateLimiter{store: newMemStore(), max: max, window: per}
}

// NewSharedRateLimiter builds a limiter whose counters live in a shared store.
// name namespaces the keys so limiters sharing one store keep separate budgets.
func NewSharedRateLimiter(store Store, name string, max int, per time.Duration) *RateLimiter {
	return &RateLimiter{store: store, name: name, max: max, window: per}
}

// bucket namespaces a key for the store, so a shared store keeps each limiter's
// budget separate. An in-process limiter (no name) uses the key as-is.
func (r *RateLimiter) bucket(key string) string {
	if r.name == "" {
		return key
	}
	return r.name + ":" + key
}

// Allow reports whether key may proceed, and how long until the window resets.
func (r *RateLimiter) Allow(ctx context.Context, key string) (bool, time.Duration) {
	if r.Skip {
		return true, 0
	}
	return r.store.Allow(ctx, r.bucket(key), r.max, r.window)
}

// Limit builds middleware keyed by client IP. keyFn may extend the key (e.g. with
// a submitted email) for credential-stuffing resistance on auth routes.
func (r *RateLimiter) Limit(keyFn func(*gin.Context) string) gin.HandlerFunc {
	return r.LimitExcept(keyFn)
}

// LimitExcept is Limit for every path except those under the given prefixes,
// which carry a limiter of their own. It exists for the server-to-server OAuth
// endpoints: one product backend calls them for all of its users from one
// address, so a per-address budget sized for a browser would throttle the
// product rather than an attacker.
func (r *RateLimiter) LimitExcept(keyFn func(*gin.Context) string, skipPrefixes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, p := range skipPrefixes {
			if strings.HasPrefix(c.Request.URL.Path, p) {
				c.Next()
				return
			}
		}
		key := c.ClientIP()
		if keyFn != nil {
			key += "|" + keyFn(c)
		}
		ok, retry := r.Allow(c.Request.Context(), key)
		if !ok {
			c.Header("Retry-After", retryAfterSeconds(retry))
			c.AbortWithStatusJSON(http.StatusTooManyRequests,
				exceptions.ErrorResponse{Error: "Too Many Requests", ReqID: RequestIDFrom(c)})
			return
		}
		c.Next()
	}
}

// LimitBy keys the budget by keyFn alone, not by address: for a budget that
// belongs to an account rather than to wherever its requests come from. A
// request keyFn cannot place (an empty key) passes; put this after whatever
// establishes the key.
func (r *RateLimiter) LimitBy(keyFn func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := keyFn(c)
		if key == "" {
			c.Next()
			return
		}
		ok, retry := r.Allow(c.Request.Context(), key)
		if !ok {
			c.Header("Retry-After", retryAfterSeconds(retry))
			c.AbortWithStatusJSON(http.StatusTooManyRequests,
				exceptions.ErrorResponse{Error: "Too Many Requests", ReqID: RequestIDFrom(c)})
			return
		}
		c.Next()
	}
}

// LimitFailures budgets FAILED requests only, per address: once an address has
// failed max times in the window, its requests are refused until the window
// resets, while successful requests cost nothing. isFailure inspects the
// finished request.
//
// It exists for client authentication at the OAuth endpoints. Their ordinary
// budget is keyed by the client id, which the caller chooses, so an attacker
// cycling through made-up ids would otherwise have an unlimited budget of
// secret guesses.
func (r *RateLimiter) LimitFailures(isFailure func(*gin.Context) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP()
		if blocked, retry := r.exhausted(c.Request.Context(), key); blocked {
			c.Header("Retry-After", retryAfterSeconds(retry))
			c.AbortWithStatusJSON(http.StatusTooManyRequests,
				exceptions.ErrorResponse{Error: "Too Many Requests", ReqID: RequestIDFrom(c)})
			return
		}
		c.Next()
		if isFailure(c) {
			r.Allow(c.Request.Context(), key) // counts the failure; the verdict applies to the next request
		}
	}
}

// exhausted reports whether key has used up its budget, without spending any.
func (r *RateLimiter) exhausted(ctx context.Context, key string) (bool, time.Duration) {
	if r.Skip {
		return false, 0
	}
	return r.store.Peek(ctx, r.bucket(key), r.max, r.window)
}

// BasicClientID is the client id an HTTP Basic credential claims (its value
// being "Basic base64(form-encoded id:secret)") — for keying a budget by the
// client a request says it is, so each client has its own however many users it
// serves. It only reads the value; authentication happens in the handler.
func BasicClientID(authorization string) string {
	scheme, value, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	id, _, _ := strings.Cut(string(raw), ":")
	if u, err := url.QueryUnescape(id); err == nil && len(u) <= 64 {
		return u
	}
	return ""
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
