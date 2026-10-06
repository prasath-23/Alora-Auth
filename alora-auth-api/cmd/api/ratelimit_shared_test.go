package main

// The shared rate-limit store: several API instances behind a load balancer
// enforce ONE budget together, instead of each granting it in full. These drive
// the real Postgres-backed store (internal/infrastructure) exactly as the wired
// limiters do.

import (
	"context"
	"testing"
	"time"

	"github.com/alora/auth/internal/infrastructure"
	"github.com/alora/auth/internal/middlewares"
)

// Two limiters on one shared store — standing in for two API processes — draw on
// a single counter: the budget is spent across both, and the one that tips over
// is refused with a Retry-After. This is the property per-process counters lack.
func TestSharedRateLimitStoreSpansInstances(t *testing.T) {
	a := newApp(t)
	store := infrastructure.NewRateLimitStore(a.db, testLogger())
	ctx := context.Background()
	key := "ip-" + randSuffix(t)

	// Two independent limiter values, same store and name: two instances.
	i1 := middlewares.NewSharedRateLimiter(store, "shared-test", 3, time.Minute)
	i2 := middlewares.NewSharedRateLimiter(store, "shared-test", 3, time.Minute)

	// Three hits spread across the two instances are all within the shared budget.
	for n, l := range []*middlewares.RateLimiter{i1, i2, i1} {
		if ok, _ := l.Allow(ctx, key); !ok {
			t.Fatalf("hit %d should be within the shared budget", n+1)
		}
	}
	// The fourth, arriving at the OTHER instance, is refused by the shared count —
	// the whole point: a second replica does not hand out a second budget.
	if ok, retry := i2.Allow(ctx, key); ok || retry <= 0 {
		t.Fatalf("the 4th hit must be refused with a retry, got ok=%v retry=%v", ok, retry)
	}

	// A different limiter name is a different budget, even on the same store and key.
	other := middlewares.NewSharedRateLimiter(store, "other-test", 3, time.Minute)
	if ok, _ := other.Allow(ctx, key); !ok {
		t.Fatal("a differently-named limiter must keep its own budget")
	}

	// A different key under the same limiter is independent too.
	if ok, _ := i1.Allow(ctx, "ip-"+randSuffix(t)); !ok {
		t.Fatal("a different key must have its own budget")
	}
}

// The in-process default keeps each limiter's counters to itself: two memStore
// limiters do NOT share a budget. This is the behaviour the shared store exists
// to change, pinned so a refactor cannot blur the two.
func TestInProcessLimitersDoNotShare(t *testing.T) {
	ctx := context.Background()
	key := "ip-fixed"
	a := middlewares.NewRateLimiter(1, time.Minute)
	b := middlewares.NewRateLimiter(1, time.Minute)
	if ok, _ := a.Allow(ctx, key); !ok {
		t.Fatal("first limiter's first hit should pass")
	}
	if ok, _ := b.Allow(ctx, key); !ok {
		t.Fatal("a separate in-process limiter must have its own budget")
	}
	// a's own budget is now spent.
	if ok, _ := a.Allow(ctx, key); ok {
		t.Fatal("the first limiter's budget should be exhausted")
	}
}
