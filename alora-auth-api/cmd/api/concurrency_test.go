package main

// Concurrency: the single-use secrets whose correctness rests on a row lock or an
// atomic statement rather than on application logic. Sequential tests cannot
// tell a FOR UPDATE read from a plain one; requests racing for the same row can.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"sync"
	"testing"
)

// race fires every request at once and returns the sorted status codes.
func race(reqs ...func() *httptest.ResponseRecorder) []int {
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, len(reqs))
	for i, do := range reqs {
		wg.Add(1)
		go func(i int, do func() *httptest.ResponseRecorder) {
			defer wg.Done()
			<-start
			codes[i] = do().Code
		}(i, do)
	}
	close(start)
	wg.Wait()
	sort.Ints(codes)
	return codes
}

// Two tabs refreshing with the SAME cookie at once is the benign race: exactly
// one rotation wins, the loser is told to retry (409), and the session survives.
func TestConcurrentCentralRefreshIsARaceNotTheft(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	s := a.login(m)
	refresh := func() *httptest.ResponseRecorder { return a.post("/auth/central/refresh", nil, withCookie(s.Cookie)) }
	codes := race(refresh, refresh)
	if codes[0] != http.StatusOK || codes[1] != http.StatusConflict {
		t.Fatalf("statuses = %v, want [200 409]", codes)
	}
	var live, burned int
	a.scalar(&live, `SELECT count(*) FROM tbl_user_sessions WHERE user_id = $1 AND revoked_at IS NULL`, m.ID)
	a.scalar(&burned, `SELECT count(*) FROM tbl_session_families WHERE user_id = $1 AND revoked_at IS NOT NULL`, m.ID)
	if live != 1 || burned != 0 {
		t.Errorf("live=%d revoked families=%d, want one live token and no burn", live, burned)
	}
}

// The same for a product's backend refreshing twice at once.
func TestConcurrentProductRefreshIsARaceNotTheft(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)
	refresh := func() *httptest.ResponseRecorder { return a.productRefresh(l.p, ts.RefreshToken) }
	codes := race(refresh, refresh)
	if codes[0] != http.StatusOK || codes[1] != http.StatusConflict {
		t.Fatalf("statuses = %v, want [200 409]", codes)
	}
	if n := a.count(`SELECT count(*) FROM tbl_session_families WHERE user_id = $1 AND revoked_at IS NOT NULL`, l.m.ID); n != 0 {
		t.Errorf("%d families revoked by a benign race", n)
	}
}

// A code redeemed twice at once opens exactly one product login.
func TestConcurrentCodeRedemptionIsSingleUse(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	code := a.code(&l, f)
	redeem := func() *httptest.ResponseRecorder {
		return a.tokenCall(l.p, url.Values{"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {l.p.Redirect}, "code_verifier": {f.Verifier}})
	}
	codes := race(redeem, redeem, redeem)
	if codes[0] != http.StatusOK || codes[1] != http.StatusBadRequest || codes[2] != http.StatusBadRequest {
		t.Fatalf("statuses = %v, want exactly one 200", codes)
	}
	if n := a.count(`SELECT count(*) FROM tbl_session_families WHERE user_id = $1 AND kind = 'PRODUCT'`, l.m.ID); n != 1 {
		t.Errorf("%d product logins opened, want 1", n)
	}
}

// A leaked reset link redeemed twice at once works exactly once.
func TestConcurrentResetRedemptionIsSingleUse(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	s := a.login(a.newAdmin(co))
	tok := tokenOf(t, jsonField(a.post("/api/admin/users/"+m.ID+"/password-reset", nil, bearer(s.Access)), "reset_url"))
	consume := func(pass string) func() *httptest.ResponseRecorder {
		return func() *httptest.ResponseRecorder {
			return a.post("/auth/reset-password", map[string]any{"token": tok, "new_password": pass})
		}
	}
	codes := race(consume("first-new-password"), consume("second-new-password"))
	if codes[0] != http.StatusNoContent || codes[1] != http.StatusBadRequest {
		t.Fatalf("statuses = %v, want [204 400]", codes)
	}
}

// An account choice completed twice at once opens exactly one session.
func TestConcurrentAccountChoiceIsSingleUse(t *testing.T) {
	a := newApp(t)
	coA, coB := a.newCompany(), a.newCompany()
	email := "race-" + randSuffix(t) + "@shared.test"
	a.newMember(coA, email)
	a.newMember(coB, email)
	w := a.post("/auth/login/password", map[string]any{"email": email, "password": testPassword})
	ticket := cookieNamed(w, "alora_choose")
	choose := func(cid string) func() *httptest.ResponseRecorder {
		return func() *httptest.ResponseRecorder {
			return a.post("/auth/login/choose", map[string]any{"client_id": cid}, withCookie(ticket))
		}
	}
	codes := race(choose(coA.ID), choose(coB.ID), choose(coA.ID))
	if codes[0] != http.StatusOK || codes[1] != http.StatusUnauthorized || codes[2] != http.StatusUnauthorized {
		t.Fatalf("statuses = %v, want exactly one 200", codes)
	}
	var sessions int
	a.scalar(&sessions, `SELECT count(*) FROM tbl_session_families f JOIN tbl_users u ON u.id = f.user_id WHERE u.email = $1`, email)
	if sessions != 1 {
		t.Errorf("%d sessions opened, want 1", sessions)
	}
}
