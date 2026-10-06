package aloraauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireScope(t *testing.T) {
	s := newIssuer(t)
	v := newVerifierFor(t, s)
	var seen *Claims
	h := v.RequireScope("mcp:tools", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = ClaimsFrom(r.Context())
	}))
	call := func(auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := call("Bearer " + s.token(t, nil)); w.Code != http.StatusOK || seen == nil || seen.Subject != "aci_1" {
		t.Fatalf("a token with mcp:tools: %d %+v", w.Code, seen)
	}
	for what, c := range map[string]struct {
		auth   string
		status int
		want   string
	}{
		"no token":        {"", 401, `error="invalid_token"`},
		"a Basic header":  {"Basic eDp5", 401, `error="invalid_token"`},
		"an invalid one":  {"Bearer x.y.z", 401, `error="invalid_token"`},
		"another product": {"Bearer " + s.token(t, func(_, c map[string]any) { c["aud"] = "product:OTHER" }), 401, `error="invalid_token"`},
		"without the scope": {"Bearer " + s.token(t, func(_, c map[string]any) { c["scope"] = "api:read" }), 403,
			`error="insufficient_scope", scope="mcp:tools"`},
	} {
		w := call(c.auth)
		if w.Code != c.status || !strings.Contains(w.Header().Get("WWW-Authenticate"), c.want) {
			t.Errorf("%s: %d %q", what, w.Code, w.Header().Get("WWW-Authenticate"))
		}
	}
}
