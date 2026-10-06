package main

// Authorization requests one character away from a valid one. Before the
// redirect URI is known to be the product's own, nothing is sent to it; after,
// every mistake goes back to the product as an OAuth error, and each limit is
// exactly where the documentation puts it.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/alora/auth/internal/core/shared/crypto/pkce"
)

// A redirect URI is registered byte for byte, or it is not the product's,
// however near it comes — and whichever copy of a repeated parameter a proxy in
// front of App Central would read.
func TestAuthorizeRefusesNearMissRedirects(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	other := a.newProduct()
	f := newFlow(t)
	r := l.p.Redirect // https://app-<suffix>.test/callback
	host := strings.TrimPrefix(l.p.Base, "https://")
	refused := func(t *testing.T, q url.Values) {
		t.Helper()
		w := a.authorize(l.s, q)
		if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
			t.Errorf("SECURITY: %d Location %q, want 400 and no redirect", w.Code, w.Header().Get("Location"))
		}
	}
	for name, redirect := range map[string][]string{
		"the host in capitals":       {strings.Replace(r, host, strings.ToUpper(host), 1)},
		"the scheme in capitals":     {"HTTPS" + strings.TrimPrefix(r, "https")},
		"a fragment":                 {r + "#x"},
		"an empty fragment":          {r + "#"},
		"an empty query":             {r + "?"},
		"a user name":                {strings.Replace(r, "://", "://user@", 1)},
		"the default port":           {strings.Replace(r, host, host+":443", 1)},
		"a trailing dot on the host": {strings.Replace(r, host, host+".", 1)},
		"a dot segment":              {strings.Replace(r, "/callback", "/./callback", 1)},
		"a parent segment":           {strings.Replace(r, "/callback", "/x/../callback", 1)},
		"a double slash":             {strings.Replace(r, "/callback", "//callback", 1)},
		"an encoded letter":          {strings.Replace(r, "/callback", "/c%61llback", 1)},
		"a space before":             {" " + r},
		"a space after":              {r + " "},
		"a tab inside":               {strings.Replace(r, "/callback", "/call\tback", 1)},
		"repeated, a stranger first": {"https://evil.example/cb", r},
		"repeated, its own first":    {r, "https://evil.example/cb"},
		"repeated, itself twice":     {r, r},
	} {
		t.Run(name, func(t *testing.T) {
			q := f.query(l.p)
			q["redirect_uri"] = redirect
			refused(t, q)
		})
	}
	for name, ids := range map[string][]string{
		"another client first":   {other.ID, l.p.ID},
		"its own client first":   {l.p.ID, other.ID},
		"the client in capitals": {strings.ToUpper(l.p.ID)},
		"the client with space":  {l.p.ID + " "},
	} {
		t.Run(name, func(t *testing.T) {
			q := f.query(l.p)
			q["client_id"] = ids
			refused(t, q)
		})
	}
	// The genuine request still goes through.
	a.code(&l, f)
}

// Once the redirect URI is trusted, the limits are exact: a state of 1,024
// characters and a nonce of 512 are taken and come back whole, one more is an
// error for the product; the S256 method and the response type are exact; and
// a parameter given twice is refused (RFC 6749 §3.1), since which copy counts is
// not something a proxy and App Central may disagree on.
func TestAuthorizeLimitsAreExact(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	set := func(k string, vs ...string) func(url.Values) { return func(q url.Values) { q[k] = vs } }
	another := pkce.ChallengeS256(newFlow(t).Verifier)
	for name, tc := range map[string]struct {
		mutate func(url.Values)
		want   string
	}{
		"a state of 1,025":             {set("state", strings.Repeat("s", 1025)), "invalid_request"},
		"a nonce of 513":               {set("nonce", strings.Repeat("n", 513)), "invalid_request"},
		"a challenge of 42":            {set("code_challenge", strings.Repeat("c", 42)), "invalid_request"},
		"a challenge of 129":           {set("code_challenge", strings.Repeat("c", 129)), "invalid_request"},
		"s256 in lower case":           {set("code_challenge_method", "s256"), "invalid_request"},
		"code in capitals":             {set("response_type", "CODE"), "unsupported_response_type"},
		"a hybrid response type":       {set("response_type", "code id_token"), "unsupported_response_type"},
		"no response type":             {func(q url.Values) { q.Del("response_type") }, "unsupported_response_type"},
		"openid in capitals":           {set("scope", "OPENID"), "invalid_scope"},
		"the state repeated":           {set("state", f.State, "another"), "invalid_request"},
		"the nonce repeated":           {set("nonce", f.Nonce, f.Nonce), "invalid_request"},
		"the challenge repeated":       {set("code_challenge", pkce.ChallengeS256(f.Verifier), another), "invalid_request"},
		"the method repeated":          {set("code_challenge_method", "S256", "plain"), "invalid_request"},
		"the scope repeated":           {set("scope", "openid", "openid email"), "invalid_request"},
		"the response type repeated":   {set("response_type", "code", "token"), "invalid_request"},
		"the prompt repeated":          {set("prompt", "none", "login"), "invalid_request"},
		"prompt none with another one": {set("prompt", "none consent"), "invalid_request"},
	} {
		t.Run(name, func(t *testing.T) {
			q := f.query(l.p)
			tc.mutate(q)
			w := a.authorize(l.s, q)
			expect(t, w, http.StatusFound, name)
			got := location(t, w)
			if got.Scheme+"://"+got.Host+got.Path != l.p.Redirect || got.Query().Get("error") != tc.want || got.Query().Get("code") != "" {
				t.Errorf("redirected to %s, want error=%s and no code", got, tc.want)
			}
		})
	}
	// A parameter App Central does not read is ignored, repeated or not.
	q := f.query(l.p)
	q["utm_source"] = []string{"a", "b"}
	if w := a.authorize(l.s, q); location(t, w).Query().Get("code") == "" {
		t.Errorf("an unknown repeated parameter was refused: %s", w.Header().Get("Location"))
	}

	// At the limits exactly, the sign-in goes through, and state and nonce come
	// back whole.
	f = newFlow(t)
	f.State = strings.Repeat("s", 1024)
	f.Nonce = strings.Repeat("n", 512)
	ts := a.exchange(l.p, a.code(&l, f), f)
	if claims(t, ts.IDToken)["nonce"] != f.Nonce {
		t.Error("the ID token does not carry the 512-character nonce whole")
	}
}
