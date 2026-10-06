package main

// A stub OpenID provider for the federated sign-in tests: discovery, a JWKS, and
// a token endpoint that authenticates the client and checks the PKCE verifier,
// then returns an ID token the test shaped. It stands in for a company's IdP and
// for Google alike, so both paths are exercised offline and deterministically.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alora/auth/internal/core/shared/crypto/pkce"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type idpStub struct {
	t        *testing.T
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	secret   string

	mu    sync.Mutex
	codes map[string]stubCode
}

// stubCode is one sign-in the stub vouches for: the PKCE challenge it must see
// proved, and the ID token it answers with.
type stubCode struct {
	challenge string
	idToken   string
}

func newIdPStub(t *testing.T, clientID, secret string) *idpStub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idpStub{t: t, key: key, clientID: clientID, secret: secret, codes: map[string]stubCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint": p.srv.URL + "/token", "jwks_uri": p.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		k, _ := jwk.FromRaw(&p.key.PublicKey)
		_ = k.Set(jwk.KeyIDKey, "stub-kid")
		_ = k.Set(jwk.AlgorithmKey, jwa.RS256)
		set := jwk.NewSet()
		_ = set.AddKey(k)
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		id, sec, ok := r.BasicAuth()
		id, _ = url.QueryUnescape(id)
		sec, _ = url.QueryUnescape(sec)
		if !ok || id != p.clientID || sec != p.secret {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		_ = r.ParseForm()
		p.mu.Lock()
		c, found := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		p.mu.Unlock()
		if !found || !pkce.VerifyS256(r.PostForm.Get("code_verifier"), c.challenge) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "stub-at", "token_type": "Bearer", "id_token": c.idToken})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// idClaims are the ID token's claims; the test adjusts them to shape an attack.
type idClaims map[string]any

// claimsFor is a well-formed ID token for a sign-in: this issuer, this client,
// the nonce App Central sent, five minutes of life.
func (p *idpStub) claimsFor(sub, email string, verified bool, nonce string) idClaims {
	now := time.Now()
	return idClaims{
		"iss": p.srv.URL, "sub": sub, "aud": p.clientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"nonce": nonce, "email": email, "email_verified": verified,
	}
}

// sign signs claims with the stub's key and kid (RS256).
func (p *idpStub) sign(c idClaims) string {
	return p.signWith(c, jwa.RS256, p.key, "stub-kid")
}

func (p *idpStub) signWith(c idClaims, alg jwa.SignatureAlgorithm, key any, kid string) string {
	p.t.Helper()
	tok := jwt.New()
	for k, v := range c {
		if err := tok.Set(k, v); err != nil {
			p.t.Fatal(err)
		}
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)
	s, err := jwt.Sign(tok, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		p.t.Fatal(err)
	}
	return string(s)
}

// unsigned is an alg=none token of the claims.
func unsignedToken(c idClaims) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"stub-kid"}`))
	body, _ := json.Marshal(c)
	return h + "." + base64.RawURLEncoding.EncodeToString(body) + "."
}

// hs256 is the classic confusion: HS256 keyed with the provider's public key.
func (p *idpStub) hs256(c idClaims) string {
	der, _ := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	return p.signWith(c, jwa.HS256, der, "stub-kid")
}

// started is what App Central sent the browser to the provider with.
type started struct {
	state     string
	nonce     string
	challenge string
	cookie    *http.Cookie // the pending sign-in's binding to this browser
}

// start follows a /auth/{google,sso}/start redirect and reads the request App
// Central made of the provider.
func (a *app) start(path string, p *idpStub) started {
	a.t.Helper()
	w := a.get(path)
	if w.Code != http.StatusFound {
		a.t.Fatalf("start %s: %d %s", path, w.Code, w.Body.String())
	}
	u := location(a.t, w)
	if !strings.HasPrefix(u.String(), p.srv.URL+"/authorize?") {
		a.t.Fatalf("start %s went to %s, not the provider", path, u)
	}
	q := u.Query()
	if q.Get("client_id") != p.clientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		!strings.Contains(q.Get("scope"), "openid") {
		a.t.Fatalf("authorization request = %s", u)
	}
	ck := cookieNamed(w, "alora_login")
	if ck == nil || !ck.HttpOnly {
		a.t.Fatalf("no login-state cookie: %+v", ck)
	}
	return started{state: q.Get("state"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), cookie: ck}
}

// vouch makes the provider issue a code for this sign-in that redeems for the
// given ID token.
func (p *idpStub) vouch(s started, idToken string) string {
	code := "stub-code-" + randSuffix(p.t)
	p.mu.Lock()
	p.codes[code] = stubCode{challenge: s.challenge, idToken: idToken}
	p.mu.Unlock()
	return code
}

// callback returns the browser to App Central's callback.
func (a *app) callback(path string, s started, code string) *httptest.ResponseRecorder {
	a.t.Helper()
	q := url.Values{"state": {s.state}, "code": {code}}
	return a.get(path+"?"+q.Encode(), withCookie(s.cookie))
}

// signedIn asserts a callback signed the browser in and returns the session.
func (a *app) signedIn(w *httptest.ResponseRecorder, wantPath string) session {
	a.t.Helper()
	if w.Code != http.StatusFound {
		a.t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	u := location(a.t, w)
	if u.Query().Get("sso_error") != "" || u.Query().Get("google_error") != "" {
		a.t.Fatalf("callback failed: %s", u)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != testFrontend+wantPath {
		a.t.Fatalf("callback sent the browser to %s, want %s", got, testFrontend+wantPath)
	}
	ck := cookieNamed(w, centralCookie)
	if ck == nil || ck.MaxAge <= 0 {
		a.t.Fatalf("callback set no session cookie")
	}
	s := session{Cookie: ck}
	s2, rw := a.refresh(s)
	if rw.Code != http.StatusOK {
		a.t.Fatalf("the new session does not refresh: %d %s", rw.Code, rw.Body.String())
	}
	return s2
}

// failedWith asserts a callback failed with code, and set no session.
func (a *app) failedWith(w *httptest.ResponseRecorder, param, code string) {
	a.t.Helper()
	if w.Code != http.StatusFound {
		a.t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	u := location(a.t, w)
	if u.Path != "/login" || u.Query().Get(param) != code {
		a.t.Fatalf("callback went to %s, want /login?%s=%s", u, param, code)
	}
	if ck := cookieNamed(w, centralCookie); ck != nil && ck.MaxAge > 0 {
		a.t.Fatal("SECURITY: a failed callback set a session cookie")
	}
}
