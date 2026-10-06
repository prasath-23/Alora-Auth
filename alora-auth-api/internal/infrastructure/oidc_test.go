package infrastructure

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// idp is a minimal OpenID provider: discovery, a JWKS, and a token endpoint that
// returns whatever ID token the test put there.
type idp struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	key         *rsa.PrivateKey
	kid         string
	issuer      string // what discovery claims; defaults to the server URL
	authMethods []string
	idToken     string
	lastAuth    string // the Authorization header of the last token request
	lastForm    url.Values

	jwksHits atomic.Int32
}

func newIdP(t *testing.T) *idp {
	t.Helper()
	p := &idp{t: t, kid: "k1", key: rsaKey(t)}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		iss := p.issuer
		methods := p.authMethods
		p.mu.Unlock()
		if iss == "" {
			iss = p.srv.URL
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint": p.srv.URL + "/token", "jwks_uri": p.srv.URL + "/jwks",
			"token_endpoint_auth_methods_supported": methods,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		p.jwksHits.Add(1)
		p.mu.Lock()
		defer p.mu.Unlock()
		k, _ := jwk.FromRaw(&p.key.PublicKey)
		_ = k.Set(jwk.KeyIDKey, p.kid)
		set := jwk.NewSet()
		_ = set.AddKey(k)
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		p.lastAuth, p.lastForm = r.Header.Get("Authorization"), r.PostForm
		tok := p.idToken
		p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": tok})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sign issues an ID token; mutate adjusts the claims before signing.
func (p *idp) sign(nonce string, mutate func(b *jwt.Builder) *jwt.Builder) string {
	p.t.Helper()
	b := jwt.NewBuilder().Issuer(p.srv.URL).Subject("sub-1").Audience([]string{"client-1"}).
		IssuedAt(time.Now()).Expiration(time.Now().Add(5*time.Minute)).
		Claim("nonce", nonce).Claim("email", "alice@acme.test").Claim("email_verified", true)
	if mutate != nil {
		b = mutate(b)
	}
	tok, err := b.Build()
	if err != nil {
		p.t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	p.mu.Lock()
	_ = hdrs.Set(jws.KeyIDKey, p.kid)
	key := p.key
	p.mu.Unlock()
	s, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		p.t.Fatal(err)
	}
	return string(s)
}

var client1 = OIDCClient{ClientID: "client-1", ClientSecret: "s3cret/+", RedirectURI: "http://localhost/cb"}

func TestVerifyIDTokenHappyPath(t *testing.T) {
	p := newIdP(t)
	o := NewOIDC(OIDCOptions{})
	claims, err := o.VerifyIDToken(context.Background(), p.srv.URL, "client-1", p.sign("n-1", nil), "n-1")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "sub-1" || claims.Email != "alice@acme.test" || !claims.EmailVerified {
		t.Errorf("claims = %+v", claims)
	}
	// email_verified as the string some providers send.
	s := p.sign("n-1", func(b *jwt.Builder) *jwt.Builder { return b.Claim("email_verified", "true") })
	if c, err := o.VerifyIDToken(context.Background(), p.srv.URL, "client-1", s, "n-1"); err != nil || !c.EmailVerified {
		t.Errorf("string email_verified: %+v %v", c, err)
	}
}

// Every one of these is a token a hostile or broken provider — or someone
// replaying a token meant for another client — could present.
func TestVerifyIDTokenRefusals(t *testing.T) {
	p := newIdP(t)
	o := NewOIDC(OIDCOptions{})
	other := rsaKey(t)
	cases := map[string]string{
		"wrong issuer":  p.sign("n", func(b *jwt.Builder) *jwt.Builder { return b.Issuer("https://evil.test") }),
		"wrong aud":     p.sign("n", func(b *jwt.Builder) *jwt.Builder { return b.Audience([]string{"client-2"}) }),
		"azp not us":    p.sign("n", func(b *jwt.Builder) *jwt.Builder { return b.Claim("azp", "client-2") }),
		"multi aud":     p.sign("n", func(b *jwt.Builder) *jwt.Builder { return b.Audience([]string{"client-1", "client-2"}) }),
		"expired":       p.sign("n", func(b *jwt.Builder) *jwt.Builder { return b.Expiration(time.Now().Add(-5 * time.Minute)) }),
		"wrong nonce":   p.sign("other", nil),
		"no nonce":      p.sign("", nil),
		"no sub":        p.sign("n", func(b *jwt.Builder) *jwt.Builder { return b.Subject("") }),
		"alg none":      unsigned(t, p.srv.URL),
		"HS256":         hmacSigned(t, p),
		"unknown key":   signedWith(t, p, other, "k1"),
		"no such kid":   signedWith(t, p, p.key, "k-missing"),
		"not a JWT":     "not.a.jwt",
		"empty":         "",
		"garbage parts": "a.b.c",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := o.VerifyIDToken(context.Background(), p.srv.URL, "client-1", tok, "n"); err == nil {
				t.Errorf("SECURITY: accepted an ID token with %s", name)
			} else if !errors.Is(err, ErrOIDC) {
				t.Errorf("error %v is not an ErrOIDC", err)
			}
		})
	}
}

func unsigned(t *testing.T, iss string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`))
	c, _ := json.Marshal(map[string]any{"iss": iss, "sub": "x", "aud": "client-1", "nonce": "n",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	return h + "." + base64.RawURLEncoding.EncodeToString(c) + "."
}

// hmacSigned is the classic confusion: HS256 keyed with the provider's PUBLIC
// key bytes, which a verifier that trusts the header would accept.
func hmacSigned(t *testing.T, p *idp) string {
	der, _ := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	tok, _ := jwt.NewBuilder().Issuer(p.srv.URL).Subject("x").Audience([]string{"client-1"}).
		IssuedAt(time.Now()).Expiration(time.Now().Add(time.Hour)).Claim("nonce", "n").Build()
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, "k1")
	s, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, der, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(s)
}

func signedWith(t *testing.T, p *idp, key *rsa.PrivateKey, kid string) string {
	tok, _ := jwt.NewBuilder().Issuer(p.srv.URL).Subject("x").Audience([]string{"client-1"}).
		IssuedAt(time.Now()).Expiration(time.Now().Add(time.Hour)).Claim("nonce", "n").Build()
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)
	s, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(s)
}

// A provider rotates by publishing a new key and then signing with it: an
// unknown kid triggers one re-fetch, and a flood of unknown kids does not
// trigger one per token.
func TestUnknownKidRefetchIsRateLimited(t *testing.T) {
	p := newIdP(t)
	o := NewOIDC(OIDCOptions{})
	ctx := context.Background()
	if _, err := o.VerifyIDToken(ctx, p.srv.URL, "client-1", p.sign("n", nil), "n"); err != nil {
		t.Fatal(err)
	}
	hits := p.jwksHits.Load()
	for i := 0; i < 5; i++ {
		_, _ = o.VerifyIDToken(ctx, p.srv.URL, "client-1", signedWith(t, p, p.key, "k-made-up"), "n")
	}
	if got := p.jwksHits.Load() - hits; got > 1 {
		t.Errorf("five unknown kids re-fetched the JWKS %d times, want at most once a minute", got)
	}

	// A genuine rotation after the interval: back-date the last fetch.
	p.mu.Lock()
	p.key, p.kid = rsaKey(t), "k2"
	p.mu.Unlock()
	o.mu.Lock()
	o.providers[p.srv.URL].keysFetched = time.Now().Add(-2 * jwksRefetchInterval)
	o.mu.Unlock()
	if _, err := o.VerifyIDToken(ctx, p.srv.URL, "client-1", p.sign("n", nil), "n"); err != nil {
		t.Errorf("a token under the rotated key failed: %v", err)
	}
}

// A discovery document that claims to be another issuer is refused (OpenID
// Connect Discovery §4.3).
func TestDiscoveryIssuerMustMatch(t *testing.T) {
	p := newIdP(t)
	p.issuer = "https://accounts.google.com"
	if _, err := NewOIDC(OIDCOptions{}).Discover(context.Background(), p.srv.URL); err == nil {
		t.Fatal("SECURITY: accepted a discovery document naming another issuer")
	}
}

func TestExchangeUsesBasicAuthByDefault(t *testing.T) {
	p := newIdP(t)
	o := NewOIDC(OIDCOptions{})
	p.idToken = p.sign("n-9", nil)
	claims, err := o.Exchange(context.Background(), p.srv.URL, client1, "code-1", "verifier-1", "n-9")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "sub-1" {
		t.Errorf("claims = %+v", claims)
	}
	// RFC 6749 §2.3.1: the id and secret are each form-encoded inside Basic.
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("client-1:s3cret%2F%2B"))
	if p.lastAuth != want || p.lastForm.Get("client_secret") != "" {
		t.Errorf("Authorization %q, form secret %q; want Basic and no secret in the body", p.lastAuth, p.lastForm.Get("client_secret"))
	}
	if p.lastForm.Get("code_verifier") != "verifier-1" || p.lastForm.Get("grant_type") != "authorization_code" {
		t.Errorf("token request form = %v", p.lastForm)
	}
}

func TestExchangeFallsBackToPostWhenBasicUnsupported(t *testing.T) {
	p := newIdP(t)
	p.authMethods = []string{"client_secret_post"}
	p.idToken = p.sign("n", nil)
	if _, err := NewOIDC(OIDCOptions{}).Exchange(context.Background(), p.srv.URL, client1, "c", "v", "n"); err != nil {
		t.Fatal(err)
	}
	if p.lastAuth != "" || p.lastForm.Get("client_secret") != "s3cret/+" {
		t.Errorf("Authorization %q, secret %q; want client_secret_post", p.lastAuth, p.lastForm.Get("client_secret"))
	}
}

func TestExchangeRequiresAnIDToken(t *testing.T) {
	p := newIdP(t)
	if _, err := NewOIDC(OIDCOptions{}).Exchange(context.Background(), p.srv.URL, client1, "c", "v", "n"); err == nil {
		t.Fatal("a token response without an id_token was accepted")
	}
}

func TestAuthCodeURLCarriesPKCEStateAndNonce(t *testing.T) {
	p := newIdP(t)
	raw, err := NewOIDC(OIDCOptions{}).AuthCodeURL(context.Background(), p.srv.URL,
		OIDCClient{ClientID: "client-1", RedirectURI: "http://localhost/cb", Scopes: "email"},
		"st", "no", "ch", url.Values{"prompt": {"select_account"}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	for k, want := range map[string]string{
		"response_type": "code", "client_id": "client-1", "redirect_uri": "http://localhost/cb",
		"scope": "openid email", "state": "st", "nonce": "no", "code_challenge": "ch",
		"code_challenge_method": "S256", "prompt": "select_account",
	} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if !strings.HasPrefix(raw, p.srv.URL+"/authorize?") {
		t.Errorf("URL %s is not the provider's authorization endpoint", raw)
	}
}

// In production a customer-configured issuer must not be able to point App
// Central at itself, the cloud metadata service or anything else internal.
func TestRestrictedClientRefusesPrivateAddresses(t *testing.T) {
	p := newIdP(t) // listens on 127.0.0.1
	o := NewOIDC(OIDCOptions{Restricted: true})
	if _, err := o.Discover(context.Background(), p.srv.URL); err == nil {
		t.Fatal("SECURITY: a restricted client fetched from a plain-http loopback issuer")
	}
	// https alone does not help: the dialled address is what is checked.
	tls := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tls.Close)
	o.http.Transport.(*http.Transport).TLSClientConfig = tls.Client().Transport.(*http.Transport).TLSClientConfig
	_, err := o.Discover(context.Background(), tls.URL)
	if err == nil || !strings.Contains(err.Error(), "private address") {
		t.Fatalf("SECURITY: dialling a loopback https issuer: %v, want a private-address refusal", err)
	}
}

func TestIsPrivateAddress(t *testing.T) {
	for _, ip := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0",
		"100.64.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "224.0.0.1",
	} {
		if !IsPrivateAddress(net.ParseIP(ip)) {
			t.Errorf("SECURITY: %s is not treated as private", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "142.250.72.14", "2001:4860:4860::8888"} {
		if IsPrivateAddress(net.ParseIP(ip)) {
			t.Errorf("%s is treated as private", ip)
		}
	}
}
