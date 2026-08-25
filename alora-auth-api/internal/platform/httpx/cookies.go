package httpx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Cookie names. NOTE: deliberately NO `__Host-` prefix — that prefix forbids a
// Domain attribute, and these cookies need Domain=.alora.io for cross-subdomain
// SSO. (The stale design notes claimed __Host-; the shipped Node code does not.)
const (
	CookieRefresh    = "alora_rt"
	CookieAccess     = "alora_at"
	CookieOAuthState = "alora_oauth_state"
)

// AccessCookieMaxAge mirrors the access-token TTL advertised as expires_in.
const AccessCookieMaxAge = 900 // seconds (15m)

// OAuthStateMaxAge bounds how long a Google OAuth round-trip may take.
const OAuthStateMaxAge = 600 // seconds (10m)

// CookieJar issues and clears cookies with consistent, environment-correct
// attributes. Constructing every cookie through one type is what guarantees a
// clear operation replays EXACTLY the attributes used to set it — a mismatch in
// Path/Domain/Secure/SameSite means the browser silently keeps the old cookie,
// so "logout" would not actually delete the refresh token.
type CookieJar struct {
	domain string // "" = host-only cookie
	secure bool   // false in dev so plain-HTTP localhost still works
	secret []byte // HMAC key for signed cookies
}

func NewCookieJar(domain string, isProd bool, secret string) *CookieJar {
	return &CookieJar{domain: domain, secure: isProd, secret: []byte(secret)}
}

func (j *CookieJar) base(name, value string, maxAge int, httpOnly bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   j.domain,
		MaxAge:   maxAge,
		Secure:   j.secure,
		HttpOnly: httpOnly,
		// Lax (not Strict) is required: Strict would drop the cookie on the
		// top-level redirect back from Google, breaking the OAuth callback.
		// Lax still blocks cross-site POST, which is the CSRF vector that matters
		// (there is no CSRF token — this is the structural defense).
		SameSite: http.SameSiteLaxMode,
	}
}

// SetRefresh stores the refresh token. HttpOnly so JS can never read it, with an
// absolute expiry matching the token's own lifetime.
func (j *CookieJar) SetRefresh(c *gin.Context, token string, ttl time.Duration) {
	ck := j.base(CookieRefresh, token, int(ttl.Seconds()), true)
	ck.Expires = time.Now().Add(ttl)
	http.SetCookie(c.Writer, ck)
}

// SetAccess stores the access token with HttpOnly=FALSE by design: the SPA reads
// it to build the Authorization header. It is short-lived (900s) and carries no
// refresh capability, so JS-readability is an accepted, bounded trade-off.
func (j *CookieJar) SetAccess(c *gin.Context, token string) {
	http.SetCookie(c.Writer, j.base(CookieAccess, token, AccessCookieMaxAge, false))
}

// SetOAuthState stores the HMAC-signed OAuth state payload.
func (j *CookieJar) SetOAuthState(c *gin.Context, payload string) {
	http.SetCookie(c.Writer, j.base(CookieOAuthState, j.Sign(payload), OAuthStateMaxAge, true))
}

// ClearRefresh/ClearAccess/ClearOAuthState delete by replaying the identical
// attribute set with MaxAge<0. Any divergence and the browser keeps the cookie.
func (j *CookieJar) ClearRefresh(c *gin.Context)    { j.clear(c, CookieRefresh, true) }
func (j *CookieJar) ClearAccess(c *gin.Context)     { j.clear(c, CookieAccess, false) }
func (j *CookieJar) ClearOAuthState(c *gin.Context) { j.clear(c, CookieOAuthState, true) }

func (j *CookieJar) clear(c *gin.Context, name string, httpOnly bool) {
	ck := j.base(name, "", -1, httpOnly)
	ck.Expires = time.Unix(0, 0)
	http.SetCookie(c.Writer, ck)
}

// Sign returns value|base64url(HMAC-SHA256(value)). Signing does not hide the
// value; it proves the server minted it, so a client cannot forge OAuth state.
func (j *CookieJar) Sign(value string) string {
	return value + "|" + base64.RawURLEncoding.EncodeToString(j.mac(value))
}

// Unsign verifies and returns the payload. The MAC is compared in constant time
// so an attacker cannot brute-force a signature byte-by-byte via timing.
func (j *CookieJar) Unsign(signed string) (string, error) {
	value, sig, ok := strings.Cut(signed, "|")
	if !ok {
		return "", errors.New("cookie: malformed signed value")
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return "", errors.New("cookie: malformed signature")
	}
	if !hmac.Equal(want, j.mac(value)) {
		return "", errors.New("cookie: signature mismatch")
	}
	return value, nil
}

func (j *CookieJar) mac(value string) []byte {
	m := hmac.New(sha256.New, j.secret)
	m.Write([]byte(value))
	return m.Sum(nil)
}
