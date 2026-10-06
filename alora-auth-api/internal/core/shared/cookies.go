package shared

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

// Cookie base names. Every cookie App Central sets is host-only: it names no
// Domain, so no other host — no product, no sibling subdomain — ever receives
// it or can overwrite it. In production each carries the __Host- prefix, which
// makes the browser itself enforce that (Secure, Path=/, no Domain), so a
// compromised sibling subdomain cannot plant one either.
const (
	cookieCentral = "alora_cs"     // the App Central session's refresh token
	cookieLogin   = "alora_login"  // binds a Google/SSO round trip to this browser
	cookieChooser = "alora_choose" // binds an account choice to this browser
)

// Lifetimes of the transient cookies. The central session cookie's lifetime is
// the session's own.
const (
	LoginStateMaxAge = 10 * time.Minute // a consent screen and back
	ChooserMaxAge    = 5 * time.Minute  // picking an account from a list
)

// CookieJar issues, reads and clears cookies with consistent, environment-correct
// attributes. Constructing every cookie through one type is what guarantees a
// clear operation replays EXACTLY the attributes used to set it — a mismatch in
// Path/Secure/SameSite means the browser silently keeps the old cookie, so
// "logout" would not actually delete the session.
type CookieJar struct {
	secure bool   // false in dev so plain-HTTP localhost still works
	prefix string // "__Host-" in production
	secret []byte // HMAC key for the signed transient cookies
}

// NewCookieJar builds the jar for an environment.
func NewCookieJar(isProd bool, secret string) *CookieJar {
	j := &CookieJar{secure: isProd, secret: []byte(secret)}
	if isProd {
		j.prefix = "__Host-"
	}
	return j
}

// CentralName is the session cookie's name in this environment.
func (j *CookieJar) CentralName() string { return j.prefix + cookieCentral }

func (j *CookieJar) base(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     j.prefix + name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   j.secure,
		HttpOnly: true, // no cookie here is ever meant for script
		// Lax, not Strict: a product sends the browser to /oauth/authorize with a
		// top-level navigation from its own site, and Google and SSO providers
		// return to the callbacks the same way. Strict would drop the cookie on
		// exactly those requests. Lax still withholds it from cross-site POSTs and
		// subresource requests, and every cookie-bearing POST is additionally
		// refused unless same-origin (middlewares.SameOriginOnly).
		SameSite: http.SameSiteLaxMode,
	}
}

func (j *CookieJar) set(c *gin.Context, name, value string, ttl time.Duration) {
	ck := j.base(name, value, int(ttl.Seconds()))
	ck.Expires = time.Now().Add(ttl)
	http.SetCookie(c.Writer, ck)
}

// clear deletes by replaying the identical attribute set with MaxAge<0. Any
// divergence and the browser keeps the cookie.
func (j *CookieJar) clear(c *gin.Context, name string) {
	ck := j.base(name, "", -1)
	ck.Expires = time.Unix(0, 0)
	http.SetCookie(c.Writer, ck)
}

// read returns a cookie's value when it is present and within bounds. The bounds
// reject absurd input before it is hashed or looked up.
func (j *CookieJar) read(c *gin.Context, name string, max int) (string, bool) {
	v, err := c.Cookie(j.prefix + name)
	if err != nil || len(v) < 16 || len(v) > max {
		return "", false
	}
	return v, true
}

// SetCentral stores the App Central session's refresh token for ttl.
func (j *CookieJar) SetCentral(c *gin.Context, token string, ttl time.Duration) {
	j.set(c, cookieCentral, token, ttl)
}

// Central reads the App Central session's refresh token.
func (j *CookieJar) Central(c *gin.Context) (string, bool) { return j.read(c, cookieCentral, 256) }

// ClearCentral deletes the App Central session cookie.
func (j *CookieJar) ClearCentral(c *gin.Context) { j.clear(c, cookieCentral) }

// SetLogin binds a pending Google or SSO sign-in to this browser. The value is
// signed, so a value the server did not mint is refused before any lookup.
func (j *CookieJar) SetLogin(c *gin.Context, state string) {
	j.set(c, cookieLogin, j.Sign(state), LoginStateMaxAge)
}

// Login reads and verifies the pending sign-in's state.
func (j *CookieJar) Login(c *gin.Context) (string, bool) { return j.unsigned(c, cookieLogin) }

// ClearLogin deletes the pending sign-in cookie.
func (j *CookieJar) ClearLogin(c *gin.Context) { j.clear(c, cookieLogin) }

// SetChooser binds an account choice to this browser.
func (j *CookieJar) SetChooser(c *gin.Context, ticket string) {
	j.set(c, cookieChooser, j.Sign(ticket), ChooserMaxAge)
}

// Chooser reads and verifies the account-choice ticket.
func (j *CookieJar) Chooser(c *gin.Context) (string, bool) { return j.unsigned(c, cookieChooser) }

// ClearChooser deletes the account-choice cookie.
func (j *CookieJar) ClearChooser(c *gin.Context) { j.clear(c, cookieChooser) }

func (j *CookieJar) unsigned(c *gin.Context, name string) (string, bool) {
	signed, ok := j.read(c, name, 512)
	if !ok {
		return "", false
	}
	v, err := j.Unsign(signed)
	if err != nil {
		return "", false
	}
	return v, true
}

// Sign returns value|base64url(HMAC-SHA256(value)). Signing does not hide the
// value; it proves the server minted it.
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
