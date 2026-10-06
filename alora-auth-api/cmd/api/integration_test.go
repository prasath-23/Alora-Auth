package main

// Integration tests exercise the REAL router, middleware chain and database, so
// they cannot drift from production the way a hand-rolled test harness would.
// Skipped unless ALORA_TEST_DB points at a built database, keeping
// `go test ./...` green on a machine without Docker:
//
//	bash scripts/integration-test.sh
//
// The router connects as ALORA_TEST_DB, which the script points at the
// least-privilege alora_app role, exactly as production does. Fixtures are
// seeded through ALORA_TEST_OWNER_DB, the schema owner: they write rows the
// application role deliberately cannot, such as an Owner.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/alora/auth/internal/config"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/database/contexts"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	testIssuer   = "https://auth.alora.test"
	testFrontend = "https://central.alora.test"
	testPassword = "correct horse battery staple"
)

// testSSOKey is the 32-byte key SSO secrets are sealed with in tests.
var testSSOKey = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

func testEnv(t *testing.T) {
	t.Helper()
	dsn := os.Getenv("ALORA_TEST_DB")
	if dsn == "" {
		t.Skip("ALORA_TEST_DB not set; skipping integration tests")
	}
	priv, pub := os.Getenv("ALORA_TEST_PRIV"), os.Getenv("ALORA_TEST_PUB")
	if priv == "" || pub == "" {
		t.Skip("ALORA_TEST_PRIV/PUB not set; skipping integration tests")
	}
	for k, v := range map[string]string{
		"NODE_ENV":             "test",
		"DATABASE_URL":         dsn,
		"JWT_PRIVATE_KEY":      priv,
		"JWT_PUBLIC_KEY":       pub,
		"JWT_KEY_ID":           "test-kid",
		"JWT_ISSUER":           testIssuer,
		"JWT_VERIFY_KEYS":      "",
		"FRONTEND_URL":         testFrontend,
		"COOKIE_SECRET":        "0123456789012345678901234567890123456789",
		"GOOGLE_CLIENT_ID":     "gid",
		"GOOGLE_CLIENT_SECRET": "gsecret",
		"GOOGLE_REDIRECT_URI":  testFrontend + "/auth/google/callback",
		"SSO_SECRET_KEY":       testSSOKey,
		"SSO_SECRET_KEY_ID":    "test-k1",
		"MAIL_HOST":            "",
		"COOKIE_DOMAIN":        "",
		"TRUSTED_PROXIES":      "",
	} {
		t.Setenv(k, v)
	}
}

// ownerDSN is the connection tests seed and inspect through.
func ownerDSN() string {
	if dsn := os.Getenv("ALORA_TEST_OWNER_DB"); dsn != "" {
		return dsn
	}
	return os.Getenv("ALORA_TEST_DB")
}

// app is one router over the real wiring, plus the owner's connection for
// seeding and assertions.
type app struct {
	t     *testing.T
	cfg   *config.Config
	m     *modules
	r     *gin.Engine
	db    *contexts.DbContext // the router's own (alora_app)
	owner *contexts.DbContext // the schema owner's
	pool  *pgxpool.Pool       // owner.Pool(), for plain SQL
}

func newApp(t *testing.T) *app { return newAppWith(t, nil, nil) }

// newAppWith lets a test adjust the environment before configuration loads and
// the wiring before the router is built.
func newAppWith(t *testing.T, env map[string]string, adjust func(*modules)) *app {
	t.Helper()
	testEnv(t)
	for k, v := range env {
		t.Setenv(k, v)
	}
	gin.SetMode(gin.TestMode)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := initKeys(cfg); err != nil {
		t.Fatalf("jwtkeys: %v", err)
	}
	ctx := context.Background()
	db, err := contexts.Connect(ctx, cfg.DatabaseURL, contexts.Options{})
	if err != nil {
		t.Fatalf("database: %v", err)
	}
	t.Cleanup(db.Close)
	owner, err := contexts.Connect(ctx, ownerDSN(), contexts.Options{})
	if err != nil {
		t.Fatalf("owner database: %v", err)
	}
	t.Cleanup(owner.Close)

	log := testLogger()
	m, err := newModules(cfg, log, db)
	if err != nil {
		t.Fatalf("modules: %v", err)
	}
	if adjust != nil {
		adjust(m)
	}
	r, err := newRouter(cfg, log, m)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	return &app{t: t, cfg: cfg, m: m, r: r, db: db, owner: owner, pool: owner.Pool()}
}

// testLogger is quiet unless ALORA_TEST_VERBOSE is set: every refusal a test
// provokes is otherwise a DEBUG line, and they bury the one failure that matters.
func testLogger() *slog.Logger {
	if os.Getenv("ALORA_TEST_VERBOSE") != "" {
		return shared.NewLogger(false)
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// rebuild swaps in a router over adjusted wiring, keeping the connections.
func (a *app) rebuild(adjust func(*modules)) {
	a.t.Helper()
	log := testLogger()
	m, err := newModules(a.cfg, log, a.db)
	if err != nil {
		a.t.Fatal(err)
	}
	adjust(m)
	r, err := newRouter(a.cfg, log, m)
	if err != nil {
		a.t.Fatal(err)
	}
	a.m, a.r = m, r
}

// ---------- requests ----------

type reqOpt func(*http.Request)

func bearer(tok string) reqOpt {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}
func withCookie(ck *http.Cookie) reqOpt {
	return func(r *http.Request) {
		if ck != nil {
			r.AddCookie(ck)
		}
	}
}
func header(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func basic(id, secret string) reqOpt {
	return func(r *http.Request) { r.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret)) }
}

// send issues a request to the router. A body that is url.Values is sent as a
// form, a string as-is with no content type, anything else as JSON.
func (a *app) send(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	var rd io.Reader
	ctype := ""
	switch b := body.(type) {
	case nil:
	case url.Values:
		rd, ctype = strings.NewReader(b.Encode()), "application/x-www-form-urlencoded"
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd, ctype = strings.NewReader(string(raw)), "application/json"
	}
	req := httptest.NewRequest(method, path, rd)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for _, o := range opts {
		o(req)
	}
	w := httptest.NewRecorder()
	a.r.ServeHTTP(w, req)
	return w
}

func (a *app) get(path string, opts ...reqOpt) *httptest.ResponseRecorder {
	return a.send(http.MethodGet, path, nil, opts...)
}

func (a *app) post(path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	return a.send(http.MethodPost, path, body, opts...)
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, ck := range w.Result().Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

// decode reads a JSON response body into a map.
func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not a JSON object (%d): %s", w.Code, w.Body.String())
	}
	return m
}

func decodeInto(t *testing.T, w *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode %d %s: %v", w.Code, w.Body.String(), err)
	}
}

func jsonField(w *httptest.ResponseRecorder, key string) string {
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	s, _ := m[key].(string)
	return s
}

func expect(t *testing.T, w *httptest.ResponseRecorder, status int, what string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("%s: status %d, want %d (%s)", what, w.Code, status, w.Body.String())
	}
}

// randSuffix keeps seeded rows unique so repeated runs cannot collide on the
// unique indexes.
func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

// exec runs owner-side SQL for a fixture adjustment.
func (a *app) exec(sql string, args ...any) {
	a.t.Helper()
	if _, err := a.pool.Exec(context.Background(), sql, args...); err != nil {
		a.t.Fatalf("exec %q: %v", sql, err)
	}
}

func (a *app) scalar(dst any, sql string, args ...any) {
	a.t.Helper()
	if err := a.pool.QueryRow(context.Background(), sql, args...).Scan(dst); err != nil {
		a.t.Fatalf("query %q: %v", sql, err)
	}
}

func (a *app) count(sql string, args ...any) int {
	a.t.Helper()
	var n int
	a.scalar(&n, sql, args...)
	return n
}

var platformOnce sync.Mutex

func decodeSegment(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// claims reads a JWT's payload WITHOUT verifying it: for asserting what a token
// that was already verified (or is about to be refused) carries.
func claims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := decodeSegment(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// jwtHeader reads a JWT's protected header.
func jwtHeader(t *testing.T, tok string) map[string]any {
	t.Helper()
	raw, err := decodeSegment(strings.Split(tok, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}
