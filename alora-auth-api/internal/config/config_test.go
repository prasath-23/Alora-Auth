package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// setValidEnv puts Load into a known-good state: every required variable set to
// a valid dummy, and every OPTIONAL one explicitly cleared. Individual tests
// then override one to exercise a failure path. t.Setenv restores previous
// values automatically.
//
// The clearing matters as much as the setting. Without it the suite inherits the
// developer's shell, and `PORT=8080 go test` failed for a reason that has nothing
// to do with the code -- a test that depends on who is running it teaches people
// to ignore it when it goes red.
//
// Keep this list in step with the variables Load reads:
//
//	grep -oE '(getenv|intEnv|boolEnv|durationEnv|os\.Getenv)\("[A-Z_]+"' internal/config/config.go
func setValidEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PORT", "HOST", "FRONTEND_URL", "TRUSTED_PROXIES", "DOCS_ENABLED",
		"COOKIE_DOMAIN", "JWT_API_AUDIENCE", "JWT_REFRESH_EXPIRES_DAYS",
		"JWT_ACCESS_EXPIRES_IN", "JWT_VERIFY_KEYS", "APP_CENTRAL_AUDIENCE",
		"SESSION_IDLE_DAYS", "SESSION_ABSOLUTE_DAYS", "PRODUCT_REFRESH_TTL", "OWNER_MAX_AUTH_AGE",
		"GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI",
		"SSO_SECRET_KEY", "SSO_SECRET_KEY_ID", "SSO_REDIRECT_URI",
		"MAIL_HOST", "MAIL_PORT", "MAIL_USER", "MAIL_PASS", "MAIL_FROM",
		"RATE_LIMIT_GLOBAL_MAX", "RATE_LIMIT_AUTHORIZE_IP_MAX", "RATE_LIMIT_SCALE",
		"DB_MAX_CONNS", "DB_MIN_CONNS",
		"GRPC_PORT", "GRPC_TLS_CERT", "GRPC_TLS_KEY", "GRPC_BEHIND_TLS_PROXY",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("NODE_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://localhost:5432/x")
	t.Setenv("JWT_PRIVATE_KEY", "priv")
	t.Setenv("JWT_PUBLIC_KEY", "pub")
	t.Setenv("JWT_KEY_ID", "kid-1")
	t.Setenv("COOKIE_SECRET", "0123456789012345678901234567890123") // 34 chars
	t.Setenv("JWT_ISSUER", "https://auth.test")
}

// setProdEnv is setValidEnv plus what production additionally requires.
func setProdEnv(t *testing.T) {
	t.Helper()
	setValidEnv(t)
	t.Setenv("NODE_ENV", "production")
	t.Setenv("FRONTEND_URL", "https://central.test")
	t.Setenv("SSO_SECRET_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
}

func TestLoadOK(t *testing.T) {
	setValidEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != 3001 {
		t.Errorf("Port = %d, want default 3001", cfg.Port)
	}
	if cfg.JWT.AppCentralAudience != "app-central" {
		t.Errorf("AppCentralAudience = %q, want default app-central", cfg.JWT.AppCentralAudience)
	}
	if cfg.JWT.AccessTTL != 15*time.Minute {
		t.Errorf("AccessTTL = %s, want 15m", cfg.JWT.AccessTTL)
	}
	s := cfg.Session
	if s.CentralIdleTTL != 7*24*time.Hour || s.CentralAbsoluteTTL != 14*24*time.Hour ||
		s.ProductRefreshTTL != 12*time.Hour || s.OwnerMaxAuthAge != 12*time.Hour {
		t.Errorf("session defaults = %+v, want 7d idle, 14d absolute, 12h product, 12h owner", s)
	}
	if cfg.Google.Enabled {
		t.Error("Google enabled with no client configured")
	}
	if cfg.SSO.SecretKey != nil || cfg.SSO.RedirectURI != "http://localhost:5173/auth/sso/callback" {
		t.Errorf("SSO = %+v, want no key and the App Central callback", cfg.SSO)
	}
	if cfg.RateLimit.Scale != 1 {
		t.Errorf("RateLimit.Scale = %d, want default 1 (the budgets as written)", cfg.RateLimit.Scale)
	}
	if cfg.IsProd {
		t.Error("IsProd true in development")
	}
}

func TestLoadProdOK(t *testing.T) {
	setProdEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.IsProd || len(cfg.SSO.SecretKey) != 32 || cfg.DocsEnabled {
		t.Errorf("prod = %v, key %d bytes, docs %v; want prod, a 32-byte key and no docs",
			cfg.IsProd, len(cfg.SSO.SecretKey), cfg.DocsEnabled)
	}
}

func TestLoadPEMNewlineNormalization(t *testing.T) {
	setValidEnv(t)
	t.Setenv("JWT_PRIVATE_KEY", `line1\nline2`) // literal backslash-n
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWT.PrivateKeyPEM != "line1\nline2" { // real newline
		t.Errorf("PEM not normalized: %q", cfg.JWT.PrivateKeyPEM)
	}
}

func TestLoadMissingRequired(t *testing.T) {
	for _, k := range []string{"DATABASE_URL", "JWT_ISSUER", "COOKIE_SECRET", "JWT_KEY_ID"} {
		setValidEnv(t)
		t.Setenv(k, "")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("missing %s: err %v, want one naming it", k, err)
		}
	}
}

// A setting an earlier version read must not be silently ignored: an operator
// who set COOKIE_DOMAIN believes sessions are shared with other hosts.
func TestLoadRefusesRetiredVariables(t *testing.T) {
	for k, v := range map[string]string{
		"COOKIE_DOMAIN": ".alora.io", "JWT_API_AUDIENCE": "alora-auth-api", "JWT_REFRESH_EXPIRES_DAYS": "7",
	} {
		setValidEnv(t)
		t.Setenv(k, v)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%s: err %v, want a refusal naming it", k, v, err)
		}
	}
}

func TestLoadProdRejectsPlaceholderSecret(t *testing.T) {
	setProdEnv(t)
	t.Setenv("COOKIE_SECRET", "change-this-secret-value-that-is-long-enough")
	if _, err := Load(); err == nil {
		t.Error("expected error for placeholder secret in production")
	}
}

func TestLoadProdRejectsShortCookieSecret(t *testing.T) {
	setProdEnv(t)
	t.Setenv("COOKIE_SECRET", "tooshort") // <32, no placeholder word
	if _, err := Load(); err == nil {
		t.Error("expected error for short COOKIE_SECRET in production")
	}
}

// Tokens and the session cookie travel to the issuer and App Central, so both
// are https in production; and the issuer is compared byte for byte, so a
// trailing slash is a different issuer and refused everywhere.
func TestLoadValidatesOrigins(t *testing.T) {
	cases := []struct {
		name, key, value string
		prod             bool
	}{
		{"http issuer in production", "JWT_ISSUER", "http://auth.test", true},
		{"http App Central in production", "FRONTEND_URL", "http://central.test", true},
		{"trailing slash", "JWT_ISSUER", "https://auth.test/", false},
		{"not a URL", "JWT_ISSUER", "auth.test", false},
		{"query", "JWT_ISSUER", "https://auth.test?x=1", false},
		{"fragment", "FRONTEND_URL", "https://central.test#x", false},
		{"credentials", "JWT_ISSUER", "https://user:pw@auth.test", false},
		{"other scheme", "FRONTEND_URL", "ftp://central.test", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.prod {
				setProdEnv(t)
			} else {
				setValidEnv(t)
			}
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Errorf("%s=%q accepted", tc.key, tc.value)
			}
		})
	}
	// http is fine outside production, where App Central runs on localhost.
	setValidEnv(t)
	t.Setenv("JWT_ISSUER", "http://localhost:5173")
	if _, err := Load(); err != nil {
		t.Errorf("http issuer in development: %v", err)
	}
}

func TestLoadGoogleIsAllOrNothing(t *testing.T) {
	full := map[string]string{
		"GOOGLE_CLIENT_ID": "gid", "GOOGLE_CLIENT_SECRET": "gsecret",
		"GOOGLE_REDIRECT_URI": "http://localhost:5173/auth/google/callback",
	}
	setValidEnv(t)
	for k, v := range full {
		t.Setenv(k, v)
	}
	cfg, err := Load()
	if err != nil || !cfg.Google.Enabled || cfg.Google.ClientID != "gid" {
		t.Fatalf("full Google config: enabled=%v err=%v", cfg != nil && cfg.Google.Enabled, err)
	}
	for missing := range full {
		setValidEnv(t)
		for k, v := range full {
			if k != missing {
				t.Setenv(k, v)
			}
		}
		if _, err := Load(); err == nil {
			t.Errorf("Google config without %s accepted", missing)
		}
	}
	// A plaintext callback in production would hand Google's code to anyone
	// on the path.
	setProdEnv(t)
	for k, v := range full {
		t.Setenv(k, v)
	}
	if _, err := Load(); err == nil {
		t.Error("http GOOGLE_REDIRECT_URI accepted in production")
	}
}

func TestLoadSSOSecretKey(t *testing.T) {
	for name, v := range map[string]string{
		"not base64": "not base64!!", "16 bytes": base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"64 bytes": base64.StdEncoding.EncodeToString(make([]byte, 64)),
	} {
		setValidEnv(t)
		t.Setenv("SSO_SECRET_KEY", v)
		if _, err := Load(); err == nil {
			t.Errorf("SSO_SECRET_KEY %s accepted", name)
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		setValidEnv(t)
		key := make([]byte, 32)
		key[0] = 7
		t.Setenv("SSO_SECRET_KEY", enc.EncodeToString(key))
		cfg, err := Load()
		if err != nil || len(cfg.SSO.SecretKey) != 32 || cfg.SSO.SecretKey[0] != 7 {
			t.Errorf("valid key rejected or garbled: %v", err)
		}
	}
	setProdEnv(t)
	t.Setenv("SSO_SECRET_KEY", "")
	if _, err := Load(); err == nil {
		t.Error("production started without SSO_SECRET_KEY")
	}
}

func TestLoadVerifyKeys(t *testing.T) {
	setValidEnv(t)
	t.Setenv("JWT_VERIFY_KEYS", `old-1=-----BEGIN PUBLIC KEY-----\nAAA=\n-----END PUBLIC KEY-----; old-2=PEM2`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.JWT.VerifyKeys) != 2 || cfg.JWT.VerifyKeys[0].KeyID != "old-1" ||
		!strings.Contains(cfg.JWT.VerifyKeys[0].PublicKeyPEM, "\nAAA=\n") || cfg.JWT.VerifyKeys[1].KeyID != "old-2" {
		t.Errorf("verify keys = %+v", cfg.JWT.VerifyKeys)
	}
	for name, v := range map[string]string{
		"no separator": "old-1", "empty kid": "=PEM", "empty pem": "old-1=",
		"repeated kid": "a=P1;a=P2", "the signing kid": "kid-1=PEM",
	} {
		setValidEnv(t)
		t.Setenv("JWT_VERIFY_KEYS", v)
		if _, err := Load(); err == nil {
			t.Errorf("JWT_VERIFY_KEYS %s accepted", name)
		}
	}
}

func TestLoadStrictNumericFailFast(t *testing.T) {
	setValidEnv(t)
	t.Setenv("PORT", "not-a-number")
	if _, err := Load(); err == nil {
		t.Error("expected error for non-numeric PORT (fail-fast, no silent default)")
	}
}

// Regression (audit critical #5): `env == "production"` FAILS OPEN. A typo like
// "Production" or "prod" would silently disable Secure cookies, the placeholder
// scan and the COOKIE_SECRET floor simultaneously.
func TestLoadRejectsUnknownEnvName(t *testing.T) {
	for _, bad := range []string{"Production", "prod", "PRODUCTION", "staging", "dev"} {
		setValidEnv(t)
		t.Setenv("NODE_ENV", bad)
		if _, err := Load(); err == nil {
			t.Errorf("SECURITY: NODE_ENV=%q accepted; prod controls would silently be off", bad)
		}
	}
}

// Regression: ParseDuration accepts "-5m"/"0s", which would mint already-expired
// tokens and sessions.
func TestLoadRejectsNonPositiveDurations(t *testing.T) {
	for _, k := range []string{"JWT_ACCESS_EXPIRES_IN", "PRODUCT_REFRESH_TTL", "OWNER_MAX_AUTH_AGE"} {
		for _, bad := range []string{"-5m", "0s", "soon"} {
			setValidEnv(t)
			t.Setenv(k, bad)
			if _, err := Load(); err == nil {
				t.Errorf("expected error for %s=%q", k, bad)
			}
		}
	}
}

// An idle timeout beyond the absolute cap never applies.
func TestLoadRejectsIdleBeyondAbsolute(t *testing.T) {
	setValidEnv(t)
	t.Setenv("SESSION_IDLE_DAYS", "30")
	t.Setenv("SESSION_ABSOLUTE_DAYS", "14")
	if _, err := Load(); err == nil {
		t.Error("idle 30d under a 14d cap accepted")
	}
}

// Regression: MAIL_PORT was compared as a raw string against "465", so "0465"
// parsed to port 465 but left Secure=false → plaintext EHLO to a TLS-only port.
func TestMailSecureUsesParsedPort(t *testing.T) {
	setValidEnv(t)
	t.Setenv("MAIL_PORT", "0465")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mail.Port != 465 || !cfg.Mail.Secure {
		t.Errorf("Port=%d Secure=%v, want 465/true", cfg.Mail.Port, cfg.Mail.Secure)
	}
}

// Regression: out-of-range numerics must fail fast, not silently pass through.
func TestLoadRejectsOutOfRangeNumerics(t *testing.T) {
	cases := map[string]string{
		"PORT": "70000", "SESSION_IDLE_DAYS": "0", "SESSION_ABSOLUTE_DAYS": "400", "RATE_LIMIT_GLOBAL_MAX": "0",
		// 0 would switch every scaled budget off: each would admit nothing.
		"RATE_LIMIT_SCALE": "0",
	}
	for k, v := range cases {
		setValidEnv(t)
		t.Setenv(k, v)
		if _, err := Load(); err == nil {
			t.Errorf("expected error for %s=%s", k, v)
		}
	}
}

// Pool sizing is validated at startup rather than trusted, because every one of
// these mistakes produces a service that starts cleanly and then fails under
// load, when the cause is furthest from the symptom.
func TestPoolSizingIsValidated(t *testing.T) {
	cases := []struct {
		name, max, min string
		wantErr        string
	}{
		{"min above max", "5", "9", "exceeds"},
		{"zero max cannot serve a request", "0", "0", "between"},
		{"max beyond any sane server", "5000", "1", "between"},
		{"non-numeric", "ten", "1", "integer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv("DB_MAX_CONNS", tc.max)
			t.Setenv("DB_MIN_CONNS", tc.min)

			_, err := Load()
			if err == nil {
				t.Fatalf("accepted DB_MAX_CONNS=%q DB_MIN_CONNS=%q; a pool that cannot "+
					"serve traffic must not reach production", tc.max, tc.min)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q, so it will not tell an operator what to change",
					err, tc.wantErr)
			}
		})
	}
}

func TestPoolSizingDefaults(t *testing.T) {
	setValidEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Explicit values, not pgx's CPU-derived default: the number of cores the API
	// happens to run on says nothing about what the database can serve.
	if cfg.DBMaxConns != 10 || cfg.DBMinConns != 2 {
		t.Fatalf("defaults are max=%d min=%d, want max=10 min=2", cfg.DBMaxConns, cfg.DBMinConns)
	}
}

// readEnvExample parses ../../.env.example into its KEY=VALUE assignments.
func readEnvExample(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf(".env.example: not an assignment: %q", line)
		}
		out[k] = v
	}
	return out
}

// The example is what an operator copies. It must start as it is (with the
// signing keys, which it cannot ship, filled in), document every variable Load
// reads, and name nothing Load ignores — a stale variable in it is a setting
// somebody will believe applies.
func TestEnvExampleMatchesWhatLoadReads(t *testing.T) {
	example := readEnvExample(t)

	src, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}
	read := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?:getenv|intEnv|boolEnv|durationEnv|os\.Getenv)\("([A-Z0-9_]+)"`).FindAllStringSubmatch(string(src), -1) {
		read[m[1]] = true
	}
	for k := range example {
		if !read[k] {
			t.Errorf(".env.example sets %s, which Load never reads", k)
		}
	}
	for k := range read {
		if _, ok := example[k]; !ok {
			t.Errorf("Load reads %s, which .env.example does not document", k)
		}
	}

	setValidEnv(t)
	for k, v := range example {
		t.Setenv(k, v)
	}
	t.Setenv("JWT_PRIVATE_KEY", "priv")
	t.Setenv("JWT_PUBLIC_KEY", "pub")
	if _, err := Load(); err != nil {
		t.Fatalf("the example does not start: %v", err)
	}
}

// gRPC is off unless a port is named. In production every call carries a client
// secret, so the listener must serve TLS itself or sit behind a proxy that does:
// plaintext on the network is refused at startup, and so is a half-set or
// contradictory TLS setup.
func TestGRPCListenerIsOffOrSafe(t *testing.T) {
	setValidEnv(t)
	cfg, err := Load()
	if err != nil || cfg.GRPC.Enabled() {
		t.Fatalf("gRPC with no port: %+v, %v", cfg.GRPC, err)
	}
	t.Setenv("GRPC_PORT", "3002")
	if cfg, err = Load(); err != nil || !cfg.GRPC.Enabled() || cfg.GRPC.TLS() {
		t.Fatalf("plaintext gRPC outside production: %+v, %v", cfg.GRPC, err)
	}

	setProdEnv(t)
	t.Setenv("GRPC_PORT", "3002")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "GRPC_TLS_CERT") {
		t.Errorf("SECURITY: plaintext gRPC in production was accepted: %v", err)
	}
	t.Setenv("GRPC_BEHIND_TLS_PROXY", "true")
	if cfg, err := Load(); err != nil || !cfg.GRPC.BehindTLSProxy {
		t.Errorf("gRPC behind a TLS proxy: %+v, %v", cfg, err)
	}
	t.Setenv("GRPC_TLS_CERT", "cert.pem")
	t.Setenv("GRPC_TLS_KEY", "key.pem")
	if _, err := Load(); err == nil {
		t.Error("TLS here AND a TLS proxy in front was accepted")
	}
	t.Setenv("GRPC_BEHIND_TLS_PROXY", "false")
	if cfg, err := Load(); err != nil || !cfg.GRPC.TLS() {
		t.Errorf("gRPC with its own TLS: %+v, %v", cfg, err)
	}
	t.Setenv("GRPC_TLS_KEY", "")
	if _, err := Load(); err == nil {
		t.Error("a certificate without its key was accepted")
	}
	t.Setenv("GRPC_TLS_KEY", "key.pem")
	for _, bad := range []string{"3001", "-1", "70000", "x"} {
		t.Setenv("GRPC_PORT", bad)
		if _, err := Load(); err == nil {
			t.Errorf("GRPC_PORT=%s was accepted", bad)
		}
	}
}
