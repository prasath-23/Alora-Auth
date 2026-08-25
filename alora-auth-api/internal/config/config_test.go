package config

import (
	"strings"
	"testing"
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
//	grep -oE '(getenv|intEnv|os\.Getenv)\("[A-Z_]+"' internal/config/config.go
func setValidEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PORT", "HOST", "FRONTEND_URL", "COOKIE_DOMAIN", "TRUSTED_PROXIES",
		"JWT_ACCESS_EXPIRES_IN", "JWT_REFRESH_EXPIRES_DAYS", "JWT_API_AUDIENCE",
		"MAIL_HOST", "MAIL_PORT", "MAIL_USER", "MAIL_PASS", "MAIL_FROM",
		"RATE_LIMIT_GLOBAL_MAX", "RATE_LIMIT_AUTHORIZE_IP_MAX", "RATE_LIMIT_AUTHORIZE_EMAIL_MAX",
		"DB_MAX_CONNS", "DB_MIN_CONNS",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("NODE_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://localhost:5432/x")
	t.Setenv("JWT_PRIVATE_KEY", "priv")
	t.Setenv("JWT_PUBLIC_KEY", "pub")
	t.Setenv("JWT_KEY_ID", "kid-1")
	t.Setenv("COOKIE_SECRET", "0123456789012345678901234567890123") // 34 chars
	t.Setenv("GOOGLE_CLIENT_ID", "gid")
	t.Setenv("GOOGLE_CLIENT_SECRET", "gsecret")
	t.Setenv("GOOGLE_REDIRECT_URI", "http://localhost:3001/auth/google/callback")
	t.Setenv("JWT_ISSUER", "https://auth.test")
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
	if cfg.JWT.APIAudience != "alora-auth-api" {
		t.Errorf("APIAudience = %q, want default alora-auth-api", cfg.JWT.APIAudience)
	}
	if cfg.IsProd {
		t.Error("IsProd true in development")
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
	setValidEnv(t)
	t.Setenv("DATABASE_URL", "") // simulate missing
	if _, err := Load(); err == nil {
		t.Error("expected error for missing DATABASE_URL")
	}
}

func TestLoadProdRejectsPlaceholderSecret(t *testing.T) {
	setValidEnv(t)
	t.Setenv("NODE_ENV", "production")
	t.Setenv("COOKIE_SECRET", "change-this-secret-value-that-is-long-enough")
	if _, err := Load(); err == nil {
		t.Error("expected error for placeholder secret in production")
	}
}

func TestLoadProdRejectsShortCookieSecret(t *testing.T) {
	setValidEnv(t)
	t.Setenv("NODE_ENV", "production")
	t.Setenv("COOKIE_SECRET", "tooshort") // <32, no placeholder word
	if _, err := Load(); err == nil {
		t.Error("expected error for short COOKIE_SECRET in production")
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

// Regression: ParseDuration accepts "-5m"/"0s", which would mint already-expired tokens.
func TestLoadRejectsNonPositiveAccessTTL(t *testing.T) {
	for _, bad := range []string{"-5m", "0s"} {
		setValidEnv(t)
		t.Setenv("JWT_ACCESS_EXPIRES_IN", bad)
		if _, err := Load(); err == nil {
			t.Errorf("expected error for JWT_ACCESS_EXPIRES_IN=%q", bad)
		}
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
	cases := map[string]string{"PORT": "70000", "JWT_REFRESH_EXPIRES_DAYS": "0", "RATE_LIMIT_GLOBAL_MAX": "0"}
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
