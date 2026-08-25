// Package config loads and validates all runtime configuration from the
// environment exactly once at startup, failing fast on anything missing or
// unsafe. It is the single validated source of configuration; no other package
// reads os.Getenv.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port   int
	Host   string
	Env    string
	IsProd bool

	DatabaseURL string
	FrontendURL string

	// Connection-pool size. Explicit because pgx otherwise derives MaxConns from
	// the number of CPUs on the machine running the API, which is unrelated to
	// what the database can serve: scaling out to more or larger replicas then
	// silently multiplies connections until Postgres starts refusing them, and
	// the first symptom is a login outage.
	//
	// These supersede any pool_* parameters in DATABASE_URL, so there is exactly
	// one place to look.
	DBMaxConns int
	DBMinConns int

	// TrustedProxies is the explicit allowlist of proxy CIDRs/IPs Gin may trust
	// for X-Forwarded-* (Decision D8). Empty = trust none (never trust-all).
	TrustedProxies []string

	JWT       JWTConfig
	Cookie    CookieConfig
	Google    GoogleConfig
	Mail      MailConfig
	RateLimit RateLimitConfig
}

type JWTConfig struct {
	PrivateKeyPEM string
	PublicKeyPEM  string
	KeyID         string
	Issuer        string
	APIAudience   string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
}

type CookieConfig struct {
	Secret string
	Domain string // empty = host-only cookie
}

type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

type MailConfig struct {
	Host   string // empty = mailer disabled (invite_url returned instead)
	Port   int
	Secure bool
	User   string
	Pass   string
	From   string
}

type RateLimitConfig struct {
	GlobalMax         int
	AuthorizeMaxIP    int
	AuthorizeMaxEmail int
}

var requiredEnv = []string{
	"DATABASE_URL",
	"JWT_PRIVATE_KEY",
	"JWT_PUBLIC_KEY",
	"JWT_KEY_ID",
	"COOKIE_SECRET",
	"GOOGLE_CLIENT_ID",
	"GOOGLE_CLIENT_SECRET",
	"GOOGLE_REDIRECT_URI",
	"JWT_ISSUER",
}

// Lowercased placeholder markers rejected in production secrets.
var placeholderHints = []string{"change-this", "your-", "placeholder", "todo", "changeme"}

// Load reads, validates, and returns the configuration. The caller (main) should
// treat any error as fatal.
func Load() (*Config, error) {
	var missing []string
	for _, k := range requiredEnv {
		if os.Getenv(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("config: missing required environment variables: %s", strings.Join(missing, ", "))
	}

	// Strict allowlist. A bare `env == "production"` FAILS OPEN: "Production",
	// "prod" or a typo would silently disable the Secure cookie attribute, the
	// placeholder-secret rejection and the COOKIE_SECRET floor all at once.
	env := getenv("NODE_ENV", "development")
	switch env {
	case "development", "test", "production":
	default:
		return nil, fmt.Errorf("config: NODE_ENV must be development, test or production, got %q", env)
	}
	isProd := env == "production"

	if isProd {
		for _, secret := range []string{os.Getenv("COOKIE_SECRET"), os.Getenv("GOOGLE_CLIENT_SECRET")} {
			low := strings.ToLower(secret)
			for _, h := range placeholderHints {
				if strings.Contains(low, h) {
					return nil, errors.New("config: placeholder value detected in a secret env var; refusing to start in production")
				}
			}
		}
		if len(os.Getenv("COOKIE_SECRET")) < 32 {
			return nil, errors.New("config: COOKIE_SECRET must be at least 32 bytes in production")
		}
	}

	accessTTL, err := time.ParseDuration(getenv("JWT_ACCESS_EXPIRES_IN", "15m"))
	if err != nil {
		return nil, fmt.Errorf("config: invalid JWT_ACCESS_EXPIRES_IN: %w", err)
	}
	// ParseDuration happily accepts "-5m" and "0s"; either would mint tokens that
	// are already expired at issue.
	if accessTTL <= 0 {
		return nil, fmt.Errorf("config: JWT_ACCESS_EXPIRES_IN must be positive, got %s", accessTTL)
	}
	// Strict numeric parsing: a set-but-invalid value is a hard error, never a
	// silent fallback (codex review — fail fast on misconfiguration).
	port, err := intEnv("PORT", 3001, 1, 65535)
	if err != nil {
		return nil, err
	}
	refreshDays, err := intEnv("JWT_REFRESH_EXPIRES_DAYS", 7, 1, 365)
	if err != nil {
		return nil, err
	}
	mailPort, err := intEnv("MAIL_PORT", 587, 1, 65535)
	if err != nil {
		return nil, err
	}
	rlGlobal, err := intEnv("RATE_LIMIT_GLOBAL_MAX", 100, 1, 1_000_000)
	if err != nil {
		return nil, err
	}
	rlIP, err := intEnv("RATE_LIMIT_AUTHORIZE_IP_MAX", 10, 1, 1_000_000)
	if err != nil {
		return nil, err
	}
	rlEmail, err := intEnv("RATE_LIMIT_AUTHORIZE_EMAIL_MAX", 5, 1, 1_000_000)
	if err != nil {
		return nil, err
	}

	// Pool sizing. Bounded rather than free-form: 0 connections cannot serve a
	// request, and a four-figure pool exhausts a default Postgres (max_connections
	// 100) from a single replica.
	dbMaxConns, err := intEnv("DB_MAX_CONNS", 10, 1, 500)
	if err != nil {
		return nil, err
	}
	dbMinConns, err := intEnv("DB_MIN_CONNS", 2, 0, 500)
	if err != nil {
		return nil, err
	}
	// Warm connections are not free here: every new connection runs AfterConnect,
	// which round-trips to register the enum types. A minimum above the maximum
	// is a typo, and pgx would accept it and behave unpredictably.
	if dbMinConns > dbMaxConns {
		return nil, fmt.Errorf("config: DB_MIN_CONNS (%d) exceeds DB_MAX_CONNS (%d)", dbMinConns, dbMaxConns)
	}

	return &Config{
		Port:           port,
		Host:           getenv("HOST", "127.0.0.1"),
		Env:            env,
		IsProd:         isProd,
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		DBMaxConns:     dbMaxConns,
		DBMinConns:     dbMinConns,
		FrontendURL:    getenv("FRONTEND_URL", "http://localhost:5173"),
		TrustedProxies: splitNonEmpty(os.Getenv("TRUSTED_PROXIES")),
		JWT: JWTConfig{
			PrivateKeyPEM: normalizePEM(os.Getenv("JWT_PRIVATE_KEY")),
			PublicKeyPEM:  normalizePEM(os.Getenv("JWT_PUBLIC_KEY")),
			KeyID:         os.Getenv("JWT_KEY_ID"),
			Issuer:        os.Getenv("JWT_ISSUER"),
			APIAudience:   getenv("JWT_API_AUDIENCE", "alora-auth-api"),
			AccessTTL:     accessTTL,
			RefreshTTL:    time.Duration(refreshDays) * 24 * time.Hour,
		},
		Cookie: CookieConfig{
			Secret: os.Getenv("COOKIE_SECRET"),
			Domain: os.Getenv("COOKIE_DOMAIN"),
		},
		Google: GoogleConfig{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURI:  os.Getenv("GOOGLE_REDIRECT_URI"),
		},
		Mail: MailConfig{
			Host: os.Getenv("MAIL_HOST"),
			Port: mailPort,
			// Compare the PARSED port, not the raw string: "0465"/"+465" both parse
			// to 465 but fail a string compare, yielding an implicit-TLS port with
			// Secure=false → a plaintext EHLO against a TLS-only listener.
			Secure: mailPort == 465,
			User:   os.Getenv("MAIL_USER"),
			Pass:   os.Getenv("MAIL_PASS"),
			From:   os.Getenv("MAIL_FROM"),
		},
		RateLimit: RateLimitConfig{
			GlobalMax:         rlGlobal,
			AuthorizeMaxIP:    rlIP,
			AuthorizeMaxEmail: rlEmail,
		},
	}, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func intEnv(key string, def, min, max int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer, got %q", key, v)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("config: %s must be between %d and %d, got %d", key, min, max, n)
	}
	return n, nil
}

// normalizePEM turns literal backslash-n sequences into real newlines so PEM
// blocks can be supplied on a single env line.
func normalizePEM(s string) string {
	return strings.ReplaceAll(s, `\n`, "\n")
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
