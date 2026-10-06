// Package config loads and validates all runtime configuration from the
// environment exactly once at startup, failing fast on anything missing or
// unsafe. It is the single validated source of configuration; no other package
// reads os.Getenv.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
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

	// FrontendURL is App Central's own origin: where the login page, the launcher
	// and the admin and Owner consoles are served, and where invitation and reset
	// links point. The API is served from the same origin (see SPEC D15).
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

	// DocsEnabled serves the OpenAPI document and Swagger UI at /docs.
	//
	// Defaults ON outside production and OFF in it. The document is a complete
	// map of the admin surface — every route, every parameter, every feature key
	// that guards it — and the UI is a ready-made request console pointed at the
	// same origin. None of that is a vulnerability on its own, but publishing it
	// from an identity provider hands an attacker the reconnaissance step for
	// free, so it is opt-in rather than opt-out where it matters.
	DocsEnabled bool

	JWT       JWTConfig
	Session   SessionConfig
	Cookie    CookieConfig
	Google    GoogleConfig
	SSO       SSOConfig
	Mail      MailConfig
	RateLimit RateLimitConfig
	GRPC      GRPCConfig
}

// GRPCConfig is App Central's gRPC listener, where applications get tokens with
// client credentials (TokenService). Off unless GRPC_PORT is set.
//
// Every call carries a client secret in its metadata, so in production the
// listener must never be plaintext on the network: it serves TLS itself (a
// certificate and key), or it sits behind a proxy that terminates TLS for it.
type GRPCConfig struct {
	Port           int    // 0: no gRPC listener
	TLSCertFile    string // PEM files, set together: the listener serves TLS itself
	TLSKeyFile     string
	BehindTLSProxy bool // plaintext here, because a proxy in front terminates TLS
}

// Enabled reports whether App Central listens for gRPC.
func (g GRPCConfig) Enabled() bool { return g.Port != 0 }

// TLS reports whether the listener serves TLS itself.
func (g GRPCConfig) TLS() bool { return g.TLSCertFile != "" }

type JWTConfig struct {
	PrivateKeyPEM string
	PublicKeyPEM  string
	KeyID         string
	Issuer        string
	// VerifyKeys are public keys that still verify but no longer sign: the key
	// being retired during a rotation, published in the JWKS until every token
	// it signed has expired.
	VerifyKeys []VerifyKey
	// AppCentralAudience is the only audience App Central's own API accepts. A
	// product token never carries it, so it can never reach /api.
	AppCentralAudience string
	// AccessTTL is the lifetime of every access token, App Central's and the
	// products' alike.
	AccessTTL time.Duration
}

// VerifyKey is one verify-only public key.
type VerifyKey struct {
	KeyID        string
	PublicKeyPEM string
}

type SessionConfig struct {
	// CentralIdleTTL is how long an App Central session survives without use.
	// Each refresh extends it, up to CentralAbsoluteTTL.
	CentralIdleTTL time.Duration
	// CentralAbsoluteTTL is how long an App Central session can last at all
	// before its user must sign in again. Every product login under it ends then
	// too.
	CentralAbsoluteTTL time.Duration
	// ProductRefreshTTL is how long a product's refresh token lives, capped at
	// the central session's absolute expiry.
	ProductRefreshTTL time.Duration
	// OwnerMaxAuthAge is how long after signing in an Owner may use the Owner
	// console; after that they sign in again.
	OwnerMaxAuthAge time.Duration
}

type CookieConfig struct {
	Secret string
}

// GoogleConfig is the Google sign-in client. Google sign-in is offered only when
// all three are set.
type GoogleConfig struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// SSOConfig is what company OIDC SSO needs from the deployment. The connections
// themselves are data the Owner registers.
type SSOConfig struct {
	// SecretKey seals every connection's client secret (AES-256-GCM). nil means
	// no secret can be stored, so no connection can be used; it is required in
	// production.
	SecretKey   []byte
	SecretKeyID string
	// RedirectURI is the callback every connection registers at its provider.
	RedirectURI string
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
	GlobalMax int
	// AuthorizeMaxIP is the password sign-in budget per minute, per address and
	// email together (see emailKey in cmd/api).
	AuthorizeMaxIP int
	// Scale multiplies every per-route budget that has no variable of its own
	// (refresh, discovery, invitations, the OAuth endpoints…). Those are sized
	// for one person at one address; many people behind one egress address — or
	// a browser test suite driving every flow from localhost — need more.
	Scale int
	// SharedStore is true when the brute-force-sensitive budgets (password
	// sign-in, the token endpoint, failed client authentications, per-account
	// password change) keep their counters in the database, so several API
	// instances behind a load balancer enforce ONE budget together instead of
	// each granting it in full. Off by default (per-process counters); set
	// RATE_LIMIT_STORE=database to turn it on.
	SharedStore bool
}

var requiredEnv = []string{
	"DATABASE_URL",
	"JWT_PRIVATE_KEY",
	"JWT_PUBLIC_KEY",
	"JWT_KEY_ID",
	"JWT_ISSUER",
	"COOKIE_SECRET",
}

// retiredEnv are variables an earlier version read. Starting with one set would
// leave an operator believing a setting applies that no longer does, so each is
// refused with what replaced it.
var retiredEnv = map[string]string{
	"COOKIE_DOMAIN": "session cookies are host-only and can no longer be shared with other hosts; " +
		"products receive their own tokens from /oauth/token instead (unset it)",
	"JWT_API_AUDIENCE":         "replaced by APP_CENTRAL_AUDIENCE",
	"JWT_REFRESH_EXPIRES_DAYS": "replaced by SESSION_IDLE_DAYS and SESSION_ABSOLUTE_DAYS",
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
	for _, k := range []string{"COOKIE_DOMAIN", "JWT_API_AUDIENCE", "JWT_REFRESH_EXPIRES_DAYS"} {
		if os.Getenv(k) != "" {
			return nil, fmt.Errorf("config: %s is no longer supported: %s", k, retiredEnv[k])
		}
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
		for _, k := range []string{"COOKIE_SECRET", "GOOGLE_CLIENT_SECRET", "SSO_SECRET_KEY"} {
			low := strings.ToLower(os.Getenv(k))
			for _, h := range placeholderHints {
				if strings.Contains(low, h) {
					return nil, fmt.Errorf("config: placeholder value detected in %s; refusing to start in production", k)
				}
			}
		}
		if len(os.Getenv("COOKIE_SECRET")) < 32 {
			return nil, errors.New("config: COOKIE_SECRET must be at least 32 bytes in production")
		}
	}

	issuer, err := originURL("JWT_ISSUER", os.Getenv("JWT_ISSUER"), isProd)
	if err != nil {
		return nil, err
	}
	frontend, err := originURL("FRONTEND_URL", getenv("FRONTEND_URL", "http://localhost:5173"), isProd)
	if err != nil {
		return nil, err
	}

	accessTTL, err := durationEnv("JWT_ACCESS_EXPIRES_IN", 15*time.Minute)
	if err != nil {
		return nil, err
	}
	// Strict numeric parsing: a set-but-invalid value is a hard error, never a
	// silent fallback (codex review — fail fast on misconfiguration).
	port, err := intEnv("PORT", 3001, 1, 65535)
	if err != nil {
		return nil, err
	}
	idleDays, err := intEnv("SESSION_IDLE_DAYS", 7, 1, 90)
	if err != nil {
		return nil, err
	}
	absoluteDays, err := intEnv("SESSION_ABSOLUTE_DAYS", 14, 1, 365)
	if err != nil {
		return nil, err
	}
	// An idle timeout longer than the absolute cap would never apply, which is
	// almost certainly not what whoever set it meant.
	if idleDays > absoluteDays {
		return nil, fmt.Errorf("config: SESSION_IDLE_DAYS (%d) exceeds SESSION_ABSOLUTE_DAYS (%d)", idleDays, absoluteDays)
	}
	productTTL, err := durationEnv("PRODUCT_REFRESH_TTL", 12*time.Hour)
	if err != nil {
		return nil, err
	}
	ownerAge, err := durationEnv("OWNER_MAX_AUTH_AGE", 12*time.Hour)
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
	rlScale, err := intEnv("RATE_LIMIT_SCALE", 1, 1, 1000)
	if err != nil {
		return nil, err
	}
	// Strict allowlist, like NODE_ENV: a typo must fail at boot, not silently fall
	// back to per-process counters and quietly multiply every budget by the
	// replica count.
	rlStore := getenv("RATE_LIMIT_STORE", "memory")
	switch rlStore {
	case "memory", "database":
	default:
		return nil, fmt.Errorf("config: RATE_LIMIT_STORE must be memory or database, got %q", rlStore)
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
	// A minimum above the maximum is a typo, and pgx would accept it and behave
	// unpredictably.
	if dbMinConns > dbMaxConns {
		return nil, fmt.Errorf("config: DB_MIN_CONNS (%d) exceeds DB_MAX_CONNS (%d)", dbMinConns, dbMaxConns)
	}

	docsEnabled, err := boolEnv("DOCS_ENABLED", !isProd)
	if err != nil {
		return nil, err
	}

	verifyKeys, err := parseVerifyKeys(os.Getenv("JWT_VERIFY_KEYS"), os.Getenv("JWT_KEY_ID"))
	if err != nil {
		return nil, err
	}

	google, err := loadGoogle(isProd)
	if err != nil {
		return nil, err
	}
	sso, err := loadSSO(isProd, frontend)
	if err != nil {
		return nil, err
	}
	grpcCfg, err := loadGRPC(isProd, port)
	if err != nil {
		return nil, err
	}

	return &Config{
		Port:           port,
		Host:           getenv("HOST", "127.0.0.1"),
		Env:            env,
		IsProd:         isProd,
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		DBMaxConns:     dbMaxConns,
		DBMinConns:     dbMinConns,
		FrontendURL:    frontend,
		TrustedProxies: splitNonEmpty(os.Getenv("TRUSTED_PROXIES")),
		DocsEnabled:    docsEnabled,
		JWT: JWTConfig{
			PrivateKeyPEM:      normalizePEM(os.Getenv("JWT_PRIVATE_KEY")),
			PublicKeyPEM:       normalizePEM(os.Getenv("JWT_PUBLIC_KEY")),
			KeyID:              os.Getenv("JWT_KEY_ID"),
			Issuer:             issuer,
			VerifyKeys:         verifyKeys,
			AppCentralAudience: getenv("APP_CENTRAL_AUDIENCE", "app-central"),
			AccessTTL:          accessTTL,
		},
		Session: SessionConfig{
			CentralIdleTTL:     time.Duration(idleDays) * 24 * time.Hour,
			CentralAbsoluteTTL: time.Duration(absoluteDays) * 24 * time.Hour,
			ProductRefreshTTL:  productTTL,
			OwnerMaxAuthAge:    ownerAge,
		},
		Cookie: CookieConfig{Secret: os.Getenv("COOKIE_SECRET")},
		Google: google,
		SSO:    sso,
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
			GlobalMax:      rlGlobal,
			AuthorizeMaxIP: rlIP,
			Scale:          rlScale,
			SharedStore:    rlStore == "database",
		},
		GRPC: grpcCfg,
	}, nil
}

// loadGRPC reads the gRPC listener's settings. The certificate and key are read
// when the listener starts, so a bad file fails the boot, not the first call.
func loadGRPC(isProd bool, httpPort int) (GRPCConfig, error) {
	port, err := intEnv("GRPC_PORT", 0, 0, 65535)
	if err != nil {
		return GRPCConfig{}, err
	}
	proxy, err := boolEnv("GRPC_BEHIND_TLS_PROXY", false)
	if err != nil {
		return GRPCConfig{}, err
	}
	g := GRPCConfig{
		Port: port, TLSCertFile: os.Getenv("GRPC_TLS_CERT"), TLSKeyFile: os.Getenv("GRPC_TLS_KEY"), BehindTLSProxy: proxy,
	}
	switch {
	case (g.TLSCertFile == "") != (g.TLSKeyFile == ""):
		return GRPCConfig{}, errors.New("config: GRPC_TLS_CERT and GRPC_TLS_KEY are set together or not at all")
	case g.TLS() && proxy:
		return GRPCConfig{}, errors.New("config: GRPC_BEHIND_TLS_PROXY says a proxy terminates TLS; GRPC_TLS_CERT and GRPC_TLS_KEY must then be unset")
	case port != 0 && port == httpPort:
		return GRPCConfig{}, fmt.Errorf("config: GRPC_PORT (%d) is also PORT", port)
	case port != 0 && isProd && !g.TLS() && !proxy:
		return GRPCConfig{}, errors.New("config: gRPC in production needs GRPC_TLS_CERT and GRPC_TLS_KEY, or GRPC_BEHIND_TLS_PROXY=true: client secrets may never cross the network in the clear")
	}
	return g, nil
}

// originURL validates a URL that names an origin every token and link is built
// from. It must be absolute http(s) with a host and nothing after the path, and
// must not end in "/": the issuer is compared byte for byte by every token
// verifier, so "https://a/" and "https://a" are different issuers. Production
// requires https, because tokens and session cookies travel to it.
func originURL(key, raw string, isProd bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("config: %s must be an absolute http(s) URL, got %q", key, raw)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("config: %s must not carry a query, fragment or credentials", key)
	}
	if strings.HasSuffix(raw, "/") {
		return "", fmt.Errorf("config: %s must not end in \"/\", got %q", key, raw)
	}
	if isProd && u.Scheme != "https" {
		return "", fmt.Errorf("config: %s must use https in production, got %q", key, raw)
	}
	return raw, nil
}

// loadGoogle reads the Google client. All three settings or none: a partial set
// is a mistake that would otherwise surface as a sign-in button that fails.
func loadGoogle(isProd bool) (GoogleConfig, error) {
	g := GoogleConfig{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURI:  os.Getenv("GOOGLE_REDIRECT_URI"),
	}
	set := 0
	for _, v := range []string{g.ClientID, g.ClientSecret, g.RedirectURI} {
		if v != "" {
			set++
		}
	}
	switch set {
	case 0:
		return g, nil
	case 3:
		u, err := url.Parse(g.RedirectURI)
		if err != nil || u.Host == "" || (isProd && u.Scheme != "https") {
			return GoogleConfig{}, fmt.Errorf("config: GOOGLE_REDIRECT_URI must be an absolute %s URL, got %q",
				map[bool]string{true: "https", false: "http(s)"}[isProd], g.RedirectURI)
		}
		g.Enabled = true
		return g, nil
	default:
		return GoogleConfig{}, errors.New("config: set all of GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and " +
			"GOOGLE_REDIRECT_URI to offer Google sign-in, or none of them")
	}
}

// loadSSO reads the key that seals SSO client secrets. It must decode to exactly
// 32 bytes (AES-256). It is required in production, where the Owner must be able
// to register a connection at any time.
func loadSSO(isProd bool, frontend string) (SSOConfig, error) {
	s := SSOConfig{
		SecretKeyID: getenv("SSO_SECRET_KEY_ID", "k1"),
		RedirectURI: getenv("SSO_REDIRECT_URI", frontend+"/auth/sso/callback"),
	}
	if raw := os.Getenv("SSO_SECRET_KEY"); raw != "" {
		key, err := decodeKey(raw)
		if err != nil || len(key) != 32 {
			return SSOConfig{}, errors.New("config: SSO_SECRET_KEY must be 32 random bytes, base64-encoded " +
				"(for example: openssl rand -base64 32)")
		}
		s.SecretKey = key
	} else if isProd {
		return SSOConfig{}, errors.New("config: SSO_SECRET_KEY is required in production")
	}
	if u, err := url.Parse(s.RedirectURI); err != nil || u.Host == "" || (isProd && u.Scheme != "https") {
		return SSOConfig{}, fmt.Errorf("config: SSO_REDIRECT_URI must be an absolute URL, got %q", s.RedirectURI)
	}
	return s, nil
}

func decodeKey(raw string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(raw); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

// parseVerifyKeys reads JWT_VERIFY_KEYS: entries separated by ";", each
// "kid=PEM" (a PEM may use literal \n). A verify-only key under the signing
// key's own kid would make that kid ambiguous, so it is refused.
func parseVerifyKeys(raw, signingKid string) ([]VerifyKey, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []VerifyKey
	seen := map[string]bool{signingKid: true}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		kid, pem, ok := strings.Cut(entry, "=")
		kid = strings.TrimSpace(kid)
		if !ok || kid == "" || strings.TrimSpace(pem) == "" {
			return nil, errors.New("config: JWT_VERIFY_KEYS entries must be kid=PEM, separated by ';'")
		}
		if seen[kid] {
			return nil, fmt.Errorf("config: JWT_VERIFY_KEYS repeats kid %q (or reuses the signing key's)", kid)
		}
		seen[kid] = true
		out = append(out, VerifyKey{KeyID: kid, PublicKeyPEM: normalizePEM(strings.TrimSpace(pem))})
	}
	return out, nil
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

// durationEnv parses a positive duration. ParseDuration happily accepts "-5m"
// and "0s"; either would mint tokens or sessions that are already expired.
func durationEnv(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("config: %s must be positive, got %s", key, d)
	}
	return d, nil
}

// boolEnv parses a boolean the same way intEnv parses a number: unset falls back
// to def, but a set-and-unparseable value is a hard error. Silently treating
// DOCS_ENABLED=ture as false would leave an operator certain they had turned
// something on when they had not.
func boolEnv(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("config: %s must be a boolean, got %q", key, v)
	}
	return b, nil
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

// LoadDatabase reads only what a provisioning command needs: the database to
// connect to. It is for cmd/bootstrap, which runs out of band as the schema
// owner and has no use for signing keys or cookies.
func LoadDatabase() (string, error) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return "", errors.New("config: missing required environment variable DATABASE_URL")
	}
	return url, nil
}
