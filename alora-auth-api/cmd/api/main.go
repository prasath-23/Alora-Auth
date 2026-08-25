// Command api is the Alora Auth server entrypoint: it loads and validates
// configuration, initialises the signing keys, opens the database, assembles the
// middleware chain in a security-significant order, and serves until signalled.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/alora/auth/internal/admin"
	"github.com/alora/auth/internal/auth"
	"github.com/alora/auth/internal/config"
	"github.com/alora/auth/internal/crypto/jwtkeys"
	"github.com/alora/auth/internal/crypto/password"
	"github.com/alora/auth/internal/health"
	"github.com/alora/auth/internal/invitation"
	"github.com/alora/auth/internal/mailer"
	"github.com/alora/auth/internal/middleware"
	"github.com/alora/auth/internal/oauth"
	"github.com/alora/auth/internal/platform/audit"
	"github.com/alora/auth/internal/platform/database"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/alora/auth/internal/platform/jobs"
	"github.com/alora/auth/internal/platform/logger"
	"github.com/alora/auth/internal/reset"
	"github.com/alora/auth/internal/session"
	"github.com/gin-gonic/gin"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	// 1. Configuration — fail fast before anything else is initialised.
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := logger.New(cfg.IsProd)

	// 2. Signing keys, loaded ONCE. Doing this at boot means a malformed key is a
	//    startup failure rather than a 500 on the first login.
	if err := jwtkeys.Init(cfg.JWT.PrivateKeyPEM, cfg.JWT.PublicKeyPEM, cfg.JWT.KeyID, cfg.JWT.Issuer); err != nil {
		return err
	}
	// Precompute the anti-enumeration dummy hash so the first unknown-user login
	// does not pay the argon2 cost inline (which would be a timing tell).
	password.Warm()

	// 3. Database.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.New(ctx, cfg.DatabaseURL, database.Options{
		MaxConns: int32(cfg.DBMaxConns),
		MinConns: int32(cfg.DBMinConns),
	})
	if err != nil {
		return err
	}
	defer pool.Close()
	q := sqlc.New(pool)

	authRepo := auth.NewRepo(q)
	authSvc := auth.NewService(authRepo, cfg.JWT.AccessTTL, cfg.JWT.APIAudience)
	auditLog := audit.New(audit.NewRepo(q), log)
	mail := mailer.New(cfg.Mail)
	jar := httpx.NewCookieJar(cfg.Cookie.Domain, cfg.IsProd, cfg.Cookie.Secret)
	sessionSvc := session.NewService(pool, q, cfg.JWT.RefreshTTL)
	oauthH := oauth.NewHandler(oauth.NewService(q), authSvc, sessionSvc, jar)
	inviteH := invitation.NewHandler(invitation.NewService(pool, q, cfg.FrontendURL), mail, auditLog, q)
	resetH := reset.NewHandler(reset.NewService(pool, q, cfg.FrontendURL), mail, auditLog)
	adminH := admin.New(pool, q, auditLog)
	googleH := oauth.NewGoogleHandler(oauth.NewService(q), oauth.GoogleConfig{
		ClientID: cfg.Google.ClientID, ClientSecret: cfg.Google.ClientSecret,
		RedirectURI: cfg.Google.RedirectURI, FrontendURL: cfg.FrontendURL,
	}, jar)

	r, err := newRouter(cfg, log, q, authRepo, oauthH, inviteH, resetH, adminH, googleH)
	if err != nil {
		return err
	}

	// 7. Serve with graceful shutdown.
	srv := &http.Server{
		Addr:              net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second, // slowloris guard
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Sweeps start only once the process is committed to serving, so a failed
	// boot never leaves background writers running against the database.
	jobs.New(q, log).Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr, "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	// Drain in-flight requests before closing the pool, so no handler loses its
	// connection mid-transaction.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// newRouter assembles the engine and routes. Extracted from run() so integration
// tests can exercise the REAL middleware chain and routing table rather than a
// hand-rolled approximation that could drift from production.
func newRouter(cfg *config.Config, log *slog.Logger, q *sqlc.Queries, authRepo *auth.Repo, oauthH *oauth.Handler, inviteH *invitation.Handler, resetH *reset.Handler, adminH *admin.Handler, googleH *oauth.GoogleHandler) (*gin.Engine, error) {
	// 4. HTTP engine. gin.New (not Default) so no unvetted middleware is present.
	if cfg.IsProd {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.RedirectTrailingSlash = false // /admin/users/ must not 301 to /admin/users
	// Gin silently returns 404 for a known path with the wrong verb unless this is
	// enabled, so NoMethod would never fire and clients could not distinguish
	// "route does not exist" from "wrong method".
	r.HandleMethodNotAllowed = true

	// Trusted proxies must be an explicit allowlist. Gin's default trusts every
	// proxy header, which would let any client spoof X-Forwarded-For and bypass
	// per-IP rate limiting. nil = trust none.
	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		return nil, err
	}

	// 5. Middleware chain — ORDER IS SEMANTIC.
	r.Use(httpx.RequestID())                 // first: everything downstream logs it
	r.Use(httpx.WithLogger(log))             //
	r.Use(gin.Recovery())                    // a panic must become a 500, not a dropped conn
	r.Use(httpx.ErrorHandler())              // renders errors recorded by later handlers
	r.Use(httpx.SecurityHeaders(cfg.IsProd)) // headers on EVERY response, including errors
	r.Use(httpx.NewCORS(authRepo, cfg.IsProd).Middleware())
	r.Use(httpx.BodyLimit(65536)) // before any body is read

	globalLimiter := httpx.NewRateLimiter(cfg.RateLimit.GlobalMax, time.Minute)
	r.Use(globalLimiter.Limit(nil))

	r.NoRoute(httpx.NotFound())
	r.NoMethod(httpx.MethodNotAllowed())

	// 6. Routes.
	h := health.New(q)
	r.GET("/health", h.Live)
	r.GET("/health/ready", h.Ready)
	r.GET("/health/pressure", h.Pressure)
	r.GET("/auth/jwks", auth.JWKS)

	// Login + session routes. Each carries a TIGHTER limiter than the global one:
	// these are the endpoints an attacker actually targets.
	//
	// /auth/authorize is keyed by ip|email so that flooding one victim's address
	// cannot exhaust every other user's budget from the same NAT egress.
	authorizeLimiter := httpx.NewRateLimiter(cfg.RateLimit.AuthorizeMaxIP, time.Minute)
	tokenLimiter := httpx.NewRateLimiter(20, time.Minute)
	refreshLimiter := httpx.NewRateLimiter(30, time.Minute)

	r.POST("/auth/authorize", authorizeLimiter.Limit(emailKey), oauthH.Authorize)
	r.POST("/auth/token", tokenLimiter.Limit(nil), oauthH.Token)
	r.POST("/auth/refresh", refreshLimiter.Limit(nil), oauthH.Refresh)
	r.POST("/auth/logout", refreshLimiter.Limit(nil), oauthH.Logout)

	// Direct admin-portal login. Same tight ip|email keying as /auth/authorize:
	// both accept a password, so both are credential-stuffing targets.
	sessionLimiter := httpx.NewRateLimiter(10, time.Minute)
	oauthH2Limiter := httpx.NewRateLimiter(30, time.Minute)
	r.POST("/auth/session", sessionLimiter.Limit(emailKey), oauthH.SessionLogin)

	// Federated login. Both legs are browser navigations, so failures redirect to
	// the frontend rather than returning a JSON error.
	r.GET("/auth/google", oauthH2Limiter.Limit(nil), googleH.Start)
	r.GET("/auth/google/callback", oauthH2Limiter.Limit(nil), googleH.Callback)

	// Public token-redemption routes. Limited per 15 minutes because each one
	// accepts a secret token: a loose limit here is an offline-guessing budget.
	inviteLimiter := httpx.NewRateLimiter(10, 15*time.Minute)
	lookupLimiter := httpx.NewRateLimiter(20, 15*time.Minute)
	r.GET("/auth/accept-invitation/lookup", lookupLimiter.Limit(nil), inviteH.Lookup)
	r.POST("/auth/accept-invitation", inviteLimiter.Limit(nil), inviteH.Accept)
	r.POST("/auth/reset-password", inviteLimiter.Limit(nil), resetH.Consume)
	r.POST("/auth/accept-invitation/google", inviteLimiter.Limit(nil), inviteH.AcceptGoogle)

	// Authenticated admin surface. authenticate → requireFresh runs for every
	// route in this group; per-route guards are added by each feature.
	adminGrp := r.Group("/admin")
	adminGrp.Use(middleware.Authenticate(cfg.JWT.APIAudience))
	adminGrp.Use(middleware.RequireFresh(authRepo))
	// Invitations: admin-only, tenant-scoped inside each handler.
	adminGrp.POST("/invitations", middleware.RequireAdmin(), inviteH.Create)
	adminGrp.GET("/invitations", middleware.RequireAdmin(), inviteH.List)
	adminGrp.DELETE("/invitations/:id", middleware.RequireAdmin(), inviteH.Revoke)

	// Issuing a reset is a takeover primitive, so it needs its own feature grant
	// rather than blanket admin.
	adminGrp.POST("/users/:id/password-reset",
		middleware.RequireFeature(authRepo, "passwords:reset"), resetH.Issue)

	adminGrp.GET("/me/features", middleware.RequireAdmin(), adminH.MyFeatures)
	// Only requireFresh (inherited) guards this: any authenticated user may
	// change their OWN password, and the current password is re-verified inside.
	adminGrp.POST("/me/change-password", adminH.ChangePassword)

	// Users. Read and write are separate feature grants so a support role can be
	// given visibility without the ability to change anything.
	adminGrp.GET("/users", middleware.RequireFeature(authRepo, "users:view"), adminH.ListUsers)
	adminGrp.GET("/users/:id", middleware.RequireFeature(authRepo, "users:view"), adminH.GetUser)
	adminGrp.PATCH("/users/:id", middleware.RequireFeature(authRepo, "users:edit"), adminH.UpdateUser)

	// Permissions are role changes, so they require full admin rather than a
	// delegated feature key.
	adminGrp.GET("/users/:id/permissions", middleware.RequireAdmin(), adminH.ListPermissions)
	adminGrp.PUT("/users/:id/permissions/:productId", middleware.RequireAdmin(), adminH.GrantPermission)
	adminGrp.DELETE("/users/:id/permissions/:productId", middleware.RequireAdmin(), adminH.RevokePermission)

	adminGrp.GET("/sessions", middleware.RequireFeature(authRepo, "sessions:view"), adminH.ListSessions)
	adminGrp.DELETE("/sessions/:id", middleware.RequireFeature(authRepo, "sessions:revoke"), adminH.RevokeSession)

	adminGrp.GET("/products", middleware.RequireFeature(authRepo, "products:view"), adminH.ListProducts)
	adminGrp.GET("/client", middleware.RequireFeature(authRepo, "client:view"), adminH.GetClient)
	adminGrp.PATCH("/client", middleware.RequireFeature(authRepo, "client:edit"), adminH.UpdateClient)

	adminGrp.GET("/groups", middleware.RequireFeature(authRepo, "groups:view"), adminH.ListGroups)
	adminGrp.GET("/groups/:id", middleware.RequireFeature(authRepo, "groups:view"), adminH.GetGroup)
	adminGrp.POST("/groups", middleware.RequireFeature(authRepo, "groups:manage"), adminH.CreateGroup)
	adminGrp.PATCH("/groups/:id", middleware.RequireFeature(authRepo, "groups:manage"), adminH.UpdateGroup)
	adminGrp.DELETE("/groups/:id", middleware.RequireFeature(authRepo, "groups:manage"), adminH.DeleteGroup)
	adminGrp.POST("/groups/:id/members", middleware.RequireFeature(authRepo, "groups:manage"), adminH.AddMember)
	adminGrp.DELETE("/groups/:id/members/:userId", middleware.RequireFeature(authRepo, "groups:manage"), adminH.RemoveMember)

	return r, nil
}

// emailKey extends the rate-limit key with the submitted email, WITHOUT consuming
// the body: it peeks at a bounded copy and restores the reader so the handler
// still sees a complete request.
func emailKey(c *gin.Context) string {
	const peek = 4096
	if c.Request.Body == nil {
		return ""
	}
	buf, err := io.ReadAll(io.LimitReader(c.Request.Body, peek))
	if err != nil {
		return ""
	}
	rest, _ := io.ReadAll(c.Request.Body)
	c.Request.Body = io.NopCloser(bytes.NewReader(append(buf, rest...)))

	var probe struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(buf, &probe) != nil {
		return ""
	}
	return httpx.NormalizeEmail(probe.Email)
}
