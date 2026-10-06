// Command api is the App Central server entrypoint: it loads and validates
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

	"github.com/alora/auth/internal/config"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/jwtkeys"
	"github.com/alora/auth/internal/core/shared/crypto/password"
	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/infrastructure"
	"github.com/alora/auth/internal/middlewares"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
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
	log := shared.NewLogger(cfg.IsProd)

	// 2. Signing keys, loaded ONCE. Doing this at boot means a malformed key is a
	//    startup failure rather than a 500 on the first login.
	if err := initKeys(cfg); err != nil {
		return err
	}
	// Precompute the anti-enumeration dummy hash so the first unknown-user login
	// does not pay the argon2 cost inline (which would be a timing tell).
	password.Warm()

	// 3. Database.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := contexts.Connect(ctx, cfg.DatabaseURL, contexts.Options{
		MaxConns: int32(cfg.DBMaxConns),
		MinConns: int32(cfg.DBMinConns),
	})
	if err != nil {
		return err
	}
	defer db.Close()

	m, err := newModules(cfg, log, db)
	if err != nil {
		return err
	}
	r, err := newRouter(cfg, log, m)
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

	// Bind first. A port that is already taken then fails the boot here, before
	// anything has started writing to the database.
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	// And the gRPC listener, when there is one: TokenService, for applications.
	var gsrv *grpc.Server
	var gln net.Listener
	if cfg.GRPC.Enabled() {
		if gsrv, err = newGRPCServer(cfg, log, m); err != nil {
			return err
		}
		if gln, err = net.Listen("tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.GRPC.Port))); err != nil {
			return err
		}
	}

	// Sweeps start only once the listener is bound, so a failed boot never leaves
	// background writers running against the database.
	infrastructure.NewJobRunner(db, log).Start(ctx)

	errCh := make(chan error, 2)
	go func() {
		log.Info("listening", "addr", srv.Addr, "env", cfg.Env, "issuer", cfg.JWT.Issuer)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	if gsrv != nil {
		go func() {
			log.Info("listening for gRPC", "addr", gln.Addr().String(), "tls", cfg.GRPC.TLS(),
				"behindTLSProxy", cfg.GRPC.BehindTLSProxy)
			if err := gsrv.Serve(gln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				errCh <- err
			}
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	// Drain in-flight requests on both doors before closing the pool, so no
	// handler loses its connection mid-transaction — within one 15-second budget,
	// after which gRPC calls still running are cut off.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if gsrv != nil {
		stopped := make(chan struct{})
		go func() {
			gsrv.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-shutdownCtx.Done():
			gsrv.Stop()
		}
	}
	return srv.Shutdown(shutdownCtx)
}

// initKeys loads the signing key and every verify-only key being retired.
func initKeys(cfg *config.Config) error {
	if err := jwtkeys.Init(cfg.JWT.PrivateKeyPEM, cfg.JWT.PublicKeyPEM, cfg.JWT.KeyID, cfg.JWT.Issuer); err != nil {
		return err
	}
	for _, k := range cfg.JWT.VerifyKeys {
		if err := jwtkeys.AddVerifyKey(k.KeyID, k.PublicKeyPEM); err != nil {
			return err
		}
	}
	return nil
}

// newRouter assembles the engine and routes. Extracted from run() so integration
// tests can exercise the REAL middleware chain and routing table rather than a
// hand-rolled approximation that could drift from production.
func newRouter(cfg *config.Config, log *slog.Logger, m *modules) (*gin.Engine, error) {
	// 4. HTTP engine. gin.New (not Default) so no unvetted middleware is present.
	if cfg.IsProd {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.RedirectTrailingSlash = false // /api/admin/users/ must not 301 to /api/admin/users
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

	// The OAuth endpoints a product's BACKEND calls. One backend calls them for
	// all its users from one address, so they are kept out of the per-address
	// global budget and given one keyed by the client instead.
	serverToServer := []string{"/oauth/token", "/oauth/revoke", "/oauth/introspect"}

	// 5. Middleware chain — ORDER IS SEMANTIC.
	r.Use(middlewares.RequestID())                 // first: everything downstream logs it
	r.Use(middlewares.WithLogger(log))             //
	r.Use(middlewares.Recovery())                  // a panic becomes the 500 envelope, not a dropped conn
	r.Use(middlewares.ErrorHandler())              // renders errors recorded by later handlers
	r.Use(middlewares.SecurityHeaders(cfg.IsProd)) // headers on EVERY response, including errors
	r.Use(middlewares.WellKnownCORS())             // CORS exists for /.well-known/* alone
	r.Use(middlewares.BodyLimit(65536))            // before any body is read

	globalLimiter := middlewares.NewRateLimiter(cfg.RateLimit.GlobalMax, time.Minute)
	r.Use(globalLimiter.LimitExcept(nil, serverToServer...))
	// Before any handler reads a path or query parameter: text the database
	// cannot store (a NUL, bytes that are not UTF-8) is refused with a 400.
	r.Use(middlewares.StorableText())
	// Last before any route: while memory is over its ceiling, every request is
	// shed with a 503 before authentication or a handler spends anything on it.
	r.Use(middlewares.UnderPressure(m.pressure))

	// The per-route budgets below are sized for one person at one address;
	// RATE_LIMIT_SCALE multiplies them all at once (config.RateLimitConfig.Scale).
	scaled := func(max int, window time.Duration) *middlewares.RateLimiter {
		return middlewares.NewRateLimiter(max*cfg.RateLimit.Scale, window)
	}

	r.NoRoute(middlewares.NotFound())
	r.NoMethod(middlewares.MethodNotAllowed())

	// 6. Routes.
	r.GET("/health", m.health.Live)
	r.GET("/health/ready", m.health.Ready)
	r.GET("/health/pressure", m.health.Pressure)

	// Standards: public, cacheable, readable from any origin.
	r.GET("/.well-known/openid-configuration", m.wellKnown.Discovery)
	r.GET("/.well-known/jwks.json", m.wellKnown.JWKS)

	// The OpenID Provider. /oauth/authorize is a browser navigation carrying the
	// App Central session cookie; the rest are server to server, authenticated
	// by the product's client secret.
	authorizeLimiter := scaled(60, time.Minute)
	// The token endpoint's budgets are shared with its gRPC door (newGRPCServer):
	// per client, and — since that key is an id the caller picks — failed client
	// authentications per address, so guessing secrets across made-up ids is
	// bounded too, whichever door the guesses come through.
	clientLimiter := m.tokenClients
	failedClientAuth := m.tokenFailures.LimitFailures(func(c *gin.Context) bool {
		return c.Writer.Status() == http.StatusUnauthorized
	})
	r.GET("/oauth/authorize", authorizeLimiter.Limit(nil), m.oauth.Authorize)
	r.POST("/oauth/token", failedClientAuth, clientLimiter.Limit(basicClientID), m.oauth.Token)
	r.POST("/oauth/revoke", failedClientAuth, clientLimiter.Limit(basicClientID), m.oauth.Revoke)
	r.POST("/oauth/introspect", failedClientAuth, clientLimiter.Limit(basicClientID), m.oauth.Introspect)

	// App Central sign-in. Every state-changing request here carries, or is about
	// to receive, the session cookie, so each must come from App Central's own
	// origin (SameOriginOnly) with a JSON body (shared.BindJSON).
	auth := r.Group("/auth", middlewares.SameOriginOnly(cfg.FrontendURL, cfg.JWT.Issuer))
	passwordLimiter := rateLimiter(m.rlStore, "password", cfg.RateLimit.AuthorizeMaxIP, time.Minute)
	chooseLimiter := scaled(20, time.Minute)
	discoverLimiter := scaled(60, time.Minute)
	refreshLimiter := scaled(60, time.Minute)
	federatedLimiter := scaled(30, time.Minute)
	// Keyed by ip|email so that flooding one victim's address cannot exhaust
	// every other user's budget behind the same NAT egress.
	auth.POST("/login/password", passwordLimiter.Limit(emailKey), m.login.Password)
	auth.POST("/login/discover", discoverLimiter.Limit(nil), m.login.Discover)
	auth.GET("/login/choices", chooseLimiter.Limit(nil), m.login.Choices)
	auth.POST("/login/choose", chooseLimiter.Limit(nil), m.login.Choose)
	auth.POST("/central/refresh", refreshLimiter.Limit(nil), m.login.Refresh)
	auth.POST("/central/logout", refreshLimiter.Limit(nil), m.login.Logout)
	// Federated sign-in. Every leg is a browser navigation, so failures redirect
	// to the login page rather than returning a JSON error.
	auth.GET("/google/start", federatedLimiter.Limit(nil), m.login.GoogleStart)
	auth.GET("/google/callback", federatedLimiter.Limit(nil), m.login.GoogleCallback)
	auth.GET("/sso/start", federatedLimiter.Limit(nil), m.login.SSOStart)
	auth.GET("/sso/callback", federatedLimiter.Limit(nil), m.login.SSOCallback)
	// Public token-redemption routes. Limited per 15 minutes because each one
	// accepts a secret token: a loose limit here is an offline-guessing budget.
	inviteLimiter := scaled(10, 15*time.Minute)
	lookupLimiter := scaled(20, 15*time.Minute)
	auth.GET("/accept-invitation/lookup", lookupLimiter.Limit(nil), m.invitations.Lookup)
	auth.POST("/accept-invitation", inviteLimiter.Limit(nil), m.invitations.Accept)
	auth.POST("/accept-invitation/federated", inviteLimiter.Limit(nil), m.invitations.AcceptFederated)
	auth.POST("/reset-password", inviteLimiter.Limit(nil), m.resets.Consume)

	// App Central's API. Only an App Central token is accepted — a product's
	// token names another audience and is refused however valid — and its
	// session is re-checked against the database on every request.
	api := r.Group("/api")
	api.Use(middlewares.Authenticate(cfg.JWT.AppCentralAudience))
	api.Use(middlewares.RequireFresh(m.authSvc))

	api.GET("/me", m.me.Me)
	api.GET("/me/apps", m.me.Apps)
	// Re-verifying the current password is a guess at it, so the account — not
	// the address — gets a budget: a stolen token used from many addresses
	// still gets five tries per fifteen minutes.
	passwordChangeLimiter := rateLimiter(m.rlStore, "password-change", 5*cfg.RateLimit.Scale, 15*time.Minute)
	callerKey := func(c *gin.Context) string { return middlewares.ActorFrom(c).UserID }
	api.POST("/me/change-password", passwordChangeLimiter.LimitBy(callerKey), m.me.ChangePassword)

	// A group manager's door: the groups the caller runs, in their own company.
	// It needs no scope — being a group's manager is not one — and every call
	// asks the database whether the caller manages that group; the writes ask
	// again at the moment of the change. An add answers differently for an
	// unknown address, a member and someone above the caller, so the account
	// gets a budget of writes.
	managerLimiter := scaled(60, 15*time.Minute)
	api.GET("/me/managed-groups", m.managedGroups.List)
	api.GET("/me/managed-groups/:gid", m.managedGroups.Get)
	api.POST("/me/managed-groups/:gid/members", managerLimiter.LimitBy(callerKey), m.managedGroups.AddMember)
	api.DELETE("/me/managed-groups/:gid/members/:uid", managerLimiter.LimitBy(callerKey), m.managedGroups.RemoveMember)

	// A company's administration, always of the caller's own company. Every
	// route names the App Central scope it needs: read to look, edit to change.
	// The scopes come from the caller's groups (the Admins group holds all of
	// them) and their extras, read from the database on this very request.
	// Changing who holds what is itself scoped, and the services apply the two
	// rules on top: nobody gives or takes away a scope they do not hold, and
	// nobody acts on someone with more access than they have.
	need := middlewares.RequireScope
	admin := api.Group("/admin")
	admin.GET("/users", need(shared.ScopeUsersRead), m.users.List)
	admin.GET("/users/:id", need(shared.ScopeUsersRead), m.users.Get)
	admin.PATCH("/users/:id", need(shared.ScopeUsersEdit), m.users.Update)
	admin.PUT("/users/:id/scopes", need(shared.ScopeUsersEdit), m.users.SetScopes)
	admin.POST("/users/:id/password-reset", need(shared.ScopeUsersEdit), m.resets.Issue)
	admin.GET("/invitations", need(shared.ScopeInvitationsRead), m.invitations.List)
	admin.POST("/invitations", need(shared.ScopeInvitationsEdit), m.invitations.Create)
	admin.DELETE("/invitations/:id", need(shared.ScopeInvitationsEdit), m.invitations.Revoke)
	admin.GET("/groups", need(shared.ScopeGroupsRead), m.groups.List)
	admin.GET("/groups/:id", need(shared.ScopeGroupsRead), m.groups.Get)
	admin.POST("/groups", need(shared.ScopeGroupsEdit), m.groups.Create)
	admin.PATCH("/groups/:id", need(shared.ScopeGroupsEdit), m.groups.Update)
	admin.DELETE("/groups/:id", need(shared.ScopeGroupsEdit), m.groups.Delete)
	admin.PUT("/groups/:id/scopes", need(shared.ScopeGroupsEdit), m.groups.SetScopes)
	admin.POST("/groups/:id/members", need(shared.ScopeGroupsEdit), m.members.Add)
	admin.DELETE("/groups/:id/members/:userId", need(shared.ScopeGroupsEdit), m.members.Remove)
	admin.POST("/groups/:id/managers", need(shared.ScopeGroupsEdit), m.managers.Appoint)
	admin.DELETE("/groups/:id/managers/:userId", need(shared.ScopeGroupsEdit), m.managers.Dismiss)
	admin.GET("/sessions", need(shared.ScopeSessionsRead), m.sessions.List)
	admin.DELETE("/sessions/:id", need(shared.ScopeSessionsEdit), m.sessions.Revoke)
	admin.GET("/products", need(shared.ScopeProductsRead), m.products.List)
	admin.GET("/client", need(shared.ScopeCompanyRead), m.client.Get)
	admin.PATCH("/client", need(shared.ScopeCompanyEdit), m.client.Update)
	admin.GET("/api-clients", need(shared.ScopeAPIClientsRead), m.apiClients.List)
	admin.POST("/api-clients", need(shared.ScopeAPIClientsEdit), m.apiClients.Create)
	admin.GET("/api-clients/:id", need(shared.ScopeAPIClientsRead), m.apiClients.Get)
	admin.PATCH("/api-clients/:id", need(shared.ScopeAPIClientsEdit), m.apiClients.Update)
	admin.DELETE("/api-clients/:id", need(shared.ScopeAPIClientsEdit), m.apiClients.Delete)
	admin.PUT("/api-clients/:id/scopes", need(shared.ScopeAPIClientsEdit), m.apiClients.SetScopes)
	admin.PUT("/api-clients/:id/products", need(shared.ScopeAPIClientsEdit), m.apiClients.SetProducts)
	admin.POST("/api-clients/:id/secrets", need(shared.ScopeAPIClientsEdit), m.apiClients.CreateSecret)
	admin.DELETE("/api-clients/:id/secrets/:sid", need(shared.ScopeAPIClientsEdit), m.apiClients.RevokeSecret)

	// The Owner console: every company, with a sign-in no older than
	// OWNER_MAX_AUTH_AGE. A company is named in the path; every write must repeat
	// it in X-Alora-Target-Company (see owner/controller).
	own := api.Group("/owner", middlewares.RequireOwner(cfg.Session.OwnerMaxAuthAge))
	own.GET("/companies", m.owner.ListCompanies)
	own.POST("/companies", m.owner.CreateCompany)
	co := own.Group("/companies/:cid")
	co.GET("", m.owner.GetCompany)
	co.PATCH("", m.owner.UpdateCompany)
	co.PUT("/domain", m.owner.SetDomain)
	co.GET("/subscriptions", m.owner.ListSubscriptions)
	co.PUT("/subscriptions/:pid", m.owner.SetSubscription)
	co.GET("/users", m.ownerUsers.List)
	co.GET("/users/:uid", m.ownerUsers.Get)
	co.PATCH("/users/:uid", m.ownerUsers.Update)
	co.PUT("/users/:uid/scopes", m.ownerUsers.SetScopes)
	co.POST("/users/:uid/password-reset", m.ownerResets.Issue)
	co.PUT("/users/:uid/login-policy", m.ownerPolicies.AssignUser)
	co.PUT("/users/:uid/grants/:pid", m.ownerGrants.Grant)
	co.DELETE("/users/:uid/grants/:pid", m.ownerGrants.Revoke)
	co.GET("/invitations", m.ownerInvitations.List)
	co.POST("/invitations", m.ownerInvitations.Create)
	co.DELETE("/invitations/:iid", m.ownerInvitations.Revoke)
	co.GET("/groups", m.ownerGroups.List)
	co.POST("/groups", m.ownerGroups.Create)
	co.GET("/groups/:gid", m.ownerGroups.Get)
	co.PATCH("/groups/:gid", m.ownerGroups.Update)
	co.DELETE("/groups/:gid", m.ownerGroups.Delete)
	co.PUT("/groups/:gid/scopes", m.ownerGroups.SetScopes)
	co.PUT("/groups/:gid/product-grants", m.ownerGroups.SetProductGrants)
	co.PUT("/groups/:gid/login-policy", m.ownerPolicies.AssignGroup)
	co.POST("/groups/:gid/members", m.ownerMembers.Add)
	co.DELETE("/groups/:gid/members/:uid", m.ownerMembers.Remove)
	co.POST("/groups/:gid/managers", m.ownerManagers.Appoint)
	co.DELETE("/groups/:gid/managers/:uid", m.ownerManagers.Dismiss)
	co.GET("/login-policies", m.ownerPolicies.List)
	co.POST("/login-policies", m.ownerPolicies.Create)
	co.PATCH("/login-policies/:pid", m.ownerPolicies.Update)
	co.DELETE("/login-policies/:pid", m.ownerPolicies.Delete)
	co.PUT("/login-policies/:pid/default", m.ownerPolicies.SetDefault)
	co.GET("/sso-connections", m.ownerSSO.List)
	co.POST("/sso-connections", m.ownerSSO.Create)
	co.PATCH("/sso-connections/:sid", m.ownerSSO.Update)
	co.PUT("/sso-connections/:sid/domains", m.ownerSSO.SetDomains)
	co.POST("/sso-connections/:sid/test", m.ownerSSO.Test)
	co.GET("/api-clients", m.ownerAPIClients.List)
	co.POST("/api-clients", m.ownerAPIClients.Create)
	co.GET("/api-clients/:aid", m.ownerAPIClients.Get)
	co.PATCH("/api-clients/:aid", m.ownerAPIClients.Update)
	co.DELETE("/api-clients/:aid", m.ownerAPIClients.Delete)
	co.PUT("/api-clients/:aid/scopes", m.ownerAPIClients.SetScopes)
	co.PUT("/api-clients/:aid/products", m.ownerAPIClients.SetProducts)
	co.POST("/api-clients/:aid/secrets", m.ownerAPIClients.CreateSecret)
	co.DELETE("/api-clients/:aid/secrets/:sid", m.ownerAPIClients.RevokeSecret)
	own.GET("/api-clients", m.ownerAPIClients.ListAll)
	own.GET("/products", m.owner.ListProducts)
	own.POST("/products", m.owner.CreateProduct)
	own.GET("/products/:pid", m.owner.GetProduct)
	own.PATCH("/products/:pid", m.owner.UpdateProduct)
	own.PUT("/products/:pid/redirect-uris", m.owner.SetRedirectURIs)
	own.PUT("/products/:pid/roles", m.owner.SetRoles)
	own.POST("/products/:pid/client-secret", m.owner.RotateSecret)

	// API documentation, when enabled. Registered last so a docs route can never
	// shadow a real one.
	registerDocs(r, cfg)

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
	return shared.NormalizeEmail(probe.Email)
}

// basicClientID keys the server-to-server limiter by the client id a product
// presents, so each product has its own budget however many users it serves.
// It only reads the header; authentication happens in the handler.
func basicClientID(c *gin.Context) string {
	return middlewares.BasicClientID(c.GetHeader("Authorization"))
}
