package main

import (
	"log/slog"
	"time"

	"github.com/alora/auth/internal/config"
	apiclientcontroller "github.com/alora/auth/internal/core/apiclient/controller"
	apiclientservice "github.com/alora/auth/internal/core/apiclient/service"
	auditservice "github.com/alora/auth/internal/core/audit/service"
	authcontroller "github.com/alora/auth/internal/core/auth/controller"
	authservice "github.com/alora/auth/internal/core/auth/service"
	groupcontroller "github.com/alora/auth/internal/core/group/controller"
	groupservice "github.com/alora/auth/internal/core/group/service"
	healthcontroller "github.com/alora/auth/internal/core/health/controller"
	healthservice "github.com/alora/auth/internal/core/health/service"
	invitationcontroller "github.com/alora/auth/internal/core/invitation/controller"
	invitationservice "github.com/alora/auth/internal/core/invitation/service"
	logincontroller "github.com/alora/auth/internal/core/login/controller"
	loginservice "github.com/alora/auth/internal/core/login/service"
	oauthcontroller "github.com/alora/auth/internal/core/oauth/controller"
	oauthservice "github.com/alora/auth/internal/core/oauth/service"
	ownercontroller "github.com/alora/auth/internal/core/owner/controller"
	ownerservice "github.com/alora/auth/internal/core/owner/service"
	policycontroller "github.com/alora/auth/internal/core/policy/controller"
	policyservice "github.com/alora/auth/internal/core/policy/service"
	resetcontroller "github.com/alora/auth/internal/core/reset/controller"
	resetservice "github.com/alora/auth/internal/core/reset/service"
	sessioncontroller "github.com/alora/auth/internal/core/session/controller"
	sessionservice "github.com/alora/auth/internal/core/session/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/secretbox"
	ssocontroller "github.com/alora/auth/internal/core/sso/controller"
	ssoservice "github.com/alora/auth/internal/core/sso/service"
	tenantcontroller "github.com/alora/auth/internal/core/tenant/controller"
	tenantservice "github.com/alora/auth/internal/core/tenant/service"
	usercontroller "github.com/alora/auth/internal/core/user/controller"
	userservice "github.com/alora/auth/internal/core/user/service"
	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/infrastructure"
	"github.com/alora/auth/internal/middlewares"
)

// modules is every feature's HTTP surface, plus what the middleware chain needs,
// assembled once by newModules.
//
// Several controllers appear twice. The same controller serves a company's own
// Admins on /api/admin — acting on their own company — and the Owner console on
// /api/owner/companies/:cid — acting on the company named in the path — built
// once with each scope resolver. Which company a request may touch is decided by
// the route it arrived on, never inside a handler.
type modules struct {
	authSvc   authservice.AuthService     // caller loading and feature checks
	pressure  middlewares.PressureMonitor // the sampled memory check that sheds load
	wellKnown *authcontroller.WellKnownController
	health    *healthcontroller.HealthController
	login     *logincontroller.LoginController
	oauth     *oauthcontroller.OAuthController
	tokenGRPC *oauthcontroller.TokenGRPC // the token endpoint's gRPC door (TokenService)
	// The token endpoint's budgets, shared by its HTTP and gRPC doors: per client
	// (keyed address|client id), and per address for failed authentications.
	tokenClients  *middlewares.RateLimiter
	tokenFailures *middlewares.RateLimiter
	// rlStore is the shared rate-limit counter store when RATE_LIMIT_STORE is
	// database, else nil (each limiter keeps its own in-process counters). main.go
	// reads it to back the password and password-change budgets the same way.
	rlStore middlewares.Store
	google  *infrastructure.Google // the one login uses, for test stubs
	oidc    *infrastructure.OIDC
	me      *usercontroller.MeController
	// A group manager's own door: the groups they run, in their own company.
	managedGroups *groupcontroller.ManagedGroupController

	// A company's Admins, on their own company.
	users       *usercontroller.UserController
	sessions    *sessioncontroller.SessionController
	invitations *invitationcontroller.InvitationController // also the public redemption routes
	resets      *resetcontroller.ResetController           // also the public redemption route
	groups      *groupcontroller.GroupController
	members     *groupcontroller.MemberController
	managers    *groupcontroller.ManagerController
	client      *tenantcontroller.ClientController
	products    *tenantcontroller.ProductController
	apiClients  *apiclientcontroller.APIClientController

	// The Owner console, on the company in the path.
	owner            *ownercontroller.OwnerController
	ownerUsers       *usercontroller.UserController
	ownerGrants      *usercontroller.PermissionController
	ownerInvitations *invitationcontroller.InvitationController
	ownerResets      *resetcontroller.ResetController
	ownerGroups      *groupcontroller.GroupController
	ownerMembers     *groupcontroller.MemberController
	ownerManagers    *groupcontroller.ManagerController
	ownerPolicies    *policycontroller.PolicyController
	ownerSSO         *ssocontroller.SSOController
	ownerAPIClients  *apiclientcontroller.APIClientController // also every company's, at /api/owner/api-clients
}

// newModules is the ONE place the application is wired. run() and the
// integration tests both call it, so a test cannot exercise a different object
// graph from the one production serves. It has no side effects: jobs, gin's
// mode and the signing keys are the caller's business.
func newModules(cfg *config.Config, log *slog.Logger, db *contexts.DbContext) (*modules, error) {
	return newModulesWith(cfg, log, db, infrastructure.NewMailer(cfg.Mail))
}

// rateLimiter builds a limiter backed by the shared store when one is configured,
// or by its own in-process counters otherwise. name namespaces the keys so
// limiters sharing one store keep separate budgets.
func rateLimiter(store middlewares.Store, name string, max int, per time.Duration) *middlewares.RateLimiter {
	if store != nil {
		return middlewares.NewSharedRateLimiter(store, name, max, per)
	}
	return middlewares.NewRateLimiter(max, per)
}

// mailer is what the invitation and reset services send through.
// *infrastructure.Mailer implements it; tests substitute a fake.
type mailer interface {
	invitationservice.Mailer
	resetservice.Mailer
}

// newModulesWith is newModules with the mailer supplied by the caller.
func newModulesWith(cfg *config.Config, log *slog.Logger, db *contexts.DbContext, mail mailer) (*modules, error) {
	box, err := secretbox.New(cfg.SSO.SecretKey, cfg.SSO.SecretKeyID)
	if err != nil {
		return nil, err
	}
	oidc := infrastructure.NewOIDC(infrastructure.OIDCOptions{Restricted: cfg.IsProd})
	google := infrastructure.NewGoogle(oidc, cfg.Google.ClientID, cfg.Google.ClientSecret, cfg.Google.RedirectURI)
	jar := shared.NewCookieJar(cfg.IsProd, cfg.Cookie.Secret)

	auditSvc := auditservice.NewAuditService(db, log)
	policySvc := policyservice.NewPolicyService(db, auditSvc)
	authSvc := authservice.NewAuthService(db, cfg.JWT.AccessTTL, cfg.JWT.AppCentralAudience)
	sessionSvc := sessionservice.NewSessionService(db, auditSvc, policySvc, sessionservice.Lifetimes{
		CentralIdle:     cfg.Session.CentralIdleTTL,
		CentralAbsolute: cfg.Session.CentralAbsoluteTTL,
		ProductRefresh:  cfg.Session.ProductRefreshTTL,
	})
	healthSvc := healthservice.NewHealthService(db)
	loginSvc := loginservice.NewLoginService(db, authSvc, sessionSvc, policySvc, google, oidc, box,
		loginservice.Config{SSORedirectURI: cfg.SSO.RedirectURI})
	oauthSvc := oauthservice.NewOAuthService(db, authSvc, sessionSvc)
	userSvc := userservice.NewUserService(db, auditSvc, policySvc)
	permissionSvc := userservice.NewPermissionService(db, auditSvc)
	groupSvc := groupservice.NewGroupService(db, auditSvc)
	memberSvc := groupservice.NewMemberService(db, auditSvc)
	managerSvc := groupservice.NewManagerService(db, auditSvc, groupSvc)
	invitationSvc := invitationservice.NewInvitationService(db, mail, auditSvc, log, cfg.FrontendURL, cfg.Google.Enabled)
	resetSvc := resetservice.NewResetService(db, mail, auditSvc, log, cfg.FrontendURL, cfg.IsProd)
	ssoSvc := ssoservice.NewSSOService(db, auditSvc, box, oidc, cfg.IsProd)
	ownerSvc := ownerservice.NewOwnerService(db, auditSvc, cfg.IsProd)
	apiClientSvc := apiclientservice.NewAPIClientService(db, auditSvc)

	owner := ownercontroller.NewOwnerController(ownerSvc)
	tenant := shared.ScopeResolver(middlewares.TenantScope)
	company := shared.ScopeResolver(owner.CompanyScope)

	// A shared store makes the brute-force budgets span every API instance; nil
	// keeps them per-process (the default).
	var rlStore middlewares.Store
	if cfg.RateLimit.SharedStore {
		rlStore = infrastructure.NewRateLimitStore(db, log)
	}

	return &modules{
		authSvc:   authSvc,
		pressure:  healthSvc,
		wellKnown: authcontroller.NewWellKnownController(authSvc),
		health:    healthcontroller.NewHealthController(healthSvc),
		login:     logincontroller.NewLoginController(loginSvc, jar, cfg.FrontendURL),
		oauth:     oauthcontroller.NewOAuthController(oauthSvc, jar, cfg.JWT.Issuer, cfg.FrontendURL),
		tokenGRPC: oauthcontroller.NewTokenGRPC(oauthSvc, log),
		// Sized for one product backend (or application) calling for all its users:
		// see newRouter. RATE_LIMIT_SCALE multiplies them like every other budget.
		tokenClients:  rateLimiter(rlStore, "token-clients", 600*cfg.RateLimit.Scale, time.Minute),
		tokenFailures: rateLimiter(rlStore, "token-failures", 20*cfg.RateLimit.Scale, 15*time.Minute),
		rlStore:       rlStore,
		google:        google,
		oidc:          oidc,
		me:            usercontroller.NewMeController(userservice.NewMeService(db, auditSvc, cfg.JWT.Issuer)),
		managedGroups: groupcontroller.NewManagedGroupController(managerSvc),

		users:       usercontroller.NewUserController(userSvc, tenant),
		sessions:    sessioncontroller.NewSessionController(sessionSvc, tenant),
		invitations: invitationcontroller.NewInvitationController(invitationSvc, tenant),
		resets:      resetcontroller.NewResetController(resetSvc, tenant),
		groups:      groupcontroller.NewGroupController(groupSvc, tenant),
		members:     groupcontroller.NewMemberController(memberSvc, tenant),
		managers:    groupcontroller.NewManagerController(managerSvc, tenant),
		client:      tenantcontroller.NewClientController(tenantservice.NewClientService(db, auditSvc), tenant),
		products:    tenantcontroller.NewProductController(tenantservice.NewProductService(db), tenant),
		apiClients:  apiclientcontroller.NewAPIClientController(apiClientSvc, tenant),

		owner:            owner,
		ownerUsers:       usercontroller.NewUserController(userSvc, company),
		ownerGrants:      usercontroller.NewPermissionController(permissionSvc, company),
		ownerInvitations: invitationcontroller.NewInvitationController(invitationSvc, company),
		ownerResets:      resetcontroller.NewResetController(resetSvc, company),
		ownerGroups:      groupcontroller.NewGroupController(groupSvc, company),
		ownerMembers:     groupcontroller.NewMemberController(memberSvc, company),
		ownerManagers:    groupcontroller.NewManagerController(managerSvc, company),
		ownerPolicies:    policycontroller.NewPolicyController(policySvc, company),
		ownerSSO:         ssocontroller.NewSSOController(ssoSvc, company),
		ownerAPIClients:  apiclientcontroller.NewAPIClientController(apiClientSvc, company),
	}, nil
}
