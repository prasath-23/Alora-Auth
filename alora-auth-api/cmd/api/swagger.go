package main

import (
	"net/http"

	_ "github.com/alora/auth/docs" // generated OpenAPI document; registers itself
	"github.com/alora/auth/internal/config"
	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// registerDocs mounts the OpenAPI document and Swagger UI at /docs.
//
// Regenerate the document after changing any handler annotation:
//
//	go run github.com/swaggo/swag/cmd/swag@v1.16.6 init \
//	  -g cmd/api/swagger.go -o docs --parseInternal --parseDepth 2
//
// The spec declares no `host`, so Swagger UI resolves requests against whatever
// origin served the page. That is what makes "Try it out" work unchanged behind
// the Vite dev proxy, over an SSH tunnel, or on a deployed hostname.
//
// @title                      App Central API
// @version                    2.0
// @description                App Central: one sign-in for every product of the platform, and the OpenID Provider those products trust.
// @description
// @description                ## Two kinds of token
// @description                People sign in once at App Central — with a password, Google, or their company's SSO, as their company's login policy allows. That opens an App Central session (an HttpOnly cookie) and yields an App Central access token (audience `app-central`), the ONLY token the `/api` routes accept. It describes everything about App Central: `scope` (what the person may do here) and `products` (the keys of the apps they may open). A product never sees it: when a product is launched, its backend runs an ordinary OpenID Connect authorization-code flow with PKCE against `/oauth/authorize` and `/oauth/token`, and receives a token for itself alone (audience `product:<key>`, carrying only its own roles).
// @description
// @description                ## Scopes
// @description                Every `/api/admin` route names the App Central scope it needs: `<feature>:read` to look, `<feature>:edit` to change (edit includes read). The features are users, groups, invitations, sessions, products (read only), company and api-clients; everyone signed in holds `apps:read`, and a platform Owner also holds `owner`. A person's scopes are their groups' plus extras given to them alone, and the Admins group holds every scope. Nobody gives or takes away a scope they do not hold, and nobody acts on someone with more access than they have (403, in those words); the Owner is bound by neither. The token's claims are a snapshot: App Central re-reads the person's access on every request, and a response carries `X-Alora-Token-Stale: 1` when the token no longer describes it — refresh, and read `/api/me` again.
// @description
// @description                ## Group managers
// @description                A group's managers add and remove its members, and nothing else, without `groups:edit` for the whole company. Holders of `groups:edit` appoint them (`POST /api/admin/groups/{id}/managers`) under the same two rules: they must hold every scope the group gives, since a manager can hand the group out, and the person may have no more reach than they have — reach being the scopes someone holds plus those of the groups they manage, which is what the second rule measures everywhere. Nobody appoints themselves; the Admins group never has managers. A manager works through `/api/me/managed-groups`, which needs no scope and opens only on the groups they manage, never on the group's managers themselves.
// @description
// @description                ## Authorizing requests here
// @description                Sign in with `POST /auth/login/password`, copy `access_token` from the response, then press **Authorize** and paste it. Every `/api` route reads the bearer token from the `Authorization` header only — never from a cookie — and re-checks its session against the database on every request.
// @description
// @description                ## Companies
// @description                No `/api/admin` endpoint accepts a company identifier: each is scoped to the caller's own company. Only the Owner console (`/api/owner`) names a company, in the path, and every write there must repeat it in the `X-Alora-Target-Company` header. The company-management routes are documented at their `/api/admin` path; the Owner console serves each of them for any company at the same path under `/api/owner/companies/{cid}` (for example `PUT /api/owner/companies/{cid}/groups/{gid}/scopes`).
// @description
// @description                ## Errors
// @description                Every failure renders as `{"error": "<safe label>", "reqId": "<request id>"}`, except the token, revocation and introspection endpoints, which answer in the RFC 6749 shape `{"error": "<code>", "error_description": "..."}`. Quote `reqId` when reporting a problem.
// @termsOfService             https://alora.io/terms
//
// @contact.name               Alora Platform
// @contact.url                https://alora.io/support
//
// @license.name               Proprietary
//
// @BasePath                   /
// @schemes                    http https
//
// @tag.name                   health
// @tag.description            Liveness, readiness and load-shedding probes. Unauthenticated.
// @tag.name                   standards
// @tag.description            The OpenID Provider metadata and signing keys. Public, and readable from any origin.
// @tag.name                   provider
// @tag.description            The OpenID Provider endpoints products integrate with.
// @tag.name                   sign-in
// @tag.description            App Central sign-in: password, the company chooser, Google, company SSO, and the session.
// @tag.name                   me
// @tag.description            The signed-in person's own account and apps.
// @tag.name                   invitations
// @tag.description            Issuing invitations, and redeeming them without a session.
// @tag.name                   passwords
// @tag.description            Administrator-issued resets and redeeming them.
// @tag.name                   users
// @tag.description            A company's users, for its Admins and delegates.
// @tag.name                   groups
// @tag.description            A company's groups and their members.
// @tag.name                   sessions
// @tag.description            A company's live sign-ins.
// @tag.name                   api-clients
// @tag.description            A company's API clients: applications' identities — a client ID and secret, the products each may get a token for, and where that token may be used (REST, gRPC, MCP).
// @tag.name                   tenant
// @tag.description            A company's own record and its product subscriptions.
// @tag.name                   owner
// @tag.description            The Owner console: every company, product registration, groups, login policies and SSO. The company-scoped user, invitation, group-membership and password-reset operations documented under /api/admin are also served for ANY company at the same path under /api/owner/companies/{cid} — /users (with /scopes and /password-reset), /invitations, /groups (with /scopes, /members and /managers) and /api-clients (with /scopes, /products and /secrets) — with the same bodies and the X-Alora-Target-Company echo on writes.
//
// The security definition MUST stay last in this block: swag consumes every line
// after @securityDefinitions.* until the next one, so anything below it (tags
// included) is silently swallowed rather than parsed.
//
// @securityDefinitions.apikey BearerAuth
// @in                         header
// @name                       Authorization
// @description                An App Central access token from /auth/login/password or /auth/central/refresh. Enter it as: Bearer &lt;token&gt;
func registerDocs(r *gin.Engine, cfg *config.Config) {
	if !cfg.DocsEnabled {
		return
	}
	// Bare /docs is a convenience: with RedirectTrailingSlash disabled nothing
	// else would rescue a caller who omits the filename.
	r.GET("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/docs/index.html")
	})
	r.GET("/docs/*any", docsCSP(), ginSwagger.WrapHandler(swaggerfiles.Handler))
}

// docsCSP relaxes the deny-all Content-Security-Policy for the documentation
// routes ONLY.
//
// SecurityHeaders sets `default-src 'none'` on every response, which is correct
// for a JSON API that renders no HTML and would otherwise leave Swagger UI a
// blank page. This replaces the policy for /docs with the narrowest one the UI
// actually runs under: same-origin assets (all of which ship inside the binary,
// so nothing is fetched from a CDN), the inline script and styles the bundle
// injects, and same-origin XHR so "Try it out" can reach this API.
//
// Everything else stays as SecurityHeaders left it — frame-ancestors and
// X-Frame-Options still forbid framing, and the Cross-Origin-Resource-Policy it
// sets is what satisfies the COEP require-corp header for these assets.
func docsCSP() gin.HandlerFunc {
	const policy = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"font-src 'self' data:; " +
		"connect-src 'self'; " +
		"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

	return func(c *gin.Context) {
		c.Writer.Header().Set("Content-Security-Policy", policy)
		c.Next()
	}
}
