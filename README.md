# Alora App Central

Alora's identity provider for B2B products. People sign in once at **App
Central** — with a password, Google, or their company's SSO — and see the apps
they may use. Opening one gives that product a short-lived token of its own,
with no second login. Company Admins — and the people they give a part of
their access to — manage their people; the platform **Owner** decides, for
every company, how sign-in works and which products users and groups may open.
Applications with no person behind them — a sync job, another backend, an AI
agent — get tokens for products too, with a client ID and secret, over HTTP or
gRPC.

Four projects, one repository. Each builds, runs and tests **independently** —
they are together because a change to a stored procedure and the Go call site
that binds to it, or to a proto and the server that answers it, are one logical
change.

| Project | What it is | Stack |
|---|---|---|
| [`alora-auth-db`](alora-auth-db/) | The database. Owns the schema and every stored procedure. | PostgreSQL 16 |
| [`alora-auth-api`](alora-auth-api/) | The service: App Central's API and the OpenID Provider. Contains no SQL of its own. | Go 1.26, Gin, pgx, sqlc |
| [`alora-auth-ui`](alora-auth-ui/) | App Central itself: sign-in, the launcher, the admin area, the Owner console. Also a sample product backend. | React 18, Vite, Tailwind |
| [`alora-auth-go`](alora-auth-go/) | What Go products and applications build against: the gRPC protos and their generated code, token checks for products, client credentials for applications, and a demo. Never imports App Central. | Go 1.26, gRPC |

---

## Prerequisites

| Tool | Needed for | Check |
|---|---|---|
| Go 1.26+ | the API | `go version` |
| Node 20+ | the UI and the sample product | `node --version` |
| Docker | a local PostgreSQL | `docker info` |
| `psql` (PostgreSQL 16 client) | applying to a real database. Not needed for `./migrate.sh --docker`, which uses the throwaway container's own client | `psql --version` |
| [sqlc](https://sqlc.dev) v1.31.1 | only if you change the database | `sqlc version` |
| [grpcurl](https://github.com/fullstorydev/grpcurl) | only to try the gRPC door by hand | `grpcurl -version` |

Changing a proto needs nothing more: `alora-auth-go/scripts/generate.sh`
installs its own pinned tools.

On Windows, run the shell scripts from **Git Bash**.

---

## Quick start

### 1. Database

```bash
cd alora-auth-db
./migrate.sh --docker          # verifies the whole build in a throwaway container
```

For a database you want to keep (this needs `psql` on PATH):

```bash
export DATABASE_URL="postgres://postgres:secret@localhost:5432/alora"
./migrate.sh              # apply
./migrate.sh --status     # report what is pending, change nothing
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v app_password="'app-secret'" -f Security/roles.sql
```

`roles.sql` creates `alora_app`, the least-privilege role the API connects as.
It can insert audit rows but never change them, and cannot create Owners.

### 2. API

```bash
cd alora-auth-api
cp .env.example .env           # then fill in the values below
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -in private.pem -pubout -out public.pem
go run ./cmd/api
```

In `.env`:

- set `DATABASE_URL` to the **`alora_app`** role;
- put the two PEM files in `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` (newlines may
  be written as `\n`);
- set `COOKIE_SECRET` to at least 32 random bytes;
- set `SSO_SECRET_KEY` (`openssl rand -base64 32`) to allow company SSO;
- optionally set `GRPC_PORT` (e.g. `3002`) to open the gRPC door applications
  get tokens from. It is off when unset; in production it also needs TLS
  (`GRPC_TLS_CERT` and `GRPC_TLS_KEY`) or `GRPC_BEHIND_TLS_PROXY=true`.

For local development `JWT_ISSUER` and `FRONTEND_URL` are both
`http://localhost:5173`, the Vite server that proxies the API. The server refuses
to start if anything required is missing or retired. That is deliberate: a
misconfigured deployment fails at boot, not at the first login.

Once it is up, **http://127.0.0.1:3001/docs** is the API reference: every route,
its shapes and its guard. It is served outside production and withheld in it
(`DOCS_ENABLED` overrides). After changing a handler annotation, regenerate it:

```bash
go run github.com/swaggo/swag/cmd/swag@v1.16.6 init -g cmd/api/swagger.go -o docs --parseInternal --parseDepth 2
```

### 3. The platform Owner

There is no signup and no API that makes an Owner: anyone who could call it
could make themselves Owner of every company. Provision the first one out of
band, **connected as the schema owner** (the app role cannot write Owners):

```bash
cd alora-auth-api
DATABASE_URL="postgres://postgres:secret@localhost:5432/alora" \
  go run ./cmd/bootstrap platform -name "Alora" -email owner@alora.example
```

It prompts for the password without echoing it (at least 12 characters), or reads
`BOOTSTRAP_PASSWORD` when there is no terminal. The Owner then creates companies,
products and groups in the Owner console. To start with some data instead:

```bash
DATABASE_URL=… go run ./cmd/bootstrap demo \
  -company "Acme Corp" -email admin@acme.example \
  -product CRM -product-name "Acme CRM" \
  -base-url http://127.0.0.1:4100/ \
  -initiate-login-uri http://127.0.0.1:4100/login/initiate \
  -redirect-uri http://127.0.0.1:4100/callback \
  -roles Admin,Editor,Viewer
```

That creates a company and its first Admin, and registers a product. The product
comes with those URLs and roles and a client secret, **printed once**. The
company is subscribed, and its Admins group may open the product with the first
role.

### 4. App Central

```bash
cd alora-auth-ui
npm install
npm run dev                    # http://localhost:5173
```

Sign in with the Owner or the demo Admin. Vite proxies `/api`, `/auth`, `/oauth`,
`/.well-known` and `/health` to the API, so the browser sees one origin, exactly
as it will behind a reverse proxy.

### 5. A product (optional)

`alora-auth-ui/sample-product.cjs` is a complete product backend in one
dependency-free file. Run it with the demo product's credentials:

```bash
cd alora-auth-ui
ALORA_ISSUER=http://localhost:5173 ALORA_CLIENT_ID=<client_id> \
ALORA_CLIENT_SECRET=<client_secret> ALORA_PRODUCT_KEY=CRM \
  node sample-product.cjs      # http://127.0.0.1:4100
```

Then open it from the App Central launcher: it signs in with no second login
and shows the claims it verified.

---

## How sign-in works

- **Identifier-first.** The login page asks for the email first. The address's
  domain decides what to offer: password, Google, or the company's SSO. The
  answer is the same for every address at a domain, so it reveals nothing about
  any account.
- **Policies decide, the page only lays out.** The Owner sets login policies per
  company, group and user. They are enforced at the end of every sign-in and at
  every refresh, so a right password on an SSO-only account fails, and
  tightening a policy ends the sessions it no longer allows.
- **One session, many products.** The App Central session is an HttpOnly,
  host-only cookie. Its access token lives in page memory and opens App Central
  alone. Each product gets its own token, audience `product:<key>`, with its roles
  in that product only.
- **Several companies, one address.** The company is chosen after the first
  factor succeeds, never before.

---

## Who may do what

Inside App Central, access is a set of **scopes**: for each feature, one to look
and one to change — `users:read` to see the people, `users:edit` to deactivate
them, reset their passwords or give them extra access, and likewise for groups,
invitations, sessions, the company and API clients (`SPEC.md §2` has the table).
An edit scope includes its read scope.

- A person holds the scopes of their groups, plus **extras** given to them
  alone. The **Admins** group holds every scope; it cannot be renamed,
  re-scoped or deleted, and always keeps one active member.
- Scopes are handed out by people who hold `groups:edit`, `users:edit` or
  `invitations:edit`, under two rules:
  1. **you can only give or take away scopes you hold yourself;**
  2. **you can only manage people who have no more access than you.**
- A group can have **managers**: people who add and remove its members, and
  nothing else, without `groups:edit`. Appoint them on the group's page (you
  need everything the group gives); they find their groups under **Admin →
  Groups you manage**. Nobody appoints themselves, the Admins group has no
  managers, and managers never change their own or each other's membership. For
  rule 2 a manager counts as holding what their groups give, so nobody below
  that can act on them.
- The **Owner** is bound by neither rule, and alone decides which products a
  group or a person may open.
- **Profile → Your access** shows each scope with where it comes from, and the
  products the person may open.

The App Central token carries the same picture — `scope` and `products` — as a
snapshot. App Central itself decides every request from the database, and when
a token is out of date it says so (`X-Alora-Token-Stale: 1`); the page renews
it, so a change shows at once.

---

## Integrating a product

Every product has its own backend and is a **confidential OpenID Connect
client**. Tokens stay on that backend; nothing is shared with App Central's
cookies. `sample-product.cjs` implements every step below and is the reference.
Discovery, at `<issuer>/.well-known/openid-configuration`, lists every endpoint.

### 1. Register it (Owner console → Products)

| Field | What it is |
|---|---|
| **Key** | Permanent. Every token for the product carries the audience `product:<key>`. |
| **Launch (initiate login) URI** | Where App Central sends a user who opens the product, e.g. `https://crm.example.com/login/initiate`. |
| **Base URL** | Where the user lands once signed in. |
| **Redirect URIs** | The product's callback(s), matched **exactly**. |
| **Roles** | The catalogue grants may use, e.g. `Admin`, `Editor`, `Viewer`. |
| **Client secret** | Issued with **Issue secret** and shown **once**. The client id is the product's id. Rotating it retires the old secret at once. |
| **Accepts API clients** | Off by default. On lets applications get tokens for the product (step 8). |

Then subscribe the companies that may use it. Grant roles through a group
(**Company → Groups → Opens these apps**) or directly to a user.

### 2. Accept a launch — `GET /login/initiate?iss=…&target_link_uri=…`

This is OpenID Connect third-party-initiated login.

1. Refuse any `iss` that is not App Central's issuer.
2. Take the landing path from `target_link_uri`, keeping only a path on your own
   origin.
3. Start an ordinary authorization request, as in step 3. App Central never sends
   a product a code it did not ask for, so none can be planted.

### 3. Send the user to App Central

```
GET <issuer>/oauth/authorize?response_type=code&client_id=<product id>
    &redirect_uri=<registered, exactly>&scope=openid%20email
    &state=<random>&nonce=<random>
    &code_challenge=<base64url(sha256(verifier))>&code_challenge_method=S256
```

Keep `state`, `nonce` and the PKCE verifier **on your server**, bound to the
browser by your own HttpOnly cookie. If the user already has an App Central
session, App Central answers immediately with a redirect and no page. If not, it
shows its login page and resumes afterwards.

### 4. Handle the callback — `GET <redirect_uri>?code&state&iss`

- `state` must match the browser's pending request, and is single-use.
- `iss` must be App Central's issuer (RFC 9207).
- `error=access_denied` means the user may not use the product.

Exchange the code with **HTTP Basic** client authentication (id and secret each
form-encoded first, RFC 6749 §2.3.1):

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" <issuer>/oauth/token \
  -d grant_type=authorization_code -d code="$CODE" \
  -d redirect_uri="$REDIRECT_URI" -d code_verifier="$VERIFIER"
# → {"access_token", "token_type":"Bearer", "expires_in":900, "refresh_token", "id_token", "scope"}
```

A code is single-use and valid for two minutes. Presenting it twice revokes the
login it opened.

### 5. Verify both tokens (against `<issuer>/.well-known/jwks.json`)

| Check | Access token | ID token |
|---|---|---|
| `alg` | RS256, key by `kid` | RS256, key by `kid` |
| `typ` header | `at+jwt` | `JWT` |
| `iss` | the issuer | the issuer |
| `aud` | `product:<key>` | your client id |
| `exp` | in the future | in the future |
| other | `client_id` = your client id | `nonce` = the one you sent |

The access token's claims are `sub` (the user), `tenant_id` (their company),
`email`, `roles` (in this product only) and `principal: "user"`. Cache the
JWKS; re-fetch it when an unknown `kid` appears, but not on every request.

### 6. Renew, and notice when the user is gone

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" <issuer>/oauth/token \
  -d grant_type=refresh_token -d refresh_token="$REFRESH_TOKEN"
```

Refresh tokens rotate: store the new one each time. `invalid_grant` means the
login is over, so end your own session. That happens when the user signed out of
App Central, lost access, was deactivated, changed their password, or their
company's policy no longer allows how they signed in. A product refresh lives 12
hours at most and never outlives the App Central session.

### 7. Sign out, and revoke

`POST <issuer>/oauth/revoke` (Basic auth, `token=<refresh token>`) ends your
product's login. Signing out of App Central ends every product's login at once.
An access token already issued stays valid until it expires, at most 15 minutes.
A product that needs instant sign-out calls `POST <issuer>/oauth/introspect`,
which reports `active:false` the moment the session, the user or the access is
gone.

### 8. Accept application tokens (REST, gRPC, MCP) — optional

Once the Owner switches the product to **Accepts API clients**, applications can
call it with tokens of their own (next section). Such a token has the same
`iss`, `aud`, `typ` and signature as a person's; its claims differ:

| Claim | A person's token | An application's token |
|---|---|---|
| `principal` | `user` | `client` |
| `sub` | the user | the API client (`aci_…`), also its `client_id` |
| `roles` | their roles in this product | `[]` |
| `scope` | — | where it may be used: `api:read` `api:edit` (REST), `grpc:read` `grpc:edit` (gRPC), `mcp:tools` (MCP) |
| `email` | theirs | none |

Check `roles` on a person's token and `scope` on an application's, and accept
each kind only where you expect it. `sample-product.cjs` shows it: `GET
/api/items` answers an application token holding `api:read`, and refuses a
person's token (401 `invalid_token`) and a token without the scope (403
`insufficient_scope`). An application's token lasts 15 minutes and has no
refresh token; introspection reports it inactive once its secret is revoked,
its client is switched off, or the product leaves its list.

In Go, [`alora-auth-go`](alora-auth-go/README.md) does these checks: a
`Verifier`, gRPC interceptors that refuse every method without a rule, and
`RequireScope` for REST and MCP handlers.

---

## Applications: client credentials

An **API client** is an application's identity in a company: a client ID
(`aci_…`) and a secret (`acc_…`), a **product list** and a **scope**. Create one
under **Admin → API clients** (with `api-clients:edit`) or, as the Owner, under
**Company → API clients**; **Owner → Client credentials** lists every product
login and every API client. Then, on the client's page:

1. **New secret.** It is shown once — copy it. A client may hold two live
   secrets, so you rotate without downtime: make a new one, deploy it, revoke
   the old one.
2. **Products.** Tick those it may get tokens for. Only products the company is
   subscribed to and that accept API clients are offered.
3. **Scope.** Where its tokens may be used: REST (`api:read`, `api:edit`), gRPC
   (`grpc:read`, `grpc:edit`), MCP tools (`mcp:tools`). Edit includes read.

**Try it** on the same page prints the commands below with the client's values.

**Over HTTP**, a token is for one product, named by `resource`:

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" <issuer>/oauth/token \
  -d grant_type=client_credentials -d resource=product:CRM -d scope=api:read
# → {"access_token", "token_type":"Bearer", "expires_in":900, "scope":"api:read"}
```

`scope` is optional — the default is everything the client holds — and always
comes back. There is no refresh token: ask again. A `resource` that is missing,
unknown, not on the list or not usable right now is one answer,
`invalid_target`; a scope the client lacks is `invalid_scope`.

**Over gRPC**, when App Central runs with `GRPC_PORT`, `TokenService.GetToken`
answers the same request by the same rules and limits, with the credentials as
Basic `authorization` metadata:

```bash
grpcurl -plaintext \
  -H "authorization: Basic $(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64 | tr -d '\n')" \
  -d '{"resource":"product:CRM","scopes":["grpc:read"]}' \
  127.0.0.1:3002 alora.auth.v1.TokenService/GetToken
```

(`-plaintext` is for local development; in production the door serves TLS.)

**From Go**, `alora-auth-go` gets, caches and renews the token, and puts it on
every call:

```go
creds, err := aloraauth.ClientCredentials(aloraauth.Config{
	TokenAddress: "central.example.com:443", // App Central's gRPC door
	ClientID: id, ClientSecret: secret,
	Product: "CRM", Scopes: []string{"grpc:read"},
})
conn, err := grpc.NewClient("crm.example.com:443",
	grpc.WithTransportCredentials(credentials.NewTLS(nil)),
	grpc.WithPerRPCCredentials(creds))
```

For REST, `aloraauth.HTTPConfig{…}.Client(ctx)` is an `*http.Client` that does
the same. `alora-auth-go/README.md` has the details and a runnable demo.

---

## Running the tests

```bash
# API: unit + integration, running as alora_app against a throwaway PostgreSQL
cd alora-auth-api && ./scripts/integration-test.sh

# The Go helper and its demo
cd alora-auth-go && go test ./...

# App Central end to end, in a real browser, against the real API (both doors),
# database, sample product backends, the gRPC demo and a stub identity provider
cd alora-auth-api && ./scripts/e2e-up.sh
cd ../alora-auth-ui && npx playwright test
cd ../alora-auth-api && ./scripts/e2e-up.sh --down

# Every generated file — database objects, sqlc, the OpenAPI document, the
# protos' Go code — matches what its source produces
bash scripts/check-generated.sh
```

Nothing is mocked where the behaviour lives. The end-to-end suite exists because
a mocked backend cannot catch contract drift between the SPA, the API and a
product, the failure mode that returns `200` while rendering nothing.
`alora-auth-ui/e2e/README.md` lists what each spec covers.

---

## How the pieces fit

```
                 one origin (reverse proxy; Vite in development)
Browser ──► App Central SPA ─┬─► /api, /auth, /.well-known ──► alora-auth-api ──► alora-auth-db
   │                         └─► /oauth/authorize ────────────┘     CALL stp_…
   │                                                                SELECT … udf_…
   └─► a product (its own host) ──► its backend ── /oauth/token, /revoke, /introspect ──┘

An application ── /oauth/token (client_credentials) ──► alora-auth-api: a token for product:<key>
  (no person)  └─ or gRPC TokenService.GetToken ─────┘
      │
      └─► that product's REST API, gRPC services or MCP tools, with the token
```

**The API runs no ad-hoc SQL.** Every database interaction is a call to a
stored procedure or function, so predicates, projections and tenant scoping
live in one reviewable place. `sqlc` reads `alora-auth-db` to generate typed Go
bindings, which makes a procedure-signature change a compile error rather than a
runtime one.

If you change the database, edit the generator that owns the object —
`gen_tables.py`, `gen_views.py`, `gen_functions.py` or `gen_procedures.py`; the
object files are their byte-reproducible output — and run it, then:

```bash
cd alora-auth-db && python gen_build.py && ./migrate.sh
cd ../alora-auth-api && sqlc generate && go build ./...
```

If you change a proto in `alora-auth-go/proto`, run
`bash alora-auth-go/scripts/generate.sh`; the generated code is checked in.

---

## Production notes

**One origin for App Central and its API.** Serve the SPA and route `/api`,
`/auth`, `/oauth`, `/.well-known` and `/health` to the API from the same host,
over https. Set `JWT_ISSUER` and `FRONTEND_URL` to that origin. Every cookie is
host-only with the `__Host-` prefix, so giving the auth host its own registrable
domain keeps sibling subdomains out of its site entirely.

**Connect as `alora_app`.** The app role makes the audit trail append-only at the
database and cannot create Owners. It is least privilege by design, not by
convention. Two controls are both required:

- the role holds `INSERT` on `tbl_audit_logs` and nothing else;
- the trail's actor key is `ON DELETE RESTRICT`, so a user who has done anything
  cannot be deleted.

Without the second, the first is theatre: a referential action runs as the
referencing table's owner, so deleting a user would strip the actor from
existing audit rows. `roles.sql` refuses to finish if either has drifted.
`cmd/bootstrap` is the one thing that connects as the owner.

**Set `NODE_ENV=production`.** It turns on `Secure` and `__Host-` cookies, HSTS,
the placeholder-secret rejection, the `COOKIE_SECRET` length floor, https-only
origins and the SSO client's outbound restrictions (https only, no private
addresses). It also makes `SSO_SECRET_KEY` required. The value is checked against
an allowlist, so a typo is a startup failure, not a silently insecure deployment.

**Set `TRUSTED_PROXIES`** to your load balancer's CIDRs. It defaults to trusting
nothing, and leaving it empty behind a proxy makes every client look like the
proxy, which collapses per-address rate limiting.

**The gRPC door is off unless `GRPC_PORT` is set.** In production it serves TLS
(`GRPC_TLS_CERT`, `GRPC_TLS_KEY`) or sits behind a proxy that terminates TLS
(`GRPC_BEHIND_TLS_PROXY=true`, with the proxy in `TRUSTED_PROXIES`); a plaintext
listener stops the boot. It shares the token endpoint's rate limits.

**Keep `SSO_SECRET_KEY` safe and stable.** It seals every company's SSO client
secret. Changing it makes them unreadable until each is entered again.

**Replicas.** Sign-in state lives in the database, so several instances behind a
load balancer are correct. Rate-limit counters are per process by default, so N
replicas grant N× each budget. Set **`RATE_LIMIT_STORE=database`** to keep the
brute-force-sensitive budgets (password sign-in, the token endpoint, failed
client authentications, per-account password change) in a counter table every
instance shares, so they enforce one budget together. It fails open: a database
blip allows the request rather than refusing every caller.

---

## Documentation

| Document | What it covers |
|---|---|
| [`SPEC.md`](SPEC.md) | The behavioural contract: endpoint inventory, security invariants, decision record |
| [`BACKLOG.md`](BACKLOG.md) | Work not built yet; an item is deleted when it is implemented |
| [`alora-auth-api/ARCHITECTURE.md`](alora-auth-api/ARCHITECTURE.md) | Layering, request lifecycle, security architecture, threat model → controls |
| [`alora-auth-db/README.md`](alora-auth-db/README.md) | Database conventions, the PostgreSQL constraints that shaped them |
| [`alora-auth-db/Migrations/README.md`](alora-auth-db/Migrations/README.md) | The v3 baseline, and when a change needs a migration |
| [`alora-auth-go/README.md`](alora-auth-go/README.md) | The Go helper: tokens for applications, token checks for products, the gRPC demo |
| [`alora-auth-ui/e2e/README.md`](alora-auth-ui/e2e/README.md) | The browser suite: what runs where, and what each spec covers |
| [`alora-auth-api/JUSTIFICATION.md`](alora-auth-api/JUSTIFICATION.md) | A construct-level audit of the foundations (predates App Central) |
| [`AGENTS.md`](AGENTS.md) | For AI coding agents: the rules the build enforces, the commands, what "done" means (`CLAUDE.md` imports it) |
| [`docs/agents/`](docs/agents/index.md) | Agent knowledge (Open Knowledge Format): an architecture map, change playbooks, gotchas |
| [`.claude/`](.claude/) | Claude Code: subagents, path-scoped rules, the OKF skill, and hooks that refuse an edit to the agent files until that skill is loaded |

---

## Troubleshooting

**`bind: An attempt was made to access a socket in a way forbidden…`**
Windows has reserved the port into its dynamic-exclusion range. Nothing is
listening, but it cannot be bound. Use another port:
`ALORA_DB_PORT=55600 ./scripts/e2e-up.sh`.

**A shell script exits with no output at all.**
Usually `openssl` is failing silently because `MSYS_NO_PATHCONV=1` was exported
globally. That stops Git Bash converting `/tmp/x` into a Windows path, which
native binaries need. Scope it to `docker` only, as the scripts here do.

**`type "idpprovider" does not exist`**
The enum types are created quoted, so `pg_type.typname` keeps its mixed case.
Compare against `'IdpProvider'`, not the lower-cased form.

**`v1 schema detected` or `v2 schema detected; rebuild the database from scratch`**
The database was built by an earlier version. There is no upgrade path, by
design: build a fresh database (`alora-auth-db/Migrations/README.md`).

**`/oauth/authorize` answers 400 instead of redirecting.**
The `client_id` is unknown or the `redirect_uri` is not registered **exactly**
(scheme, host, port, path and query). App Central never redirects to an
unverified address, so this error is shown rather than sent back.

**The token endpoint answers `invalid_client`.**
The client authenticates with HTTP Basic only, with the id and secret each
form-encoded before the base64 step. A secret in the form body is refused.
Rotating a product's secret retires the old one immediately. For an API client,
a revoked or expired secret, a client switched off and a suspended company are
the same answer.

**`unauthorized_client` or `invalid_target`.**
`unauthorized_client`: a product used `client_credentials`, or an API client
used another grant or `/oauth/revoke` / `/oauth/introspect`. `invalid_target`:
the `resource` is not a product on the API client's list that it can use right
now — ask the Owner whether the product still accepts API clients and the
subscription is live.

**API exits at startup with a config error.**
That is the intended behaviour. Every variable is documented in
`alora-auth-api/.env.example`; the message names the one at fault.
