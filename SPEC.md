# Alora App Central — Behavioural Specification

> What this system must do, stated precisely enough to verify. Every status code,
> JSON shape, cookie flag, crypto parameter and error string below is a hard
> requirement, not a description of the current implementation — if the code and
> this document disagree, one of them is a bug, and which one is a decision
> someone has to make deliberately.
>
> Companion documents: [`alora-auth-api/ARCHITECTURE.md`](alora-auth-api/ARCHITECTURE.md)
> covers layering and the threat model; this covers behaviour. Section numbers are
> stable — source comments cite `SPEC §2`, `SPEC §3` and `SPEC §8` directly, so
> sections are rewritten in place rather than renumbered.
>
> Originally written 2026-06-16 to drive the Fastify → Go rewrite. Rewritten
> 2026-09-27 for **App Central** (schema v2): two-step tokens, the platform Owner,
> group-granted products, login policies and company SSO. The v1 contract — one
> token for everything, `/auth/authorize` password login, a script-readable
> access-token cookie — is gone, not deprecated: nothing was live, and the
> database is rebuilt rather than migrated (`alora-auth-db/Migrations/README.md`).
>
> Extended the same month for **schema v3**: App Central access as per-feature
> *scopes* (read and edit) given by groups and extras under two rules, the login
> token's snapshot of that access, and **applications** — API clients that get
> product tokens with client credentials, over HTTP or gRPC — with a Go helper
> for them and for the products that check their tokens (`alora-auth-go/`).

---

## 0. Things that surprise people

Read this section before concluding something is broken.

- **Three kinds of access token, never interchangeable.**
  - App Central's own **login token** (`aud: "app-central"`) is the only one
    `/api/*` accepts. It carries everything about App Central: the person's
    `scope` (what they may do there) and `products` (the keys of the apps they
    may open — keys only).
  - A **person's product token** (`aud: "product:<key>"`, `principal: "user"`)
    carries their roles in that product only.
  - An **application's product token** (`aud: "product:<key>"`,
    `principal: "client"`) is issued to an API client with client credentials
    and carries a `scope` (`api:*`, `grpc:*`, `mcp:tools`), no roles and no person.

  Each is refused where another belongs.
- **Products never show a login page.** App Central is where people sign in (with
  a password, Google, or their company's SSO) and the launcher of their apps.
  Opening an app sends the browser to the product's backend, which asks App
  Central for a code in an ordinary authorization request — answered at once,
  with no page, because the user already has a session. App Central never hands a
  product a code it did not ask for.
- **Every product is a confidential client with its own backend.** It exchanges
  codes at `/oauth/token` with `client_secret_basic`. Tokens never reach product
  JavaScript, and PKCE (S256) is still required.
- **No access token in any cookie or storage.** App Central's access token lives
  in page memory; its refresh token is an HttpOnly, host-only cookie that script
  never sees. A page reload therefore starts with a refresh.
- **The Owner is above every company's Admins.** A platform Owner (a member of the
  platform company, listed in `tbl_platform_owners`) runs `/api/owner/*` for
  every company: companies, subscriptions, product registration, groups and what
  they grant, login policies, SSO. There is no API that makes an Owner — only
  `cmd/bootstrap platform`, connected as the schema owner.
- **What someone may do in App Central is a set of scopes.** Each feature has a
  read scope and, where it can be changed, an edit scope (`users:read`,
  `users:edit`, …); a person's scopes are their groups' plus extras given to them
  alone, and the company's system group `ADMINS` holds every one. Nobody gives
  or takes away a scope they do not hold, and nobody acts on someone with more
  access than they have; the Owner is bound by neither. A group can also have
  **managers**, who add and remove its members and nothing else, without
  `groups:edit`. All of it is read from the database on every request — a
  product role named "Admin" confers nothing.
- **The login token's access is a snapshot.** `scope` and `products` say what
  was true when the token was minted; App Central decides each request from the
  database. A response carries `X-Alora-Token-Stale: 1` when the token no longer
  describes the caller, and the SPA then refreshes once and reloads `/api/me`.
- **Applications get tokens too.** An API client — a client ID (`aci_…`) and
  secret (`acc_…`), a list of the company's products and a scope — asks for a
  token for one product with `grant_type=client_credentials` and
  `resource=product:<key>`, at `/oauth/token` or through gRPC's
  `TokenService.GetToken` (`GRPC_PORT`). Only products the Owner has switched to
  *accept API clients* can go on a list, and every token is checked again.
- **Sign-in discovery works by email *domain*.** `POST /auth/login/discover`
  answers the same for every address at a domain, so it cannot reveal whether an
  account exists. The login policy is enforced again at the end of every sign-in
  path and at every refresh.
- **32 tables, 33 views, 73 read functions, 73 write routines.** Every relation
  that crosses a tenant boundary carries a composite `(…, client_id)` foreign
  key, and every grant of a scope references the closed catalogue `tbl_scopes`.
- **Email delivery is built in**, and a no-op when SMTP is unconfigured. Outside
  production the invite and reset links then come back in the API response; in
  production a reset without mail is refused rather than returned.
- **There is no signup endpoint.** Companies are created by the Owner; the first
  company and Owner by `cmd/bootstrap`.

---

## 1. Endpoint inventory

Every JSON body is `application/json` (anything else is 415) and rejects unknown
fields (400). The API and App Central share one origin: the SPA's pages
everywhere, the API under `/api`, `/auth`, `/oauth`, `/.well-known` and
`/health`.

### Health and standards (public)
| Method | Path | Purpose | Key responses |
|---|---|---|---|
| GET | /health | liveness | 200 `{status:"ok"}` |
| GET | /health/ready | readiness (SELECT 1) | 200 `{status:"ready"}` / 503 `{status:"unavailable"}` |
| GET | /health/pressure | backpressure | 503 while overloaded (heap/RSS). While overloaded, EVERY route answers 503 + `Retry-After: 10` with the ≥500 envelope |
| GET | /.well-known/openid-configuration | OpenID Provider metadata | 200; `issuer` = `JWT_ISSUER`; `response_types_supported:["code"]`, `grant_types_supported:["authorization_code","refresh_token","client_credentials"]`, `code_challenge_methods_supported:["S256"]`, `token_endpoint_auth_methods_supported:["client_secret_basic"]`, `id_token_signing_alg_values_supported:["RS256"]`, `authorization_response_iss_parameter_supported:true`. CORS `*` |
| GET | /.well-known/jwks.json | public keys | 200 `{keys:[{kty:"RSA",kid,alg:"RS256",use:"sig",n,e}]}` — the signer and every verify-only key, sorted by kid; `Cache-Control: public, max-age=300, must-revalidate`, `Vary: Accept-Encoding`. CORS `*` |

### The OpenID Provider (a product's backend, or an application)
| Method | Path | Auth | Key responses |
|---|---|---|---|
| GET | /oauth/authorize | the App Central session cookie | Products only: an API client's id is an unknown client. Unknown client or unregistered `redirect_uri` → **400, never a redirect**; so is a repeated `client_id` or `redirect_uri`. With a usable session and access → 302 `redirect_uri?code&state&iss` (the session cookie is rotated). No session → 302 `/login?return_to=<this request>`; with `prompt=none` → 302 `?error=login_required`. No access → `?error=access_denied`. Other request errors (no PKCE, bad `response_type`, any parameter it reads given twice) → 302 `?error=invalid_request&state&iss`; a parameter it does not read is ignored |
| POST | /oauth/token | `client_secret_basic` (form body; repeated parameters refused) | A **product**: `authorization_code` (code + exact `redirect_uri` + `code_verifier`) or `refresh_token` → 200 `{access_token, token_type:"Bearer", expires_in:900, refresh_token, id_token?, scope}`. An **API client**: `client_credentials` with `resource=product:<key>` and an optional `scope` (space-separated; default: all it holds) → 200 `{access_token, token_type:"Bearer", expires_in:900, scope}` — no refresh token, no ID token. Always `Cache-Control: no-store`. RFC 6749/8707 errors: 400 `invalid_request`/`invalid_grant`/`unsupported_grant_type`; 400 `unauthorized_client` for a grant the client's kind may not use; 400 `invalid_target` for a resource that is missing, unknown, not on the list or not usable (one answer for all); 400 `invalid_scope` for a scope the client does not hold; 401 `invalid_client` (with `WWW-Authenticate`); 409 `invalid_grant` for a concurrent refresh of one token (retry) |
| POST | /oauth/revoke | `client_secret_basic`, products only (an API client: 400 `unauthorized_client`) | 200 always (RFC 7009); ends the calling product's login the token belongs to, never another product's |
| POST | /oauth/introspect | `client_secret_basic`, products only (an API client: 400 `unauthorized_client`) | 200 `{active:false}` unless the token is for the caller AND still live. A person's (`principal:"user"`): its login, its App Central session, the user, the company and the access, and an access token's permissions version current. An application's (`principal:"client"`): the API client and its company on, the secret it was issued under live, the product still on the list and usable, every scope in it still held. An active answer adds `principal` and, for an application, `scope` |

### gRPC (`GRPC_PORT`; TLS in production)
| Service / method | Auth | Key responses |
|---|---|---|
| `alora.auth.v1.TokenService/GetToken` `{resource, scopes[]}` | `authorization: Basic …` metadata, exactly once — `client_secret_basic` as over HTTP | `{access_token, token_type:"Bearer", expires_in, scopes[]}`: the same service calls as `client_credentials` at `/oauth/token`, with the same rules and the same budgets. A refusal carries a `google.rpc.ErrorInfo` whose `reason` is the OAuth code: `invalid_client` → `Unauthenticated`; `invalid_target`, `unauthorized_client` → `PermissionDenied`; `invalid_scope`, `invalid_request` → `InvalidArgument`; spent budgets → `ResourceExhausted` with `RetryInfo`; memory pressure → `Unavailable` |
| `grpc.health.v1.Health/Check` | none | `SERVING` for `""` and for `alora.auth.v1.TokenService` |

Reflection is served outside production only. The protos live in
`alora-auth-go/proto`, and their generated code in `alora-auth-go/authpb`.

### App Central sign-in (`/auth`: same-origin only; see §2)
| Method | Path | Purpose | Key responses |
|---|---|---|---|
| POST | /auth/login/discover | methods for an address's domain | 200 `{password, google, sso:{connection_id}|null}` |
| POST | /auth/login/password | password sign-in | 200 `{status:"authenticated", access_token, token_type, expires_in, return_to?}` + session cookie; or `{status:"choose_company", companies:[{client_id,name}], return_to?}` + chooser cookie. 401 `Invalid email or password` for no account, a wrong password, **and** a right password whose policy forbids passwords. Rate limit per ip\|email |
| GET | /auth/login/choices | a pending company choice | 200 `{companies}` / 401 |
| POST | /auth/login/choose | complete it | 200 as `authenticated` above / 401 |
| POST | /auth/central/refresh | rotate the session | 200 `{access_token, token_type, expires_in}` (no refresh token in the body) / 401 `Session invalid or expired` (cookie cleared) / 409 concurrent rotation (cookie kept) |
| POST | /auth/central/logout | end the session and every product login under it | 204 always |
| GET | /auth/google/start, /auth/sso/start | begin a federated sign-in | 302 to the provider (PKCE, state, nonce; state bound by cookie) / 302 `/login?google_error=`\|`sso_error=<code>` |
| GET | /auth/google/callback, /auth/sso/callback | finish it | 302 to `return_to` (or `/`), to `/login?choose=1`, or to `/login?<param>=<code>` |
| GET | /auth/accept-invitation/lookup | invite preview | 200 `{client_name, email, expires_at, groups[], methods:{password,google,sso}}` / 400 |
| POST | /auth/accept-invitation | accept with a password | 204 / 400 (also when the invitee's policy forbids passwords) |
| POST | /auth/accept-invitation/federated | accept for Google/SSO sign-in | 204 / 400 / 409 |
| POST | /auth/reset-password | consume a reset token | 204 / 400 |

Federated callback codes (a closed set, never provider text): `invalid_request`,
`state_mismatch`, `state_expired`, `exchange_failed`, `email_unverified`,
`account_unavailable`, `sso_unavailable`, `google_disabled`, `server_error`,
`cancelled`.

### App Central's API (`/api`: App Central token only; session re-checked per request)
| Method | Path | Guard (the scope the route needs) |
|---|---|---|
| GET | /api/me, /api/me/apps | any signed-in user. `/api/me` returns `scopes` (as the token lists them), `scope_sources` (each scope with `source` `GROUP`/`EXTRA` and the group), `products` (keys) and `manages` (`[{id, name}]`, the groups they run as a manager) |
| GET, GET:gid / POST:gid/members, DELETE:gid/members/:uid | /api/me/managed-groups… | any signed-in user, on a group they manage (404 otherwise, asked on every call and again inside the write); the writes are budgeted per account (60 per 15 min) |
| POST | /api/me/change-password | any signed-in user; 403 for a wrong current password; 5 attempts per 15 min per account |
| GET / GET:id | /api/admin/users[/:id] | `users:read` |
| PATCH:id, PUT:id/scopes, POST:id/password-reset | /api/admin/users/:id… | `users:edit` (activate/deactivate; a person's extra scopes; a reset) |
| GET / POST, DELETE:id | /api/admin/invitations[/:id] | `invitations:read` / `invitations:edit` |
| GET / GET:id | /api/admin/groups[/:id] | `groups:read` |
| POST, PATCH:id, DELETE:id, PUT:id/scopes, POST / DELETE:userId members, POST / DELETE:userId managers | /api/admin/groups… | `groups:edit` |
| GET / DELETE:id | /api/admin/sessions[/:id] | `sessions:read` / `sessions:edit` |
| GET | /api/admin/products | `products:read` |
| GET / PATCH | /api/admin/client | `company:read` / `company:edit` |
| GET, GET:id / POST, PATCH:id, DELETE:id, PUT:id/scopes, PUT:id/products, POST:id/secrets, DELETE:id/secrets/:sid | /api/admin/api-clients… | `api-clients:read` / `api-clients:edit` |
| everything | /api/owner/companies[/:cid/…], /api/owner/products[/:pid/…], /api/owner/api-clients | Owner, signed in within `OWNER_MAX_AUTH_AGE`; every write under `/companies/:cid` repeats `:cid` in `X-Alora-Target-Company` |

A route refused for its scope answers 403 `{"error":"Forbidden"}`; the two rules
refuse in their own words (§2). Every response to a token whose snapshot is out
of date carries `X-Alora-Token-Stale: 1`.

The Owner's company routes are the admin routes at the same path under
`/companies/:cid` — `users[/:uid]` with `scopes` and `password-reset`,
`invitations`, `groups[/:gid]` with `scopes`, `members` and `managers`, `api-clients[/:aid]`
with `scopes`, `products` and `secrets` — plus what only the Owner decides: the
company itself (`PATCH`, `PUT /domain`), `subscriptions/:pid`, users'
`login-policy` and `grants/:pid`, groups' `product-grants` and `login-policy`,
`login-policies[/:pid]` with `default`, and `sso-connections[/:sid]` with
`domains` and `test`. `GET /api/owner/api-clients` lists every company's API
clients. Product routes cover registration (including `accepts_api_clients`,
which a change that leaves it out keeps), `redirect-uris`, `roles` and
`client-secret` (the secret is in that one response and never again). `/docs`
lists every route with its exact shapes.

---

## 2. Security invariants that MUST survive (byte-for-byte)

### Crypto
- **JWT RS256 ONLY.** Header `{alg:"RS256", kid, typ}` with `typ` `at+jwt` on
  access tokens and `JWT` on ID tokens; verification pins the algorithm, resolves
  the key by kid (missing/unknown → reject) and pins `typ` (case-insensitively,
  with an optional `application/` prefix). One active signer plus verify-only
  keys (`JWT_VERIFY_KEYS`), all published in the JWKS.
- **The audience is mandatory at verification.** No verifier accepts a token
  without naming the audience it expects; `internal/core/auth/service` is the only
  code that signs (both pinned by `cmd/api/architecture_test.go`).
- **Claims.** Registered: `iss`(= `JWT_ISSUER`), `iat`, `exp`, `jti`, `sub`.
  - App Central (the login token): `aud:"app-central"`, `{tenant_id, email,
    sid:<central family>, scope, products, manages, av, pv}`. `scope` is
    space-separated and sorted — `apps:read` first, then the App Central scopes
    held, then `owner` for a platform Owner; `products` is the sorted list of the
    keys of the apps the person may open (no roles); `manages` the sorted ids of
    the groups they run as a manager (never null); `av` and `pv` are the versions
    of their App Central access and their product access the snapshot was taken
    at, read BEFORE the snapshot.
  - A person's product token: `aud:"product:<key>"` only, `{client_id:<product
    id>, tenant_id, email, roles:[this product's roles, never null],
    sid:<product family>, pv, principal:"user"}`.
  - An application's product token: `aud:"product:<key>"` only, `{sub =
    client_id:<the API client, aci_…>, tenant_id, scope, roles:[] , sid:<the
    secret it was issued under>, principal:"client"}` — no email, no person.
  - ID token: `aud:<product id>`, `{nonce, auth_time, sid:<central family>,
    email, tenant_id}`.
- **Argon2id EXACT:** type=argon2id, memory=**19456 KiB**, time=**2**, parallelism=**1**, salt 16B, key 32B, v=19. PHC `$argon2id$v=19$m=19456,t=2,p=1$<b64.RawStd salt>$<b64.RawStd hash>`. VerifyPassword swallows all errors → false (never 500). Max password length **512 UTF-16 code units**.
- **Opaque tokens:** refresh = `crypto/rand 32B → hex` (64 chars). Codes, reset
  and invite tokens, state and nonce → **base64.RawURLEncoding** (unpadded). A
  product client secret is `acs_` + base64url; an API client secret is `acc_` +
  base64url, of which only the first 12 characters are kept in the clear (to tell
  two apart); an API client's id is `aci_` + a uuid. At rest every one is
  `sha256(raw)` **lowercase hex** (unsalted; fine because high-entropy). PKCE =
  `base64.RawURLEncoding(sha256([]byte(verifier)))`, compared in constant time.
  **S256 only.** SSO client secrets are sealed with AES-256-GCM
  (`SSO_SECRET_KEY`, associated data = the connection id).
- **TTLs:** access tokens **15 min** (`expires_in` 900), an application's
  included, which has no refresh token; ID token **10 min**;
  authorization code **2 min**; central session idle **7 days**, absolute **14
  days**; product refresh **12 h**, capped by its central session; federated
  sign-in state **10 min**; company choice **5 min**; invitation **7 days**;
  reset **60 min**; Owner recent sign-in **12 h**.

### Cookies (host-only; `__Host-` prefixed in production)
- Every cookie is `HttpOnly`, `SameSite=Lax`, `Path=/`, **no `Domain`**,
  `Secure` in production, where the name carries `__Host-`:
  - `alora_cs` — the central session's refresh token.
  - `alora_login` — binds a Google/SSO round trip to this browser; HMAC-signed.
  - `alora_choose` — binds a company choice to this browser; HMAC-signed.
- No cookie carries an access token. `COOKIE_DOMAIN` is refused at startup.
- A clear replays exactly the attributes of the set, or the browser keeps the cookie.

### Sessions and rotation (the crown jewels)
- A sign-in opens a **central** session family; each product login is a
  **product** family, a child of it. Every refresh token belongs to one family;
  rotation runs in a pgx transaction on `SELECT … WHERE refresh_token_hash=$1 FOR
  UPDATE` with **no `revoked_at` filter** (a revoked match is the replay signal).
  `PREV_TOKEN_GRACE = 30 s`.
- **Every rotation re-checks the gate:** the family and its parent alive and under
  their caps, the user and company active, the product active with a live
  subscription and the user holding a role in it (product families), and the
  login policy still allowing how the user signed in.
  - Access gone → the product family is revoked with `ACCESS_LOST`.
  - Policy no longer allows it → the whole sign-in is revoked with `POLICY`.
- **Replay outside the grace window → revoke and 401.** A central token's replay
  revokes the family and every product family under it; a product token's replay
  revokes only that product's family. Both use `REUSE_DETECTED`. **COMMIT the
  revocation before returning the error.**
- **Benign race inside the grace window → 409**, cookie kept, nothing burned.
  Two detection paths: a revoked row with a live successor, and the zero-row
  fallback through `prev_token_hash` with `created_at > graceCutoff`.
- `/oauth/authorize` rotates the central cookie too, so a session used only
  through products keeps its idle timer running.
- App Central sign-out revokes the whole tree. A product access token already
  issued stays valid until it expires (15 min) unless the product introspects.
- A code redeemed twice revokes the product login it opened (RFC 6749 §4.1.2).

### Authorization and tenant isolation
- **App Central scopes.** Each feature has a read scope and, where it can be
  changed, an edit scope; edit includes read, so giving an edit scope always
  gives its read scope, and a token lists both. The closed catalogue is
  `tbl_scopes` (kind `PERSON`), and `internal/core/shared/scopes.go` must list
  exactly the same (a schema test holds them in step):

  | Feature | Read | Edit | Edit lets you… |
  |---|---|---|---|
  | Apps | `apps:read` | — | (everyone signed in) see the product list |
  | Users | `users:read` | `users:edit` | activate/deactivate, send password resets, give a person extra scopes |
  | Groups | `groups:read` | `groups:edit` | create, rename and delete groups, choose their scopes, add and remove members |
  | Invitations | `invitations:read` | `invitations:edit` | invite people into groups, revoke invitations |
  | Sessions | `sessions:read` | `sessions:edit` | revoke sessions |
  | Products | `products:read` | — | see the company's subscriptions (the Owner decides them) |
  | Company | `company:read` | `company:edit` | rename the company |
  | API clients | `api-clients:read` | `api-clients:edit` | create API clients, rotate their secrets, choose their products and scope |

  A platform Owner also holds `owner`. `apps:read` and `owner` are never given:
  one is everyone's, the other is provisioned.
- **Where scopes come from:** a person's groups (`tbl_group_scopes`) plus extras
  given to them alone (`tbl_user_scopes`, attributed to the user or the Owner who
  gave them), with each scope's source visible (`vw_EffectiveScope`). The system
  group `ADMINS` holds every `PERSON` scope implicitly, has no rows, and cannot be
  renamed, re-scoped or deleted (409). Every `/api/admin` route needs one scope
  (`RequireScope`), read from the database on THIS request; a route-table test
  proves every admin route has one.
- **Rule 1 — nobody gives or takes away a scope they do not hold.** It covers a
  group's scopes (what a change adds AND what it removes), creating and deleting
  a group, adding someone to or removing them from a group (the Admins group
  gives every scope), an invitation into groups, and a person's extras. Refused:
  403 `You can only give or take away scopes you hold yourself`.
- **Rule 2 — nobody acts on someone with more access than they have**:
  deactivating them, resetting their password, changing their extras or their
  groups, appointing or dismissing them as a group's manager. Access is measured
  by **reach**: the scopes a person holds plus the scopes of every group they
  manage, since a manager can hand those out (`vw_ScopeReach`, which grants
  nothing — the session gate reads `vw_EffectiveScope`). The person acted on
  must have no more reach than the actor holds. Nobody but an Owner acts on an
  Owner, however many scopes they hold. Refused: 403 `You can only manage people
  who have no more access than you`.
- The Owner console is bound by neither rule. **Product access** — which products
  a group opens, direct grants — stays the Owner's alone (an Admin giving a group
  products: 403; deleting a group that gives products: 403).
- Nobody changes their own extras or their own active flag (400).
- **Group managers** run one group: they add and remove its members, and
  nothing else, without `groups:edit`.
  - Appointed and dismissed (`…/groups/:id/managers`) by a holder of
    `groups:edit` who holds every scope the group gives — a manager can hand the
    group out, so appointing one is handing it out (rule 1) — and under rule 2
    on the person. The Owner console is bound by neither rule.
  - Nobody appoints themselves (400; a CHECK too); the Admins group never has
    managers (409), since whoever decides its members decides who is an Admin;
    only a live user of the group's company (404).
  - A manager works through `/api/me/managed-groups`, which needs no scope. It
    answers 404 for any group they do not manage — asked on every call — and the
    two writes ask again inside the procedure, after share-locking the group row
    that a dismissal locks for update: a manager dismissed a moment ago cannot
    slip one more change in.
  - There, rule 2 measures both sides by reach: the member's reach must be
    covered by the manager's. A manager never changes the membership of the
    group's managers, themselves included (403 `A group's managers can't add or
    remove themselves or each other; an Admin does that`), nor an Owner's.
  - Appointing, dismissing and deleting the group bump the manager's
    `admin_version`; a manager's add or removal bumps the member's versions,
    never the manager's. Audited `group.manager_added` / `group.manager_removed`
    with `{group_id, user_id}`; membership events carry `{group_id, user_id}`
    and, through the manager's door, `by_manager: true`.
- **The login token is a snapshot.** Every change to a person's App Central
  access bumps their `admin_version`, and every change to their product access
  their `permissions_version`, inside the same procedure as the change. A request
  whose token names other versions than the database is still decided from the
  database, and its response carries `X-Alora-Token-Stale: 1`.
- **Owner** = a row in `tbl_platform_owners` (SELECT-only to the app role) for a
  user of the platform company, signed in within 12 h.
  - Every Owner write under a company must carry `X-Alora-Target-Company: <cid>`
    (400 otherwise).
  - Each Owner action writes two audit rows: one under the platform company
    naming the Owner, one under the target company with no actor.
  - The platform company cannot be suspended or deactivated.
- **Suspending a company ends its sessions.** Deactivating a company
  (`is_active` → false, the Owner's Suspend) revokes every live session it has,
  central and product alike (reason `SUSPENDED`), in the same transaction as the
  status change. Reactivating the company does **not** bring them back: a
  suspension made over a compromise is not undone by turning the company on
  again. (Deactivating a *user* already behaves this way.)
- **Seat limits.** A company's `max_seats` caps its active members (`is_active`
  and not soft-deleted); a subscription's `seat_limit` caps the distinct people
  who may open that product (`vw_EffectiveProductRole`). `NULL` is unlimited.
  Both are enforced in the database, in the same transaction as the change and
  under a row lock so two concurrent additions cannot both slip under:
  `max_seats` when a member is created (invitation accept) or reactivated;
  `seat_limit` on every change that widens product access — a direct grant, a
  group join (Admin or manager door), or attaching a product to a group. Over a
  limit answers 409 and changes nothing.
- **Guards:** the last active Admin of a company can be neither deactivated nor
  removed from `ADMINS` (409); the system group cannot be renamed or deleted; a
  new company is created with its `ADMINS` group and exactly one default login
  policy, atomically.
- **Product access** = direct grants ∪ grants through groups, and only for an
  active product, a live subscription and an active company. Role names come from
  the product's catalogue (`tbl_product_roles`). A grant change bumps the
  affected users' `permissions_version` atomically (`SET pv = pv + 1`).
- Every tenant-scoped query filters by the caller's (or the Owner's target)
  `client_id`, never one taken from a body. A resource of another company answers
  404.
- **Anti-enumeration:** unknown email, wrong password and a policy-forbidden
  password all get the identical 401 `Invalid email or password`, and the
  missing-user path still runs an argon2 verify against a startup `DUMMY_HASH`.
  The company list of a choice is shown only after the first factor succeeded.
- **Single-use atomicity:** code redemption, invitation acceptance and reset are
  each one `UPDATE … WHERE <state guard> RETURNING`; a login state is taken by
  one `DELETE … WHERE <unexpired> RETURNING`.

### API clients and the client-credentials grant
- **An API client** belongs to one company: an id (`aci_…`), a name unique in
  the company (case-insensitively), an on/off switch, **one scope list** and
  **one product list**. It is created by a user of the company (with
  `api-clients:edit`) or by an Owner — exactly one, recorded — and starts with
  nothing: no scope, no product, no secret.
- **Its scopes** say where its credential may be used — `api:read`, `api:edit`
  (a product's REST API), `grpc:read`, `grpc:edit` (its gRPC services),
  `mcp:tools` (its MCP tools) — from the catalogue's `CLIENT` rows; edit brings
  read. A person's scope is refused, by the service and by the catalogue key.
- **Its products**: a product ADDED to the list must be a live subscription of
  the company (on, started, not ended) to an active product the Owner has
  switched to `accepts_api_clients` (off by default); a product already on the
  list may stay when that changes, and is marked not `usable`.
- **Its secrets** are stored as SHA-256 with a 12-character prefix, shown once in
  the response that made them (`Cache-Control: no-store`), optionally expiring.
  **At most two are live** — made under a row lock — so a secret rotates without
  downtime. Revoking stamps `revoked_at`; the application role can neither
  rewrite a secret's hash nor delete a secret.
- **One client-authentication lookup for both kinds** (`vw_OAuthClientCredential`:
  a product's secret, or an API client's live secrets). The presented secret is
  hashed once and compared in constant time with EVERY stored hash — or a dummy
  when there is none. An unknown client, an inactive one (an API client switched
  off, or its company suspended), a revoked or expired secret and a wrong secret
  are the same 401 `invalid_client`. Only then does anything look at the kind.
- **Grants by kind:** products may use only `authorization_code` and
  `refresh_token`; API clients only `client_credentials`. `/oauth/authorize`,
  `/oauth/revoke` and `/oauth/introspect` are products' alone.
- **`client_credentials`** needs `resource=product:<key>`. A resource that is
  missing, unknown, not on the list, or not usable right now (the client or its
  company off, the subscription over, the product off or no longer accepting API
  clients) is ONE answer, 400 `invalid_target`, so it reveals nothing about
  products the client may not have. `scope` asks for some of the client's scopes
  (edit brings read); one it lacks is 400 `invalid_scope`, and so is a client
  with no scope at all. The token's `scope` is always in the response.
- Each token stamps `last_used_at` on the secret and its API client, at most once
  a minute each.
- **Rate limits:** the token endpoint's per-client budget and its per-address
  budget of failed client authentications are the SAME limiters for HTTP and
  gRPC, keyed the same way: failures spent on one door close the other.

### gRPC transport
- Off unless `GRPC_PORT` is set. In production the listener serves TLS itself
  (`GRPC_TLS_CERT`, `GRPC_TLS_KEY`) or sits behind a proxy that terminates TLS
  (`GRPC_BEHIND_TLS_PROXY=true`); a plaintext listener in production, a
  half-set pair or both at once are refused at startup.
- Behind a proxy, the caller's address comes from `x-forwarded-for` only when the
  peer is in `TRUSTED_PROXIES` — the right-most hop that is not itself trusted.
- Messages are capped at 64 KiB; 64 concurrent streams per connection; a
  handshake must finish in 10 s; idle connections close after 5 min, any after
  30; a client pinging more often than every 30 s is told to stop.
- The interceptors run in the HTTP chain's order: request id (fresh, never the
  caller's; returned as `x-request-id`), recovery (a panic is `Internal`, never its
  text), one log line per call (method, code, duration, address — never metadata
  or messages), shedding under memory pressure, then the token budgets.
- Shutdown stops gRPC gracefully within the same 15 s as HTTP, before the pool
  closes.

### Login policies and federated sign-in
- A policy is `{allow_password, allow_google, sso_connection_id, priority}`. The
  one that applies to a user is resolved in this order:
  1. the user's own policy;
  2. otherwise the highest-priority policy among their groups;
  3. otherwise the company default.

  It is enforced at the end of every sign-in path and at every refresh — never
  only in the UI.
- **Discovery** by domain: a domain on an active SSO connection routes to it;
  otherwise a company's verified domain offers its default methods; otherwise
  password (and Google, when configured).
- **OIDC client (Google and company SSO).**
  - Discovery must name exactly the configured issuer.
  - ID tokens are RS256 only (`alg:none`, HS256 and an unknown kid are refused);
    unknown kids trigger a JWKS re-fetch at most once a minute.
  - The client checks `iss` (Google's `accounts.google.com` alias included),
    `aud`, `azp`, `exp`/`iat`/`sub` and the nonce, and uses PKCE and a state
    bound to this browser.
  - In production outbound calls are https only, private addresses are refused
    at dial time, responses are capped at 1 MB and 10 s, with no redirects and no
    proxy.
- **Linking.** A linked `(connection, subject)` or `(Google subject, company)`
  signs its account in. Otherwise the first link by address requires all of:
  - the domain listed on the connection;
  - a verified address (unless the Owner trusts the connection);
  - an account that already exists.

  Federated sign-in never creates an account, and there is no IdP-initiated
  sign-in.

### Input / output hygiene
- Unknown JSON fields are **rejected (400)**; a non-JSON body is **415**; bodies
  over 64 KiB are refused. `SetTrustedProxies` is an explicit allowlist.
- **Same-origin only** on every state-changing `/auth` request: `Sec-Fetch-Site`
  must be `same-origin` or `none` when present (a same-SITE sibling is refused),
  else `Origin`, when present, must be `FRONTEND_URL` or the issuer. CORS exists
  for `/.well-known/*` alone (`ACAO: *`, never with credentials).
- `return_to` is followed only when it is a path on App Central: `//host`,
  `/\host`, control characters, schemes and hosts are all dropped, not
  normalised.
- Error envelope: ≥500 → `{error:"Internal Server Error", reqId}`; 4xx →
  `{error:safeLabel||msg, reqId}`. Rate limit → 429 with `Retry-After`,
  validation → 400, 404 → `{error:"Not Found"}`. OAuth endpoints answer RFC 6749
  error objects instead.
- Logger redaction (a security control): `authorization`, `cookie`, `set-cookie` headers + body `password/token/code/code_verifier/refresh_token/access_token/id_token/client_secret/secret` → `[REDACTED]`. pgx query logging OFF.
- **Startup fail-fast.**
  - Required env is asserted, and `NODE_ENV` is checked against an allowlist.
  - Retired variables (`COOKIE_DOMAIN`, `JWT_API_AUDIENCE`,
    `JWT_REFRESH_EXPIRES_DAYS`) are refused with what replaced them.
  - In production: placeholder secrets are rejected (`change-this`, `your-`,
    `placeholder`, `todo`, `changeme`, case-insensitive, on `COOKIE_SECRET`,
    `GOOGLE_CLIENT_SECRET` and `SSO_SECRET_KEY`); `COOKIE_SECRET` must be at least
    32 bytes; the issuer and frontend must be https; `SSO_SECRET_KEY` is required.
  - `\n` becomes a newline in the JWT PEM variables.
- **Response leakage bans:**
  - No response carries a password hash, a token hash, a sealed secret or a
    client secret — except the one response that made it: a product's rotation,
    or an API client's new secret.
  - The session list names users by address and never by id.
  - The refresh response carries no refresh token.
  - Reset and invite responses carry a link only outside production without mail.

### DB-level security DDL (hand-authored)
- Composite tenant foreign keys `(…, client_id)` on every relation that crosses
  a tenant boundary. Among them: sessions, families, grants, memberships,
  invitations and their groups, linked identities, policies, SSO connections and
  domains.
- The audit actor foreign key is `ON DELETE RESTRICT`, and the app role holds
  INSERT only on `tbl_audit_logs`.
- Partial unique `user_email_active_unique (client_id, lower(email)) WHERE deleted_at IS NULL`.
- A company's verified domain is unique across companies. An SSO connection
  domain is unique too, and cannot be another company's verified domain.
- Expression unique `group_name_per_client_unique (client_id, lower(name))`;
  exactly one `ADMINS` group and one default policy per company; a policy's
  priority is unique per company.
- `tbl_platform_owners` can only hold users of the platform company, and the app
  role cannot write it.
- **Scopes:** `tbl_scopes` is the closed catalogue (`kind` `PERSON` or `CLIENT`;
  `feature:level`, lower case), upserted by the build and read-only to the app
  role. Every grant references it by `(scope, kind)` and pins its own kind by a
  CHECK — `tbl_group_scopes` and `tbl_user_scopes` `PERSON`,
  `tbl_api_client_scopes` `CLIENT` — so an unknown scope, or one of the other
  kind, cannot even be stored. An extra has at most one grantor.
- **API clients:** the id is `aci_` + a uuid (CHECK), with exactly one creator of
  its own company or an Owner; its scopes, products and secrets carry the
  composite `(api_client_id, client_id)` key, and a product on its list the
  composite key of the company's subscription (RESTRICT). A secret's prefix is
  `acc_` + 4–12 characters. The app role may UPDATE only `revoked_at` and
  `last_used_at` of a secret, and only the name, description, switch and stamps
  of an API client — never its id or company; `roles.sql` refuses to finish
  otherwise.
- Every constraint and index name fits PostgreSQL's 63 characters (the generator
  refuses a longer one, which would be truncated and break the build's rerun).

---

## 3. Cross-cutting concerns
- **Middleware chain (order is semantic):**
  1. request-id (uuid) and request logger;
  2. recovery;
  3. error handler;
  4. security headers — helmet-style: CSP all `'none'`, HSTS 1y incl.
     subdomains preload **in production only** (D14), COEP require-corp, COOP
     same-origin, CORP same-origin, Referrer no-referrer;
  5. the `/.well-known` CORS responder;
  6. body limit;
  7. global rate limit, excluding the server-to-server OAuth endpoints, which are
     limited per client instead;
  8. the text guard: a path or query holding text PostgreSQL cannot store — a
     NUL character, or bytes that are not UTF-8 — is a 400 `Invalid request`;
  9. under-pressure (memory read at most once a second).

  Per route come the per-route limiters (scaled by `RATE_LIMIT_SCALE`), then:

  | Route group | Guards |
  |---|---|
  | `/auth` | `SameOriginOnly` |
  | `/api` | Authenticate(`app-central`) → RequireFresh (sets `X-Alora-Token-Stale`) |
  | `/api/admin` | RequireScope(`<the route's scope>`) |
  | `/api/owner` | RequireOwner(12 h) |

  The gRPC server (`GRPC_PORT`) runs the same stages as interceptors: request
  id, recovery, log, under-pressure, then the token endpoint's two budgets,
  which are the very limiters `/oauth/*` uses.
- **State.** Federated sign-in state and pending company choices live in
  `tbl_login_states` (single use, expiring). Nothing that sign-in needs is held in
  process, so replicas behind a load balancer are correct. Rate-limit counters are
  per process by default (N replicas grant N× the budget); with
  `RATE_LIMIT_STORE=database` the brute-force-sensitive budgets — password sign-in,
  the token endpoint, failed client authentications and per-account password
  change — share one counter table (`tbl_rate_limit_counters`), so replicas enforce
  one budget together. The shared store fails open: a database error allows the
  request rather than 429-ing the whole fleet.
- **Fire-and-forget audit + email:** goroutine with `context.WithoutCancel` (NOT request ctx) + recover; errors logged, never propagated, never block/500. Audit table append-only.
- **Background jobs:** `time.Ticker` goroutines, started only once the listener is
  bound, eager first run:
  - expire sessions and families past their caps, hourly;
  - expire invitations, every 6 h;
  - clean up codes, hourly;
  - clean up login states, every 15 min.

  They stop on the shutdown signal.

---

## 4. Package layout

The authoritative tree is in
[`alora-auth-api/ARCHITECTURE.md`](alora-auth-api/ARCHITECTURE.md). It is not
duplicated here: the copy that used to live in this section drifted out of date
and had to be deleted, which is what a second copy of a directory listing always
does eventually.

Five layers under `internal/`: `database`, `infrastructure`, `exceptions`,
`middlewares` and `core`. Each feature in `core/` is split into `controller/`,
`service/` and `models/`. The rules that constrain it:

- **All data access goes through `internal/database`, organised by table.**
  Feature services call the table services (`database/services/<table>`, CRUD
  plus `customs/`), never sqlc or the pool, and run transactions through the
  DbContext.
- **Every layer has its own model, and every boundary converts:**
  - table skeletons in `database/models`;
  - DTOs in a feature's `models/dto.go`;
  - request and response models in `models/request.go` and `response.go`.

  A database model is **NEVER** rendered, and a service never sees a request or
  response model.
- `cmd/api/architecture_test.go` enforces all of it, and also:
  - only `internal/core/auth/service` signs tokens;
  - no verification may pass an empty audience;
  - only the Owner controller may build an Owner scope;
  - transports stay at the edges: no service, database or infrastructure code
    imports gin, gRPC or the generated protos, and `core/shared` imports no gRPC;
  - `alora-auth-go` — the protos, their generated code (`authpb`), the Go helper
    (`aloraauth`) and the demo — never imports App Central. The API uses it
    through a `replace`, so a product `go get`s it without App Central's
    dependencies.

---

## 5. Dependency order

Not a checklist any more — the build is done — but the order still holds, and it
is the order to construct things in when adding a feature or standing the system
up from nothing. Each layer may only depend on those above it.

1. **Database objects** — enums, tables, views, then functions and procedures.
   `alora-auth-db/build.sql` applies them in that order.
2. **Generated bindings** — `sqlc generate` reads the database repository, so the
   schema must exist as files before the Go code that binds to it does.
3. **Configuration** — loaded and validated before anything that consumes it,
   which is why a bad value is a startup failure rather than a runtime one.
4. **Database layer** — the DbContext (pool, transactions), the table and view
   skeletons, then the table services over the generated bindings.
5. **Shared primitives** — `exceptions`, then `core/shared`:
   - crypto (tokens, PKCE, password, JWT keys, secretbox — all pure);
   - logger, binding, cookies, `return_to` safety;
   - the actor and scope, and the scope registry (people's and applications').
6. **Infrastructure** — mailer, the OIDC client (Google is a preset of it),
   background jobs.
7. **Middlewares**, in two groups:
   - request id, recovery, errors, security headers, `/.well-known` CORS, body
     limit, rate limit, under-pressure, same-origin;
   - then authenticate → freshness → scope | owner;
   - and the gRPC interceptors, which reuse the same budgets.
8. **Features** — in this order:
   1. audit;
   2. policy;
   3. auth (the only token signer);
   4. session;
   5. login;
   6. oauth;
   7. invitation, reset, user, group, tenant, SSO, apiclient;
   8. owner;
   9. health.

   Within each: models, then service, then controller.
9. **Wiring** — `cmd/api/modules.go`, `main.go` (the router) and `grpc.go` (the
   gRPC server), and the integration tests that exercise both against a real
   database.

The one rule that matters: nothing in `internal/database`,
`internal/infrastructure`, `internal/middlewares` or `internal/core/shared` may
import a feature package. When that inverts, the layering is gone and the next
person cannot reason about what a change touches. `cmd/api/architecture_test.go`
fails the test suite when it does.

---

## 6. sqlc query surface

The authoritative list is `alora-auth-db/api/*.sql`, one file per area. Every
statement is a `CALL stp_…` or a `SELECT … FROM udf_…`; sqlc turns the file set
into one typed `Querier`. The security-relevant properties by file:

- **sessions** — `ByRefreshHashForUpdate` (`FOR UPDATE`, no `revoked_at`
  filter); the family gate (`vw_SessionFamilyGate`: family, parent, user, company,
  product, subscription and access, Admin and Owner flags, auth method, the
  person's `scopes` and both versions); tree revocation; the admin summary (by
  address, no id, no hashes).
- **rbac** — a group's scopes and a person's extras, each replaced wholesale by a
  procedure that looks its target up by `(id, company)` and bumps
  `admin_version` in the same transaction; `vw_EffectiveScope` (each scope with
  its source); the catalogue.
- **group managers** — `tbl_group_managers` (one appointer, never oneself,
  tenant-bound both ways; INSERT and DELETE only for the app role);
  `stp_AddGroupManager` / `stp_RemoveGroupManager` (bump `admin_version`; a
  system group refused); the manager's writes `stp_ManagerAddGroupMember` /
  `stp_ManagerRemoveGroupMember` (the re-check under the group row's lock);
  `udf_IsGroupManager`, `udf_ListManagedGroups`, `udf_ListGroupManagers`;
  `vw_ScopeReach` for rule 2. `stp_DeleteGroup` bumps members and managers
  once each, merged first.
- **oauth** — code claim (`UPDATE … WHERE used_at IS NULL AND unexpired
  RETURNING`); `ByHash` (the replay check); login-state take (single use) and get
  (non-consuming, for the company chooser).
- **users** — login candidates (up to 10 live accounts with a password, joined to
  active companies); identities by address; the tenant-scoped detail (no hash);
  keyset pages; freshness.
- **products / client_products / product_permissions / groups** — the client
  credential (hashed secret), exact redirect URIs, role catalogues; effective
  roles and access (`vw_EffectiveProductRole`, `vw_UserApp`); group grants that
  bump members' `pv`.
- **login policies / SSO** — `vw_UserLoginPolicy` (the resolution order),
  `vw_DomainLoginHint` (discovery by domain), SSO runtime (sealed secret, domains).
- **invitations / reset / audit / platform** — claims as single `UPDATE …
  RETURNING`; the invitation's groups; `InsertAuditLog` (INSERT-only);
  `CreatePlatformOwner` (schema owner only).
- **apiclients** — everything tenant-scoped by `(id, company)` inside the
  routine; secrets made under a row lock (at most two live) and read only
  through `vw_ApiClientSecret`, which has no hash; the client-authentication
  lookup (`vw_OAuthClientCredential`, 0–2 rows per client id); the grant check
  (`vw_ApiClientGrant`: usable now, and the scopes held); the once-a-minute
  last-use stamp.

---

## 7. Decision record

Cited as `SPEC §7` from `ARCHITECTURE.md`. Kept as written when each call was
made — a decision record is worth less once it is edited to look prescient. A
later decision that overrides an earlier one says so; the earlier row stays.

| # | Question | DECISION |
|---|---|---|
| D1 | REUSE_DETECTED nuke rolled back by JS `$transaction` throw (latent bug) | **COMMIT the family-nuke before returning 401.** Required by parity tests; fixes the latent bug. |
| D2 | CSRF token? | **No.** Structural defense only (SameSite=Lax refresh + Bearer on /admin/*). |
| D3 | Cookie signing byte-compat with @fastify/cookie? | **No interop needed** (clean rewrite, no live users). Use a self-consistent HMAC-SHA256(COOKIE_SECRET) scheme, constant-time verify. |
| D4 | JWT lib + key storage | **lestrrat-go/jwx/v2**; RS256 keys stay env PEM (JWT_PRIVATE_KEY/PUBLIC_KEY/KEY_ID). No KMS now. |
| D5 | Argon2 lib | **alexedwards/argon2id** with the exact params; self-consistent round-trip (no node-argon2 interop required). |
| D6 | OAuth state store | **In-memory Map (single instance) now.** Redis deferred until horizontal scaling — flagged, not built. |
| D7 | Router | **Gin** (already chosen). |
| D8 | Trusted proxies | **Env-driven `TRUSTED_PROXIES` allowlist**; default trust-none in dev, set explicit CIDRs in prod. Never trust-all. |
| D9 | under-pressure | Port **heap(500MB)+RSS(600MB)** via runtime.MemStats; event-loop delay = N/A. |
| D10 | Response shape mismatches | (a) **Include** invite_url in POST /admin/invitations response; (b) **Exclude** user_id from /admin/sessions (test oracle). |
| D11 | Stored procs vs inline | **Keep the 3 procs + 1 UDF verbatim and CALL them** (preserve atomicity + enum cast semantics). |
| D12 | Auth-code TTL | **Keep hardcoded 2-min constant.** |
| D14 | HSTS outside production? (D13 is in ARCHITECTURE §10) | **No — production only**, where it is sent exactly as §3 specifies (`max-age=31536000; includeSubDomains; preload`). A browser honours HSTS only over TLS, and a development or staging host served over TLS (a `*.alora.test` proxy) would otherwise be pinned to https, subdomains included, for a year. Pinned by `TestHSTSOnlyInProd`. |
| D15 | One token for every product, or a central login and a token per product? (2026-09) | **Two steps.** App Central's session and token (`aud: app-central`) are for App Central alone; each product gets its own short-lived token (`aud: product:<key>`, its roles only) through the code flow. A token leaked from one product opens nothing else, and a product token opens no admin API. Replaces the v1 token whose audience was `["product:<key>", "alora-auth-api"]`. |
| D16 | CSRF, now that App Central has cookie-bearing POSTs of its own | **Same-origin enforcement** on every state-changing `/auth` request (Fetch Metadata, else Origin), on top of SameSite=Lax and JSON-only bodies. The third layer stops a same-*site* sibling subdomain, which SameSite does not. Supersedes D2. |
| D17 | Where sign-in state lives | **In the database** (`tbl_login_states`), single-use and expiring, bound to the browser by a signed cookie. Supersedes D6: replicas are now correct. |
| D18 | Cookie scope | **Host-only, with `__Host-` in production.** No cookie is shared with any other host, and `COOKIE_DOMAIN` is refused at startup. Products get their own tokens instead of a shared cookie. |
| D19 | Who configures a company's sign-in, groups and product access? | **A platform Owner**, above every company's Admins, through `/api/owner/*`. Owners are made only by `cmd/bootstrap` (the app role cannot write `tbl_platform_owners`). Their writes need a recent sign-in (12 h) and the target-company header, and are audited in both companies. |
| D20 | What makes someone a company Admin? | **Membership of the system group `ADMINS`**, read in the database on every request. Replaces `is_global_admin` and "a product role named Admin". |
| D21 | How do users get products? | **Direct grants ∪ group grants**, from a per-product role catalogue, counting only for an active product, a live subscription and an active company. |
| D22 | How is sign-in chosen per company, group and user? | **Login policies**: user, then highest-priority group, then company default. Enforced at the end of every sign-in path and at every refresh (revoked with `POLICY`). Discovery is by domain, so it reveals no account. |
| D23 | Company SSO | **OpenID Connect first** (SAML reserved). Secrets are sealed with AES-256-GCM. There is no provisioning on first sign-in and no IdP-initiated sign-in. The first link by address needs a listed domain, a verified address (unless trusted) and an existing account. MFA is out of scope for now. |
| D24 | How does App Central launch a product? | **OIDC third-party-initiated login.** App Central opens the product's `initiate_login_uri`, and the product starts its own authorization request. App Central never delivers a code the product did not request, so none can be planted. |
| D25 | Product clients | **All confidential**, since every product has a backend: `client_secret_basic` against a hashed secret, shown once. Rotation retires the old secret at once. Redirect URIs match exactly, and PKCE S256 is required anyway. |
| D26 | A wrong current password on change-password | **403, not 401**, since the token was fine and a client refreshing on 401 would re-send the guess. Throttled per account (5 per 15 min), not per address. |
| D27 | The admin session list, which D10(b) left without a user | **Name each session's user by address.** An admin cannot sensibly revoke a session without knowing whose it is. Still no user id, no token material. |
| D28 | A page that reloads or navigates while its session refresh is in flight | **The SPA's refresh and sign-out are `keepalive` requests.** A dropped response would leave the browser holding a rotated-away cookie, and every later refresh would be a replay. With keepalive the new cookie is stored, and the 409 retry picks it up. |
| D29 | Rate limits behind one egress address | **`RATE_LIMIT_SCALE`** multiplies every fixed per-route budget. Default 1: the budgets as written. |
| D30 | How is what someone may do in App Central expressed? (schema v3) | **Scopes, per feature: read to look, edit to change** (edit includes read), from a closed catalogue in the database (`tbl_scopes`) that every grant references; `apps:read` for everyone, `owner` for Owners. Every admin route names one. Supersedes schema v2's nine delegated feature keys (`users:view` … `client:edit`) and the Admin-only routes; D20 stands, `ADMINS` now meaning every scope. |
| D31 | Who gives scopes, and what stops delegation becoming escalation? | **Groups, plus extras for one person**, given by holders of `groups:edit` / `users:edit` / `invitations:edit` under two rules: nobody gives or takes away a scope they do not hold, and nobody acts on someone with more access than they have. The Owner is exempt from both. Which products a group opens stays the Owner's. |
| D32 | What does the login token say about access? | **Everything about App Central, as a snapshot:** `scope` and `products` (keys only — roles live in each product's own token), with `av`/`pv` for staleness. App Central still decides every request from the database and flags a stale token with `X-Alora-Token-Stale: 1`; the SPA refreshes once and reloads `/api/me`. Amends D15: the login token now carries access, but still opens nothing but App Central. |
| D33 | How do applications — sync jobs, backends, agents — get tokens? | **API clients with client credentials** (RFC 6749 §4.4): a client ID and secret, a product list and one scope list (`api:*`, `grpc:*`, `mcp:tools`). A token names its product with `resource=product:<key>` (RFC 8707), is for that product alone, lives 15 minutes and has no refresh token. Only products the Owner switched to *accept API clients* can be on a list, and every token is checked again. Amends D25: products stay code-flow clients; API clients are a second kind, limited to this grant. |
| D34 | An API client's secrets | **`acc_` + base64url, stored as SHA-256 with a 12-character prefix**, shown once. **At most two live**, so a secret rotates without downtime (make, deploy, revoke). Revoking stamps; the app role cannot rewrite a hash or delete a secret. |
| D35 | One client-authentication path, or one per kind? | **One lookup for both kinds** (`vw_OAuthClientCredential`), compared in constant time against every stored hash or a dummy, with one `invalid_client` for every failure. The kind decides what the client may do only after it has authenticated. |
| D36 | gRPC for applications | **App Central answers `TokenService.GetToken` itself**, through the same service calls as `/oauth/token`, behind interceptors mirroring the HTTP chain and drawing on the same budgets. Plaintext is refused in production at startup (TLS here, or `GRPC_BEHIND_TLS_PROXY`). |
| D37 | Where does the Go helper live? | **Its own module, `alora-auth-go`** (`github.com/prasath-23/Alora-Auth/alora-auth-go`): the protos, the generated code (checked in), the helper and the demo. It never imports App Central; the API uses it through a `replace`. The helper's gRPC interceptors deny every method they have no rule for. |
| D38 | How does a product tell a person's token from an application's, and end an application's early? | **`principal`** (`user` or `client`) on every product token; an application's `sid` is the secret it was issued under, so introspection reports it inactive the moment the secret is revoked, the client is switched off, the product leaves its list or a scope it carries is taken away. |
| D39 | Who runs a group without holding `groups:edit`? | **Its managers**, appointed per group by a `groups:edit` holder who holds everything the group gives (or the Owner). They add and remove its members through their own door, `/api/me/managed-groups`, and nothing else: not its scopes, apps, sign-in policy or managers, nor their own or a fellow manager's membership. Being a manager is not a scope — the database is asked on every call and again inside each write — but it is App Central access, so it is in the login token (`manages`) and bumps `admin_version`. The Admins group never has managers. |
| D40 | What does rule 2 compare? | **Reach**: the scopes a person holds plus those of the groups they manage. A manager can hand those out, so someone below that cannot deactivate, reset, re-scope, regroup or dismiss them; and a manager acting on a member is measured the same way. Reach never grants: it is not in `vw_EffectiveScope` or the session gate. |
| D41 | What does a second press do while the first is still sending? | **Nothing: a button whose request is out is disabled**, whatever else would enable it (`Button` applies `loading` after every other prop). A second press would otherwise make a second of what the first made — a second live API-client secret that is never shown, a second company — or answer a success with a spurious "already exists" or "Not Found". |
| D42 | What happens to an answer that arrives after the person moved on? | **It is dropped if it belongs to a list they have left:** a page asked for under one search that answers after another search began never joins the new list (`UsersPanel`), as `useResource` already drops an earlier load that answers after a later one. |

---

## 8. Project-wide invariants

Numbered and cited from source comments (`SPEC §8`, "global-risk #N"), so the
numbering is fixed. Each one was a real way to get this wrong — several were
found the hard way during the rewrite, where a JavaScript idiom translated into
Go that compiled, ran, and was subtly incorrect.

1. **JWT alg-confusion** — pin RS256 + resolve by kid (reject missing/unknown kid); pin `typ`; require the audience.
2. **base64url vs base64** — codes/reset/state/PKCE use `base64.RawURLEncoding` (unpadded). **Refresh tokens are HEX, not base64url.**
3. **SHA-256 at-rest** — lowercase hex, hash the UTF-8 bytes of the raw token *string*.
4. **Argon2 unit drift** — memory is KiB (19456), `base64.RawStdEncoding` (no pad) in PHC.
5. **Unknown-field rejection** — `json.Decoder.DisallowUnknownFields()`; manually enforce uniqueItems/minProperties:1/slice de-dup.
   **Text the database cannot store** — a NUL character, or bytes that are not UTF-8 — is the caller's 400 wherever it arrives: the path and query (the text guard), a JSON body (`BindJSON`: the body must be UTF-8, which Go's decoder would otherwise repair silently, and no decoded string may hold a NUL), the OAuth form (`invalid_request`), HTTP Basic credentials (`invalid_client`) and gRPC fields (`InvalidArgument`). PostgreSQL's own refusal (22021, 22P05, and 54000 for a value too large for its index) maps to 400 as the backstop, so no such text is ever a 500.
   **A value is judged by the text that will be stored.** A format rule without its length lets a well-formed value of any length through (the `fqdn` rule says nothing of a domain's 253 characters, so the SSO domain list says `max=253` itself), and a URL is judged by its raw text as well as its parse (`shared.AbsoluteURL`): `url.Parse` lower-cases the scheme and leaves the fragment of a lone `#` empty, while the tables' checks read the text. The tables hold the standards' lengths too: a domain at most 253 characters, a provider's subject at most 255.
   **A name is never blank:** one made only of whitespace is refused like no name at all (`notblank`), on every route that names something.
   **A browser's identity is display-only, so it is kept, not judged:** the User-Agent header may carry bytes that are not UTF-8, which HTTP allows, so it is made storable (U+FFFD for such bytes, NULs dropped, cut to 512 bytes at a character boundary) rather than refused — no browser is ever refused sign-in over its name.
   **An identity provider's claims are input.** A subject past OpenID Connect's 255 characters, or one the database cannot store, fails the exchange (`exchange_failed`); an address that is no address — past 320 characters, or holding a NUL — counts as none.
6. **Fire-and-forget goroutines** — `context.Background()`/`WithoutCancel`, NOT request ctx; add `recover()`.
7. **Atomicity/locking** — every single-use redemption is one `UPDATE…RETURNING`; the rotation lookup is `SELECT…FOR UPDATE` inside a transaction (NOT the pool).
8. **409-vs-401 in refresh** — distinguish grace race (409, keep cookie, no burn) from replay (401 + family burn).
9. **Time/timezone** — UTC + timestamptz; push `expires_at>now` into SQL; check `pgtype.*.Valid`, never zero-value.
10. **Integer types** — Prisma `Int` is int32; pgx scans int4; decode JWT `pv` as int not float64; pv default 1.
11. **PG enums** — *(retired in v2: the enum-array column is gone.)* Enum values are cast at the call (`sqlc.arg(...)::"Type"`); compare type names in their exact case (`'IdpProvider'`).
12. **Unique-violation mapping** — `23505` → 409 with exact messages.
13. **permissions_version** — atomic `SET pv = pv + 1`.
14. **Case-insensitive email/domain/group-name** — `lower()` before insert AND in WHERE; escape `%`/`_` in ILIKE.
15. **Cookie Secure flag env-gated**; clear-cookie attrs must exactly match set. **Host-only; `__Host-` in production** (D18).
16. **DEFERRABLE INITIALLY DEFERRED** on the auditlog composite FK — preserve; audit table append-only (never emit ON CONFLICT/UPDATE/DELETE). The single-column actor FK must be **ON DELETE RESTRICT**, never SET NULL: a referential action bypasses the caller's grants, so SET NULL erases the actor from existing rows when a user is deleted.
17. **Every refresh is a fresh decision** — the gate (sessions, user, company, product, subscription, access) and the login policy are re-read at each rotation; nothing is carried over from an earlier token.
18. **A code or token is bound to what it was issued for** — the code to its product, redirect URI, PKCE challenge, nonce and session; a refresh token to its family's kind and product. Presented anywhere else, it is refused before any replay check, so it can never be used to burn someone else's session.
19. **Nobody gives what they do not hold; nobody manages who holds more** — rules 1 and 2 on every path that changes App Central access (a group's scopes, creating and deleting groups, membership, invitations, extras), the Owner alone exempt. A path that forgets one is an escalation.
20. **A token's claims are a snapshot; the database decides** — App Central reads scopes on every request and flags a token whose `av`/`pv` are out of date; nothing is authorised from a claim alone.
21. **One door's rules are the other's** — the HTTP token endpoint and gRPC `TokenService` call the same service methods and share their budgets; a rule added to one is added to both, or the doors drift.
22. **A manager hands out their group and nothing else** — the manager's door opens only on groups the caller manages (asked on every call and again inside the write), never on the group's managers or anyone beyond the manager's reach; and rule 2 everywhere measures by reach, so a manager is never at the mercy of someone who could not run their groups.
23. **No input is a server error** — every route answers hostile input (a malformed or oversized body, a value of the wrong type, text the database cannot store, a strange id, a bad content type or credential) with a client error in the standard shape, and a write racing another (a duplicate, a delete, a limit) with a 404, 409 or 400, never a 500. A check followed by a write never enforces a rule on its own: a lock or a unique index does.
