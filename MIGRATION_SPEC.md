# Alora Auth — Go (Gin + pgx/v5 + sqlc) Migration Spec

> Source of truth for the Fastify → Go rewrite. Produced 2026-06-16 by deep-reading the live
> `alora-auth-api` (43 source files + 14 tests) and `alora-auth-db` (Prisma schema + raw SQL).
> **Stale design notes are overruled by code/tests.** The Fastify `node:test` suite in
> `alora-auth-api/src/__tests__` is the **parity oracle** — every status code, JSON shape, cookie
> flag, crypto param, and error string below is a hard requirement.

---

## 0. Key corrections vs the old design notes
- **15 DB models, not 9** (+`authorization_codes`, +4 RBAC tables, +`password_reset_tokens`).
- **There is no `POST /auth/login`.** Password login is the **OAuth2 authorization-code + PKCE (S256)** flow: `POST /auth/authorize` → `POST /auth/token`.
- **No CSRF plugin / dependency exists.** Defense is structural (SameSite=Lax refresh cookie + Bearer on `/admin/*`).
- **No `__Host-` cookie prefix.** Cookies use an explicit `Domain` attribute for `*.alora.io` SSO.
- **Email delivery is built** (`lib/mailer.js` + nodemailer).

---

## 1. Endpoint inventory

### Public / auth (no Bearer)
| Method | Path | Purpose | Guards | Key responses |
|---|---|---|---|---|
| GET | /health | liveness | logLevel warn | 200 `{status:"ok"}` + helmet headers |
| GET | /health/ready | readiness | — | 200 `{status:"ready"}` (SELECT 1) / 503 `{status:"unavailable"}` |
| GET | /health/pressure | backpressure | under-pressure | 503 when overloaded (heap/RSS only in Go) |
| GET | /auth/jwks | public JWKS | — | 200 `{keys:[{kty,kid,alg:"RS256",use:"sig",n,e}]}`, `Cache-Control: public, max-age=300, must-revalidate`, `Vary: Accept-Encoding` |
| POST | /auth/authorize | password → auth code | per-IP\|email RL (max=10) | 200 `{code}` / 401 `Invalid email or password` / 400 `Invalid request` |
| POST | /auth/token | code+verifier → tokens | RL 20/min | 200 `{access_token,token_type:"Bearer",expires_in:900}` + sets alora_rt, alora_at / 400 / 403 `Account inactive` |
| POST | /auth/refresh | rotation | RL 30/min | 200 token (+new alora_rt, alora_at) / 401 `Session invalid or expired` / 409 `Concurrent rotation — retry` |
| POST | /auth/logout | revoke session | RL 30/min, cookie-only | 204 always (idempotent), clears both cookies |
| POST | /auth/session | admin password login | RL 10/min ip\|lower(email) | 200 token (+cookies) / 401 `Invalid email or password` |
| POST | /auth/reset-password | consume reset token | RL 10/15min | 204 / 400 `Invalid or expired reset token` |
| GET | /auth/accept-invitation/lookup | invite preview | RL 20/15min | 200 invite detail / 400 `Invitation not found, expired, or already used` |
| POST | /auth/accept-invitation | register via invite (EMAIL) | RL 10/15min | 204 / 400 / 409 |
| POST | /auth/accept-invitation/google | register via invite (OAUTH_ONLY) | RL 10/15min | 204 / 400 / 403 / 409 |
| GET | /auth/google | start OAuth | — | 302 to Google, sets alora_oauth_state |
| GET | /auth/google/callback | finish OAuth | — | 302 to product `?code=` OR 302 `?google_error=<code>` OR 400 |

### Admin (`authenticate` → `requireFreshPermissions` → route guard)
| Method | Path | Guard |
|---|---|---|
| GET | /admin/me/features | requireAdmin |
| POST | /admin/me/change-password | requireFreshPermissions (H-1) |
| GET / GET:id / PATCH:id | /admin/users[/:id] | requireFeature(users:view / users:edit) |
| POST | /admin/users/:id/password-reset | requireFeature(passwords:reset) |
| GET:userId / PUT / DELETE | /admin/users/:userId/permissions[/:productId] | requireAdmin |
| GET / DELETE:id | /admin/sessions[/:id] | requireAdmin |
| GET | /admin/products | requireFeature(products:view) |
| GET / PATCH | /admin/client | requireFeature(client:view / client:edit) |
| GET / GET:id / POST / PATCH:id / DELETE:id | /admin/groups[/:id] | requireFeature(groups:view / groups:manage) |
| POST / DELETE:userId | /admin/groups/:id/members | requireFeature(groups:manage) |
| GET / POST / DELETE:id | /admin/invitations[/:id] | requireAdmin |

---

## 2. Security invariants that MUST survive (byte-for-byte)

### Crypto
- **JWT RS256 ONLY.** Header `{alg:"RS256", kid:<activeKid>, typ:"JWT"}`. kid mandatory; missing/unknown kid → reject. Pin algorithm allowlist; reject none/HS256 (**alg-confusion guard**).
- **Claims:** `iss`(=JWT_ISSUER), `iat`, `jti`(uuid v4), `exp`(+15m); `aud` set ONLY when audience provided; verify enforces `aud` ONLY when passed. requiredClaims `[sub,exp,iat,iss]`. clockTolerance **5s**. Private claims: `sub, client_id, email, roles(map[string]string), pv(int), is_global_admin(bool)`. Token-exchange aud = `["product:<key>", apiAudience]` when product.key present, else `apiAudience` ("alora-auth-api").
- **Argon2id EXACT:** type=argon2id, memory=**19456 KiB**, time=**2**, parallelism=**1**, salt 16B, key 32B, v=19. PHC `$argon2id$v=19$m=19456,t=2,p=1$<b64.RawStd salt>$<b64.RawStd hash>`. VerifyPassword swallows all errors → false (never 500). Max password length **512 UTF-16 code units**.
- **Opaque tokens:** refresh = `crypto/rand 32B → hex` (64 chars). auth code & reset token & OAuth state/nonce → **base64.RawURLEncoding** (unpadded). At-rest = `sha256(raw)` **lowercase hex** (unsalted; OK because high-entropy). PKCE = `base64.RawURLEncoding(sha256([]byte(verifier)))`, compared with `subtle.ConstantTimeCompare` after length guard. **S256 only.**
- TTLs: invite **7 days**; reset **60 min**; auth-code **2 min** (hardcoded constant); refresh **7 days**. `expires_in` is a hardcoded literal **900** in all 3 token responses.

### Cookies (NO `__Host-` prefix; `Domain` IS used for SSO)
- `alora_rt`: HttpOnly=true, Secure=isProd, SameSite=Lax, Path=/, Domain=COOKIE_DOMAIN||unset, **Expires=absolute**.
- `alora_at`: **HttpOnly=FALSE** (JS-readable Bearer), Secure=isProd, SameSite=Lax, Path=/, Domain=COOKIE_DOMAIN, **MaxAge=900**.
- `alora_oauth_state`: signed (HMAC over COOKIE_SECRET), HttpOnly, Secure=isProd, SameSite=Lax, Path=/, MaxAge=600. Value=base64url(JSON{state,nonce,productId,redirectUrl,codeChallenge,codeChallengeMethod,clientState}).
- Clear-cookie must replay Path/Secure/SameSite/Domain exactly or the browser won't delete.

### Session rotation (crown jewels)
Runs in a pgx tx with `SELECT ... WHERE refresh_token_hash=$1 FOR UPDATE` (**no `revoked_at` filter** — must match revoked rows). `PREV_TOKEN_GRACE_MS=30000`.
- **Normal rotation:** insert successor (generation+1, prev_token_hash=old hash, family inherited, new session_uuid); update predecessor (revoked_at=now, replaced_by_id=successor; revoked_reason left NULL).
- **Reuse outside grace → family nuke** `UPDATE ... SET revoked_at=now, revoked_reason='REUSE_DETECTED' WHERE family_id=$1 AND revoked_at IS NULL`, then 401. ⚠️ **In Go, COMMIT the nuke before returning the 401** — the JS `$transaction` throw rolls it back (latent bug). Parity tests assert the family IS burned. See Decision D1.
- **Benign grace race → 409**, do NOT clear cookie, do NOT burn family. Two detection paths (revoked-row-with-live-successor; zero-row prev_token_hash fallback with created_at>graceCutoff).
- Refresh cookie length guard: 32..256 inclusive (refresh); ≤256 only (logout).

### Authz / tenant isolation
- RBAC precedence: `is_global_admin` > any **roles map VALUE == "Admin"** (range values, not keys) > group feature membership. requireFeature verifies the **group's own client_id** matches caller tenant.
- requireFreshPermissions: one DB SELECT/request; 401 unless exists AND is_active AND deleted_at IS NULL AND `pv == DB permissions_version`.
- Every admin query scoped by `client_id = request.user.clientId` (never trust body/param client_id). Member-delete scoped by `{user_id, group_id, client_id}`. Group must HAVE ≥1 feature to grant admin-session access. Self-edit guard: PATCH /admin/users/:id where id==caller → 400 `Cannot modify your own account`.
- permissions_version bump = **atomic SQL** `SET permissions_version = permissions_version + 1`.
- Anti-enumeration: unknown email + wrong password → identical 401 `Invalid email or password`; missing-user path still runs argon2 verify against a startup `DUMMY_HASH`.
- Single-use atomicity: auth-code redemption and invite acceptance are **single** `UPDATE ... WHERE <state guard> RETURNING` statements.

### Input / output hygiene
- `additionalProperties:false` everywhere → unknown JSON fields **rejected (400)**, not stripped. Go: `json.Decoder.DisallowUnknownFields()`. Also manually enforce uniqueItems, minProperties:1 (PATCH bodies → 400 on empty), slice de-dup — Gin binding does none of these.
- bodyLimit 65536 bytes. trustProxy → explicit `SetTrustedProxies` allowlist (Gin default trusts all = downgrade).
- Error envelope: ≥500 → `{error:"Internal Server Error", reqId}`; 4xx → `{error:safeLabel||msg, reqId}`. Rate-limit→429, validation→400, 404 → `{error:"Not Found"}` (no reqId).
- Logger redaction (a security control): `authorization`, `cookie`, `set-cookie` headers + body `password/token/code/code_verifier/refresh_token` → `[REDACTED]`. pgx query logging OFF.
- Startup fail-fast: required env; prod placeholder-secret rejection (`change-this`,`your-`,`placeholder`,`TODO`,`CHANGEME` ci on COOKIE_SECRET + GOOGLE_CLIENT_SECRET); COOKIE_SECRET ≥32 bytes; `\n`→newline on JWT PEM env vars.
- Response leakage bans: /admin/users no password_hash/deleted_at; /admin/sessions no refresh_token_hash/revoked_reason/**user_id**; /auth/session body exactly `{access_token,token_type,expires_in}`. Reset responses never include raw token.

### DB-level security DDL (hand-authored; Prisma-inexpressible)
- 4 composite FKs → `tbl_users(id,client_id)`: usersession CASCADE, productpermission CASCADE, **auditlog SET NULL DEFERRABLE INITIALLY DEFERRED**, usergroup CASCADE.
- partial unique `user_email_active_unique (client_id, lower(email)) WHERE deleted_at IS NULL` (+ DROP legacy `tbl_users_client_id_email_key`).
- partial unique `client_domain_normalized_unique (lower(domain)) WHERE domain IS NOT NULL AND domain_verified_at IS NOT NULL`.
- expression unique `group_name_per_client_unique (client_id, lower(name))` (NOT partial).
- UserGroup composite PK `(user_id, group_id)` (no surrogate id).

---

## 3. Cross-cutting concerns
- **Middleware chain (order is semantic):** request-id (uuid) → recovery+error-handler → security headers (helmet: CSP all `'none'`, HSTS 1y incl subdomains preload, COEP require-corp, COOP same-origin, CORP same-origin, Referrer no-referrer, X-Permitted none) → **CORS** (dynamic, DB-backed; after DB available) → cookie parse/verify → rate-limit (skippable) → under-pressure (skippable). **No CSRF.**
- **CORS (fail closed):** no origin → allow; localhost/127.x/[::1] → allow; `*.alora.test` only when !isProd; else must be https AND hostname matches `tbl_clients WHERE domain=$host AND domain_verified_at IS NOT NULL AND is_active=true`. 60s per-origin cache (thread-safe). DB error → deny. Expose `ClearCorsCache()`.
- **Fire-and-forget audit + email:** goroutine with `context.Background()`/`context.WithoutCancel` (NOT request ctx) + recover; errors logged, never propagated, never block/500. Audit table append-only.
- **Background jobs:** `time.Ticker` goroutines started after listen, eager first run; expire-sessions hourly, expire-invitations 6h. Stop via context cancel on SIGINT/SIGTERM.
- **OAuth state store:** in-memory Map is PRIMARY (10-min TTL, one-time delete), signed cookie is fallback/CSRF binding. Process-local → externalize (Redis) only if horizontally scaled (Decision D6).

---

## 4. Proposed Go package layout (package-by-feature)
```
alora-auth-go/
├── cmd/api/main.go                  # load config, jwt.init() once, pool, start jobs after listen, signal shutdown
├── internal/
│   ├── config/config.go             # env load + fail-fast validate, prod placeholder/length guards, \n→newline PEM
│   ├── platform/
│   │   ├── database/{db.go, sqlc/}  # pgxpool + Ping/Close + enum-array codec; GENERATED sqlc (one shared pkg)
│   │   ├── logger/logger.go         # slog, redaction hook, pretty(dev)/json(prod)
│   │   ├── httpx/{errors,requestid,headers,cors,ratelimit,bodylimit,cookies}.go
│   │   ├── jobs/{expire_sessions,expire_invitations}.go
│   │   └── audit/audit.go           # fire-and-forget LogAudit(context.Background(), ...) goroutine+recover
│   ├── crypto/
│   │   ├── tokens/tokens.go         # GenerateRefreshToken(hex), GenerateOpaque(base64url), HashToken(sha256 hex)
│   │   ├── password/password.go     # argon2id PHC encode/decode, DUMMY_HASH, 512 UTF-16 guard
│   │   ├── jwtkeys/{keys,sign,verify,jwks}.go  # kid-keyed RS256, required claims, 5s skew
│   │   └── pkce/pkce.go             # S256 verify (sha256→base64url→ConstantTimeCompare)
│   ├── middleware/{authenticate,fresh,admin,feature,tenant}.go  # + ADMIN_FEATURES 12-key registry
│   ├── auth/{service,repo}.go       # token-minting: buildTokenPayload, refreshAccessToken
│   ├── oauth/{handler,service,google,state,dto}.go  # THE login path
│   ├── session/{handler,service,repo,cookies,dto}.go  # rotateSession TX
│   ├── invitation/{handler,service,repo,dto}.go
│   ├── reset/{handler,service,repo,dto}.go
│   ├── mailer/mailer.go             # lazy SMTP singleton, Noop when MAIL_HOST empty
│   ├── admin/{users,groups,permissions,sessions,products,client,me, service,repo,dto}.go
│   └── health/handler.go
├── db/
│   ├── migrations/{0001_enums_tables, 0002_extras_initial, 0003_extras_rbac, 0004_procs_udf}.sql
│   └── queries/{products,clients,users,sessions,oauth,invitations,rbac,passwordreset,audit,procs}.sql
└── sqlc.yaml                        # postgresql; uuid→google/uuid.UUID, jsonb→json.RawMessage; one shared db pkg
```
Repos wrap `*Queries` + `*pgxpool.Pool` for `WithTx(tx)`. DTOs (binding tags) and response structs live in each feature's `dto.go` and are **NEVER** the sqlc row structs. Prisma `Int`→`int32`; `DateTime?`→`pgtype.Timestamptz`/`*time.Time` in DTOs; enums→sqlc string constants validated in service.

---

## 5. Build order (dependency-first)
1. `db/migrations` 0001–0004 (enums, 15 tables, extras: composite FKs + partial indexes + DROP legacy idx, then 3 procs + 1 UDF).
2. `sqlc.yaml` + `db/queries/*.sql` → generate shared db package (incl. raw/locking queries + proc/udf wrappers).
3. `internal/config` (env + fail-fast, PEM normalize).
4. `internal/platform/database` (pgxpool + Ping/Close + enum-array codec).
5. `internal/platform/logger` (redaction hook).
6. `internal/crypto/tokens` + `crypto/pkce` (pure).
7. `internal/crypto/password` (argon2id PHC, DUMMY_HASH, 512 guard).
8. `internal/crypto/jwtkeys` (kid-keyed RS256 sign/verify/JWKS; init once).
9. `internal/platform/httpx` (errors, requestid, headers, cors, ratelimit, bodylimit, cookies) + `audit` + `mailer`.
10. `internal/middleware` (authenticate → fresh → admin → feature(key) → tenant; ADMIN_FEATURES 12-key registry).
11. `internal/auth` (token-minting service shared by oauth+session).
12. `internal/session` (rotateSession TX, cookies, /auth/refresh /auth/logout /auth/session).
13. `internal/oauth` (/auth/authorize, /auth/token, /auth/google[/callback], state store). **THE login path.**
14. `internal/invitation` + `internal/reset`.
15. `internal/admin` (users, groups, permissions, sessions, products, client, me).
16. `internal/health` + `cmd/api/main.go` wiring; then port the test oracle as httptest integration tests.

---

## 6. sqlc query surface (named queries by feature)
- **products:** GetProductById; GetProductByIdActive (id,base_url); GetProductKeyById; ListActiveProducts; CreateProduct; UpdateProduct
- **clients:** GetClientById; GetClientByVerifiedActiveDomain (CORS hot path); GetClientForOAuthGate (allowed_idp_providers,is_active); GetClientName; CreateClient; UpdateClient (updated_at=now())
- **users:** GetUserById; GetUserFreshnessById (permissions_version,is_active,deleted_at); **GetActiveUserByLowerEmail** [RAW login: lower(email)=lower($1) AND deleted_at IS NULL AND is_active AND account_type IN ('EMAIL','HYBRID') LIMIT 1]; GetUserTenantScoped; GetUserDetail (joins); ListUsersCursor (keyset, take+1, optional ILIKE); FindOAuthLinkableUser (OAUTH_ONLY); CreateUser; UpdateUserActive; UpdateUserPasswordHash; SoftDeleteUser; **IncrementUserPermissionsVersion** (SET pv = pv + 1); ActiveEmailCheck [:one udf_active_email_check]
- **sessions:** **GetSessionByRefreshHashForUpdate** [RAW FOR UPDATE, no revoked_at filter]; GetSessionById; FindActiveSuccessorById; FindGraceSuccessorByPrevHash (prev_token_hash AND revoked_at IS NULL AND created_at>$2); GetSessionByRefreshHash (logout); CreateSession; CreateSuccessorSession; MarkSessionReplaced; RevokeSession; RevokeAllUserSessions; **RevokeTokenFamily** [:exec CALL sp_revoke_token_family]; ListActiveSessionsForClient (LIMIT 200, projection omits refresh_token_hash/revoked_reason/user_id); GetClientSessionById
- **oauth:** CreateAuthorizationCode (writes state); CreateAuthorizationCodeNoState (google); **ClaimAuthorizationCode** [RAW :one UPDATE SET used_at=now() WHERE code=$1 AND used_at IS NULL AND expires_at>now() RETURNING ...]; GetLinkedIdentity; CreateLinkedIdentity; CleanupExpiredAuthCodes
- **auth(token-mint):** ListActiveProductPermissionsForUser (valid_until guard JOIN products → product_key,role_name)
- **invitations:** FindPendingInviteByEmailClient; CreateInvitation (+nested products); ListInvitationsForClient (LIMIT 100); RevokeInvitation (rowsAffected); ClaimInviteWithAcceptedBy / ClaimInviteRegistration [RAW :one UPDATE ... RETURNING]; SetInviteAcceptedBy; LookupPendingInvite (JOIN client + products); GetPendingInviteMinimal; GetPendingInviteWithIdp
- **invitation_products / client_products / product_permissions / rbac(groups) / passwordreset / audit / procs:** see workflow output; includes UpsertProductPermission (ON CONFLICT), CheckGroupFeatureForUser, AddGroupMember (23505→409), FindValidResetToken, InsertAuditLog (:exec, INSERT-ONLY), CALL sp_* wrappers, HealthCheck SELECT 1.

---

## 7. Resolved decisions (open questions → calls)
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

---

## 8. Global JS→Go landmines (apply project-wide)
1. **JWT alg-confusion** — pin RS256 allowlist + resolve by kid; reject missing/unknown kid.
2. **base64url vs base64** — codes/reset/state/PKCE use `base64.RawURLEncoding` (unpadded). **Refresh tokens are HEX, not base64url.**
3. **SHA-256 at-rest** — lowercase hex, hash the UTF-8 bytes of the raw token *string*.
4. **Argon2 unit drift** — memory is KiB (19456), `base64.RawStdEncoding` (no pad) in PHC.
5. **Unknown-field rejection** — `json.Decoder.DisallowUnknownFields()`; manually enforce uniqueItems/minProperties:1/slice de-dup.
6. **Fire-and-forget goroutines** — `context.Background()`/`WithoutCancel`, NOT request ctx; add `recover()`.
7. **Atomicity/locking** — auth-code redemption + invite acceptance = single `UPDATE...RETURNING`; rotation lookup = `SELECT...FOR UPDATE` inside `Queries.WithTx(tx)` (NOT the pool).
8. **409-vs-401 in refresh** — distinguish grace race (409, keep cookie, no burn) from replay (401 + family burn).
9. **Time/timezone** — UTC + timestamptz; push `expires_at>now` into SQL; check `pgtype.*.Valid`, never zero-value.
10. **Integer types** — Prisma `Int` is int32; pgx scans int4; decode JWT `pv` as int not float64; pv default 1, roles default `{}`.
11. **PG enum array** (`allowed_idp_providers`) — register array type with pgx; exact-case 'GOOGLE' check.
12. **Unique-violation mapping** — `23505` → 409 with exact messages.
13. **permissions_version** — atomic `SET pv = pv + 1`.
14. **Case-insensitive email/domain/group-name** — `lower()` before insert AND in WHERE; escape `%`/`_` in ILIKE.
15. **Cookie Secure flag env-gated**; clear-cookie attrs must exactly match set. **No `__Host-` prefix.**
16. **DEFERRABLE INITIALLY DEFERRED** on auditlog FK — preserve; audit table append-only (never emit ON CONFLICT/UPDATE/DELETE).
