# JUSTIFICATION.md — Construct-Level Audit, Alora Auth Go

## 1. Executive Summary

| Metric | Value |
|---|---|
| Audit units | 12 |
| Files audited | 27 (4 Go crypto/platform pkgs, 3 migrations, 12 query files, 4 build/config, 2 docs) |
| Constructs justified | 447 |
| Constructs found **unjustifiable / dead weight** | 41 |
| **Real optimizations** identified | 96 |
| **Spec violations / doc contradictions** | 58 |
| **Missing hardening** items | 92 |
| **Ranked action items (merged, de-duplicated)** | 78 |
| Adversarial-critic corrections applied | 22 (6 rubber-stamps, 6 missed constructs, 5 wrong claims, 5 confirmed) |

**Build state (verified, not asserted).** Implemented: `internal/config`, `internal/platform/logger`, `internal/platform/database` (+16 generated sqlc files), `internal/crypto/{tokens,pkce,password,jwtkeys}`, `internal/mailer`, 3 migrations, 12 query files. **Empty directories**: `cmd/api`, `internal/platform/{httpx,audit,jobs}`, `internal/middleware`, `internal/{auth,oauth,session,invitation,reset,admin,health}`. `github.com/gin-gonic/gin` is **absent from go.mod**. There is **no parity test suite** — 26 test funcs cover 7 pure packages only. Every HTTP-layer control described in ARCHITECTURE §3/§4 in the present tense is unbuilt.

**Highest-severity conclusions.**
1. `database.New` **cannot succeed against the real schema** — `conn.LoadType("IdpProvider")` resolves via `regtype`, which case-folds; the DDL created the type double-quoted. Every connection fails `AfterConnect`. Latent only because no `main.go` exists.
2. `jwtkeys.Sign` applies the caller claim map **after** the registered claims, so a caller-supplied `exp`/`sub`/`iss` overrides them; combined with the `exp: 0` sentinel gap in `Verify`, this yields a signed, never-expiring token.
3. `GetLinkedIdentity` has no `deleted_at` filter and `SoftDeleteUser` never clears `is_active` → a deprovisioned user signs back in via Google.
4. `buildMIME` concatenates tenant-controlled `clientName` into `Subject:` with no CRLF sanitisation → email header injection under your DKIM signature.
5. `isProd := env == "production"` fails **open**: a typo or unset `NODE_ENV` disables Secure cookies, the placeholder-secret scan and the 32-byte `COOKIE_SECRET` floor simultaneously.
6. `password.Verify` promises totality (`bool`) but argon2 **panics** on `t=0`, `p=0` or an empty key segment in a stored hash.

---

## 2. Per-File Construct Tables

### 2.1 `internal/config/config.go`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `package config` + "no other pkg reads os.Getenv" doc | 1-5 | Single validated config source (ARCH §6); makes SPEC §2 fail-fast total | Prose-only; add depguard/forbidigo lint or CI grep | Prod secret guards become bypassable by any future pkg |
| imports errors/fmt/os/strconv/strings/time | 7-14 | All six used; zero 3rd-party in boot path | already optimal | Compile error |
| `type Config` + value sub-structs | 16,29-33 | One alloc, no nil sub-struct, mailer gets an immutable copy | Exported mutable `*Config` — a holder can flip `IsProd` at runtime | Compile error at every consumer |
| `Port`/`Host` defaults 3001 / 127.0.0.1 | 17-18,123,150 | Byte-parity w/ Node; matches GOOGLE_REDIRECT_URI; loopback fails closed | No range validation on port; no parse of Host | Unhardened IdP published to LAN if default flipped |
| `Config.Env` | 19,100,151 | Intended 3-state test/dev/prod for skippable middleware | **WRITE-ONLY** — no reader in repo. Delete or wire the test branch | None today |
| `IsProd` / `isProd := env=="production"` | 20,101,152 | Master security switch: Secure cookies, CORS, log fmt, both secret guards | **FAILS OPEN** — allowlist `{development,test,production}` and error otherwise | Session cookies over plaintext HTTP |
| `DatabaseURL` raw os.Getenv | 22,153 | Opaque DSN keeps pool/TLS/search_path params intact | Not in placeholder scan though `.env.example` ships `admin:password@`; assert `sslmode != disable` in prod | No DB; boot Ping fails |
| `FrontendURL` default localhost:5173 | 23,154 | OAuth error redirect + invite/reset email base | **Not required in prod** → 302s real users to localhost; assert https | Empty Location / relative URLs to users |
| `TrustedProxies` + `splitNonEmpty` | 25-27,155,215-226 | D8 / SPEC §2 — Gin default trusts all; nil = trust-none sentinel | No CIDR syntax validation; not required in prod → all IPs collapse to proxy IP | X-Forwarded-For spoof → rate-limit bypass |
| JWT PrivateKeyPEM/PublicKeyPEM/KeyID | 37-39,157-159 | D4 env PEM; kid separate for overlapping rotation | Accepts any string; add `pem.Decode` + priv/pub correspondence | No key material; JWKS empty |
| JWT `Issuer` req / `APIAudience` default | 40-41,160-161 | iss enforced byte-for-byte on verify; audience literal from SPEC §2 | Validate Issuer as absolute https — drift = mass logout | 100% of tokens rejected |
| `AccessTTL` + ParseDuration + `%w` | 42,117-120,162 | SPEC §2 exp +15m; parse once at boot | Desyncs with hardcoded `expires_in:900`; **no sign/zero check** (critic) → already-expired tokens; Node `1d` syntax rejected undocumented | Tokens expired at issue |
| `RefreshTTL` = days×24h, default 7 | 43,127-130,163 | SPEC §2 7d; operator knob unchanged from Node | **Unbounded** — 0 → 0s (total outage), -1 → -24h. Clamp 1..90 | Refresh tokens valid forever |
| `Cookie.Secret` raw getenv | 47,166 | D3 HMAC key for signed `alora_oauth_state` | Store as `[]byte`; require ≥32 *decoded* bytes | Unsigned state → OAuth CSRF / code interception |
| `Cookie.Domain` + ""=host-only | 48,167 | SPEC §0/§2 reject `__Host-`; needed for *.alora.io SSO | Contract is a comment; reject public suffixes; pin leading-dot semantics | SSO breaks across subdomains |
| Google ClientID/Secret/RedirectURI | 51-55,78-80,170-172 | SPEC §1 OAuth is first-class; RedirectURI must not derive from Host header | RedirectURI unvalidated; `GOOGLE_CLIENT_ID` not placeholder-scanned | OAUTH_ONLY users locked out |
| Mail Host/Port/User/Pass/From + ""=disabled | 57-63,131-134,174-180 | ARCH §2 Noop transport; D10(a) invite_url fallback; 587 = IANA submission | No "Host set ⇒ User/Pass set" check → silent 501 on every invite | Invited users unreachable, no error |
| `Secure: os.Getenv("MAIL_PORT")=="465"` | 60,177 | 465 implicit TLS vs 587 STARTTLS branch in mailer | **DEFECT** — `+465`/`0465` parse to 465 but compare false. Use `mailPort == 465` | SMTPS providers unreachable |
| RateLimit Global/AuthorizeIP/Email 100/10/5 | 66-70,135-146,182-186 | SPEC §1 + ARCH §9 credential-stuffing control; email tighter than IP is correct | Unvalidated: 0/negative accepted; no window knob | Unlimited password guessing |
| `requiredEnv` 9 entries + order | 72-82 | Byte-identical set+order to Node — parity oracle; no safe default exists for any | Regroup JWT_ISSUER; **missing** FRONTEND_URL and prod TRUSTED_PROXIES | Empty COOKIE_SECRET → forgeable state cookie |
| `placeholderHints` + prod scan | 84-85,104-111 | SPEC §2 names these exact 5 values on exactly these 2 vars | Extend to DATABASE_URL/JWT_PRIVATE_KEY/MAIL_PASS; anchor `todo`; name the var in the error | `.env.example` verbatim → known secret in prod |
| `len(COOKIE_SECRET) < 32` prod-gated | 112-114 | SPEC §2 ≥32 bytes | Length ≠ entropy; **byte count is LOOSER than Node's UTF-16 count** (critic); no floor outside prod | Brute-forceable HMAC key |
| `Load()` accumulate-then-report | 88-98 | Testable (no os.Exit); reports all missing at once; `==""` treats set-but-empty as missing | Return a typed sentinel so main can exit EX_CONFIG | Zero-valued config discovered by attacker |
| 6 `intEnv` call sites, strict Atoi | 121-146 | SPEC §2 fail-fast; rejects Node's NaN and prefix-parse | Add min/max params — 6 one-line edits close a whole class | Silent zeros on typo (the Node bug) |
| Single keyed composite literal return | 148-187 | No partially-initialised `*Config` can escape | Keyed literal does not catch omitted field; add exhaustruct | Half-built config on early return |
| `getenv(key,def)` | 190-195 | Node `||` semantics; empty==unset for the 5 vars where "" is never valid | Comment the deliberate asymmetry vs raw getenv sites | 5 duplicated inline blocks, drifting semantics |
| `intEnv` body, `%q`, `return 0` | 197-207 | Mirrors getenv; `%q` distinguishes `" 3001"` | Helper is general — a numeric secret would leak to stderr; `return def, err` | Silent-fallback parsing returns |
| `normalizePEM` backtick `\n`→newline | 209-213,157-158 | SPEC §2/§5 — single-line env PEM rehydration; backtick literal is essential | No `pem.Decode` assertion; no `\r\n` normalisation | Service cannot start in any container |

### 2.2 `internal/config/config_test.go`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| internal `package config` | 1-3 | Reaches unexported helpers | Access unused — all tests go via `Load()` | No test binary |
| `setValidEnv` + `t.Setenv` + 34-char secret | 8-20 | `t.Setenv` auto-restores; secret clears the 32 floor | **RESOLVED** — was not hermetic (`PORT=8080 go test` failed). Now clears all 18 optional vars; verified green under a hostile environment | Duplicated setup drift |
| `TestLoadOK` (Port/APIAudience/IsProd) | 22-37 | Pins the 3 parity-critical values | Asserts 3 of ~20; pin Host/RefreshTTL/AccessTTL/rate limits | Silent default drift |
| `TestLoadPEMNewlineNormalization` | 39-49 | Highest-value test: guards backtick-vs-escape trap | Covers only PRIVATE key; add PUBLIC | normalizePEM silently becomes identity |
| `TestLoadMissingRequired` | 51-57 | Pins set-but-empty==missing coupling | Loop `requiredEnv`; assert message names the var | 8 entries could be deleted silently |
| Prod placeholder + short-secret tests | 59-75 | Crafted values isolate exactly one control each | GOOGLE_CLIENT_SECRET arm never exercised; 31/32 boundary unpinned; **no mis-cased NODE_ENV test** | Both prod guards unverified |
| `TestLoadStrictNumericFailFast` | 77-83 | Pins the deliberate divergence from Node `parseInt` | 1 of 6 call sites; no `3001abc`, no range cases | Silent-fallback regression invisible |

### 2.3 `internal/crypto/jwtkeys/jwtkeys.go`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| package-level unexported keys/mu/activeKid/issuer | 5,30-35 | Only compile-enforced encapsulation; priv key can leave only as a signature | Convert to injectable `Keystore` struct | Any pkg could marshal the private key |
| imports context…time | 8-16 | Each load-bearing | already optimal | Compile error |
| `encoding/json` (JWKS marshal) | 11,190 | RFC 7517 `{"keys":[...]}` envelope under our control | already optimal | /auth/jwks unimplementable |
| `google/uuid` | 18,106 | SPEC §2 `jti` uuid v4 | `NewString` wraps `Must` — **unreachable panic on go1.26** (critic); no change needed | No jti / no revocation handle |
| jwa/jwk/jws/jwt (jwx v2.1.7) | 19-22 | Only lib exposing a KeyProvider separating "alg we accept" from "alg claimed" | v2 in maintenance; pin + CI check | golang-jwt reintroduces alg confusion |
| `type keyPair{priv,pub}` | 25-28 | Atomic rotation; concrete `*rsa.*` enforces RS256 at struct level | Add verify-only variant so retired priv keys leave env | Desynced maps → nil-key panic |
| `var mu sync.RWMutex` | 31 | Concurrent map read+write is a fatal runtime error, not a race | `atomic.Pointer` snapshot would make the hot path lock-free | Unrecoverable process abort |
| `keys = map[string]keyPair{}` | 32 | SPEC §2 resolve-by-kid; exact lookup, no candidate trying | No `Retire(kid)` — map only grows, rotation revokes nothing | Try-all-keys → key confusion |
| `activeKid` / `issuer` | 33-34 | Sign with one, verify with many; one issuer source | `issuer` duplicates `config.JWT.Issuer` | Random kid per call; cross-issuer replay |
| `Init(priv,pub,kid,iss) error` | 39 | Maps 1:1 to D4 env vars; PEM strings, no FS access; fail-closed | Add `priv.PublicKey.Equal(pub)` self-test | IdP mints nothing, accepts nothing |
| `%w` wrapped private/public errors | 42,46 | Names which env var is malformed; startup-only, safe to be verbose | already optimal | Long outage during rotation |
| Single Lock over 3 writes | 48-52 | No torn state; parse before lock = all-or-nothing | Use `defer mu.Unlock()` | Concurrent map write abort |
| `activeKid = kid` unconditional | 50 | Only write to activeKid | **Contradicts its own doc** — registering an old kid makes it the active signer. Split into `RegisterVerifyKey` | No token can be minted |
| `pem.Decode` nil guard | 56-60,72-76 | `block.Bytes` on nil panics; discarding `rest` is correct | Also reject non-empty `rest` and check `block.Type` | nil-deref crash-loop at startup |
| `ParsePKCS8` / `ParsePKIX` | 61,77 | Matches doc + test helper + modern OpenSSL default | Fall back to PKCS1 for legacy `openssl genrsa` | No path from PEM to key |
| comma-ok `*rsa.*` assertions | 65-68,81-84 | First half of the RS256 pin — non-RSA key cannot enter the store | already optimal as a type gate | Panic on ECDSA key; silent total outage |
| Modulus floor + keypair match | 56-86 | jwk's validateRSAKey checks structure, not strength | **RESOLVED** — `Init` rejects under 2048 bits, and rejects a public key that is not the private key's counterpart (otherwise every login succeeds and every request after it 401s) | Weak key published via JWKS, factored → total forgery |
| `Sign(subject,claims,ttl,audience)` | 91 | Mirrors SPEC §2; `[]string` aud for `["product:<key>",api]` | Replace `map[string]any` with a typed struct | No token minting at all |
| RLock snapshot of kp/kid/iss | 92-95 | Consistent triple; lock released before RSA modexp | already optimal | Torn kid/key → self-rejected tokens |
| `if !ok { "not initialized" }` | 96-98 | Fail-closed zero state; avoids nil `kp.priv` deref | already optimal | Panic per request = DoS |
| single `now := time.Now()` | 100 | exp−iat == ttl exactly | already optimal | iat/exp drift, spurious 401s |
| Builder Issuer/Subject/IssuedAt/Expiration | 101-105 | SPEC §2 registered claims via typed NumericDate acceptors | already optimal *encoding*; see ordering defect | Eternal tokens / cross-env replay |
| `JwtID(uuid.NewString())` | 106 | SPEC §2 jti; 122 bits of entropy | Write-only until the audit writer records it | No per-token revocation handle |
| **`for k,v := range claims` placed AFTER** | 107-109 | Attaches private claims — position is the defect | **Move above the registered chain or reject reserved keys** | `claims["exp"]=0` → signed never-expiring token |
| `if len(audience)>0 { Claim(aud) }` | 110-112 | SPEC §2 "aud set ONLY when provided"; avoids `aud: []` | Use typed `b.Audience()` | Cross-product confused deputy |
| `b.Build()` + err check | 113-116 | Only place a bad claim *value* surfaces | already optimal | nil Token deref / silently missing roles |
| `hdrs.Set(kid)`, `Set(typ,"JWT")` | 118-120 | SPEC §2 header shape; `alg` set by jws from the signer so it cannot disagree | Stop discarding `Set` errors | Missing kid = 100% outage; missing typ = RFC 8725 loss |
| `jwt.Sign(..., jwa.RS256, priv, WithProtectedHeaders)` | 122 | Compile-time alg constant; kid inside the signature | already optimal — do not refactor | CVE-class alg confusion / kid swap |
| `string(signed)` | 126 | base64url ASCII, allocation-only | already optimal | Mutable []byte bearer credential |
| `type keyProvider struct{}` value receiver | 131,133 | Zero-sized seam for "we decide key AND alg" | already optimal | WithKeySet consults the token's own alg |
| `FetchKeys(_ ctx, sink, sig, _ msg)` | 133 | Blanks document that ctx and message are deliberately unconsulted | already optimal | Interface unsatisfied |
| `sig.ProtectedHeaders().KeyID()` | 134 | Protected = tamper-evident; public headers are attacker-authored | already optimal | Attacker steers key selection |
| `if kid == "" reject` | 135-137 | SPEC §2/§8.1 mandatory kid; fail closed | already optimal | One `keys[""]` line from accepting unkeyed tokens |
| RLock lookup + `unknown kid` | 138-143 | Exact-match against registered set; kid used only as a map key | Both messages must collapse to a generic 401 | Fatal map abort / nil key DoS |
| `sink.Key(jwa.RS256, kp.pub)` | 144 | **The** alg-confusion guard — verifier built from sink alg, never the header | already optimal | HS256-with-public-key forgery = total bypass |
| `Verify(token, audience string)` | 151 | Singular aud = membership test; returns jwt.Token for typed claims | Empty-audience escape hatch is silent; add `VerifyNoAudience` | Alg pin re-implemented per call site |
| RLock snapshot of issuer | 152-154 | String header read is not atomic; non-nested to avoid recursive RLock deadlock | already optimal | Data race / deadlock |
| `jwt.WithKeyProvider(keyProvider{})` | 157 | Also what makes verification mandatory (parse errors without a key option) | already optimal | `WithVerify(false)` would be total bypass |
| `jwt.WithValidate(true)` | 158 | Intended to enable exp/iat validation | **No-op** — jwx sets `validate=true` before reading options | None |
| `jwt.WithIssuer(iss)` | 159 | Enforces presence *and* exact equality of iss | already optimal | Cross-environment token replay |
| `WithAcceptableSkew(5s)` | 160 | SPEC §2 clockTolerance parity; symmetric on exp and iat | Named const; must not become configurable | Intermittent 401 storms |
| conditional `WithAudience` | 162-164 | SPEC §2 enforce aud only when passed; unconditional would reject audience-less tokens | Preallocate opts cap 5 | Outage on /auth/session, or cross-product crossing |
| `jwt.Parse` + err check | 165-168 | Single entry: format → signature → decode → validate | Add ~8KB length guard; `WithCompactOnly(true)` | Forged tokens accepted if err ignored |
| post-parse recheck sub/exp/iat | 169-171 | Only enforcement of SPEC §2 requiredClaims — jwx returns nil on absent exp | Use `Unix() <= 0`: `exp:0` passes both jwx and `IsZero()` | Eternal token surviving every revocation |
| `\|\| tok.Issuer()==""` clause | 169 | Meant to enforce iss | **Dead** — WithIssuer already rejects; JWT_ISSUER is required | None |
| `JWKS()` + `jwk.NewSet()` + RLock/defer | 176-179 | SPEC §1 key discovery; bytes let the handler set cache headers | Memoise the marshalled bytes; invalidate in Init | Manual key provisioning per product |
| range keys → `jwk.FromRaw(kp.pub)` | 180-184 | Publishes ALL kids for overlapping rotation; **pub only** | Add a test asserting no `d`/`p`/`q` in output | `kp.priv` typo = instant total IdP compromise |
| `Set(kid)`, `use:"sig"`, `alg:RS256` | 185-187 | SPEC §1 JWKS entry shape; propagates the alg pin to consumers | Check the discarded Set errors | Consumers cannot index; alg confusion on their side |
| `AddKey` + `json.Marshal(set)` | 188,190 | RFC 7517 envelope; AddKey error unreachable (pointer identity) | Check anyway — dedup semantics could change | `{"keys":[]}` — nothing verifies |

### 2.4 `internal/crypto/jwtkeys/jwtkeys_test.go`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| internal pkg + jwa/jws/jwt imports | 1-15 | Needed to forge a different-alg token and observe globals | Globals block `t.Parallel()`; order-coupled | Security tests degrade to round-trips |
| `testPEMs` helper, 2048-bit, PKCS8/PKIX | 17-34 | Ephemeral keys, no committed material; mirrors parser expectations | Generate once via `sync.OnceValue`; no rejection-path coverage | Checked-in keypair or no tests |
| `TestSignVerifyRoundTrip` | 36-55 | Claim keys/TTL/audience lifted from SPEC §2 | Never asserts exp/iat/jti/iss/aud or the protected header; `pv` int-vs-float64 untested | Mismatched key or dropped claim ships |
| Wrong-audience / expired tests | 57-77 | Negative TTL isolates expiry cleanly | Assert the specific error; add ±5s skew boundary | Stolen tokens never die |
| `TestVerifyRejectsWrongIssuer` | 79-93 | Re-Init swaps issuer while keeping the key — clean isolation | Leaks `issuer=evil.test` into later tests; add `t.Cleanup` | Cross-environment replay |
| `TestVerifyRejectsAlgConfusion` | 97-120 | Most important test in the repo; known kid so resolution succeeds | Add HS256-keyed-with-**public-key**, alg=none, unknown/missing kid, flipped byte | Alg pin becomes undefended |
| `TestJWKS` (parse, Len ≥ 1) | 122-138 | Confirms a relying party could consume it | Far too weak — assert field set and **absence of `d`/`p`/`q`** | A 6-char typo publishes the private key, suite stays green |
| discarded `Sign` errors | 62,73,85 | Terseness in Verify-focused tests | **Dangerous** — `Sign→("",err)` makes all three negatives pass for the wrong reason | n/a (this is the defect) |
| Missing coverage set | 1-138 | Each maps to a stated §2 invariant | Add unknown/missing kid, tampered payload, absent exp, `exp:0`, parser error branches, `-race` | Half of §2's crypto section asserted only by reading |

### 2.5 `internal/crypto/password/password.go`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `package password` leaf under internal/crypto | 3 | SPEC §4/§5 placement; cannot depend on request/DB ctx → cannot log a plaintext | already optimal | Params drift between login paths |
| imports (rand/hex/errors/sync/utf16/argon2id) | 5-13 | Each load-bearing; **no logging, no ctx, no DB** | Duplicates tokens.GenerateRefreshToken | Compile error |
| `MaxPasswordLength = 512` | 17 | SPEC §2 512 UTF-16 code units; untyped for comparison and tests | No minimum length; 512 is generous vs OWASP | Node parity broken; unbounded absorb |
| `ErrPasswordTooLong` sentinel | 20 | `errors.Is` → 400 not 500; contains no user input | already optimal | 400 becomes 500; envelope violation |
| `var params = &argon2id.Params{…}` | 23-29 | Library needs `*Params`; one definition site; all 5 fields set explicitly | Mutable package pointer; nothing asserts salt/key length | DefaultParams → non-deterministic, parity destroyed |
| `Memory: 19456` | 24 | OWASP-sanctioned m=19456,t=2,p=1; memory-hardness denies GPU parallelism | It is OWASP's floor, not a margin — document a review date | Clamped to 8 KiB → ~2400× cheaper cracking |
| `Iterations: 2` | 25 | Jointly specified with m by OWASP; encoded in PHC | already optimal | **Panics** "number of rounds too small" |
| `Parallelism: 1` | 26 | Part of the byte-for-byte output; reproducible across machines | already optimal | **Panics** "parallelism degree too low" |
| `SaltLength: 16` | 27 | RFC 9106 128-bit; defeats precomputation and cross-user equality inference | already optimal | Empty salt — silent, no test catches it |
| `KeyLength: 32` | 28 | RFC 9106 256-bit tag | already optimal | **nil-deref panic** in blake2b |
| `Hash(plaintext string) (string,error)` | 32 | Returns full PHC → one DB column, future param upgrades | already optimal | No registration / reset / invite accept |
| `if utf16Len > Max` (strict `>`) | 33 | SPEC §2 cap; 512 inclusive matches JS | already optimal | Password settable but never verifiable = lockout |
| `return "", ErrPasswordTooLong` | 34 | Zero value cannot be persisted on the error path | already optimal | Garbage hash stored |
| `argon2id.CreateHash` passthrough | 36 | Delegates salt/derive/PHC (RawStdEncoding, SPEC §8 #4) to the audited lib | Wrap with `%w` | No hash produced |
| `Verify(plaintext,hash) bool` | 46 | Bool-only **is** the enforcement of "never 500"; no err branch to leak | Add `defer recover()` — the signature promises totality the body lacks | Corrupt-hash accounts become an enumeration oracle |
| over-length early return in Verify | 47-49 | Provably correct (Hash rejects >512); timing stays symmetric | Stated DoS rationale is **wrong** — argon2 cost is length-independent | ~35ms wasted, same result |
| `ComparePasswordAndHash` | 50 | Decodes params from the stored hash; `subtle` constant-time compare | Use `CheckHash` → enables rehash-on-login + param ceiling | Timing side channel on the tag |
| `if err != nil { return false }` | 51-53 | SPEC §2 swallow-all-errors; legacy/corrupt hashes → 401 not 500 | **Incomplete** — argon2 panics are not errors | 500 = precise enumeration oracle |
| `return match` | 54 | No branch between compare and return | already optimal | Compile error |
| `utf16Len` | 57-59 | SPEC §2 UTF-16 code units to match JS `String.length` | Allocates ~384 KiB per unauthenticated attempt; rewrite allocation-free with early exit | Silent parity break for CJK/emoji |
| `dummyOnce` / `dummyHash` | 61-64 | Caches the ~35ms cost; `sync.Once` gives the happens-before edge | Use `sync.OnceValue`; empty state is representable | Data race / 35ms per unknown-user login |
| `DummyHash() string` | 70 | SPEC §2 anti-enumeration — equalises the missing-user path | already optimal in shape | Full user enumeration by timing |
| `dummyOnce.Do` | 71 | Exactly one computation under concurrency | **FAIL-OPEN** — `Once` latches even if `f()` panics; Gin Recovery would leave `dummyHash==""` forever | Concurrent first-callers race |
| `make([]byte,32)` | 72 | 256-bit unguessable dummy plaintext | Reuse tokens pkg | Known dummy plaintext |
| `rand.Read` err → panic | 73-75 | Intended entropy fail-fast | **DEAD but KEPT** — go1.26 `rand.Read` never errors, so this cannot fire. Removing it costs signature churn across every caller to delete a zero-cost branch, and re-adds risk if the guarantee is ever narrowed | None |
| `hex.EncodeToString` + **same params** | 76 | Params reuse is what makes timing identical across both paths | already optimal | Timing oracle returns |
| `panic("failed to compute dummy hash")` | 80 | Refuse to serve with the control disabled | Only safe if `Warm()` runs at startup — it has **zero callers** | Returns "" silently → enumeration |
| write inside Do / read outside | 82,84 | Once's release/acquire makes the read race-free | Add post-Do `dummyHash == ""` check | Recompute per call / data race |
| `func Warm()` | 90 | Names the startup obligation; moves cost and panic out of the request path | **Zero call sites**; move into `init()` and delete | First unknown-user login is measurably slower |

### 2.6 `internal/crypto/password/password_test.go`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| internal `package password` | 1 | Can reach `utf16Len`, `params`, the Once | Privilege unused — spend it on a `utf16Len` table test | Unexported internals untestable |
| imports strings/testing | 3-6 | Repeat builds boundary inputs; HasPrefix asserts PHC | Add base64/Split to assert salt=16B, key=32B | Compile error |
| `TestHashVerifyRoundTrip` | 8-23 | Core contract incl. the negative case | Add `Hash(pw)` twice must differ — only cheap catch for SaltLength=0 | Broken Verify ships |
| PHC prefix assertion | 14 | Pins variant + v=19 + m/t/p in one string | Stops at the salt — SaltLength/KeyLength have **zero** coverage; assert no `=` padding | DefaultParams swap goes green |
| `TestTooLong` + boundary | 25-34 | Pins both sides of strict `>` | ASCII-only → cannot distinguish utf16Len from `len()`; use `errors.Is` | Off-by-one ships |
| `TestVerifyMalformedHashIsFalse` | 36-40 | Intends to lock "never 500" | **False confidence** — tests the one safe shape; `t=0`,`p=0`,empty-key all panic | Even the wrong-shape case uncovered |
| `TestDummyHashStableAndInert` | 42-53 | Non-empty, stable, inert | Assert the dummy's PHC prefix equals a real hash's (the timing property); add `-race` | Empty/unstable dummy ships |
| `TestVerifyRejectsOverLength` | 57-65 | Locks the review fix against refactors | Asserts result, not mechanism — passes with the guard deleted | Guard silently removable (already true) |

### 2.7 `internal/crypto/tokens/tokens.go` + `tokens_test.go`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `package tokens` under internal/ | 6 | One owner for the encoding decisions of global-risks #2/#3 | already optimal | Encoding invariant loses its owner |
| `import "crypto/rand"` | 9 | The load-bearing import — math/rand is state-recoverable | Add a repo-wide depguard ban: the swap compiles and passes every test | Full authentication bypass by prediction |
| sha256/hex/base64 imports | 10-12 | hex is lowercase by construction; base64url for URL-borne secrets | already optimal | Compile error |
| `const tokenBytes = 32` | 15 | 256 bits; Node byte-parity so old hashes stay valid; fixes 64-hex/43-b64url lengths | Export `RefreshTokenLen`/`OpaqueLen` — derived lengths are re-typed as magic numbers elsewhere | Guessable refresh tokens |
| `randomBytes(n)` + `make` | 17-18 | Single CSPRNG funnel; `make` pre-sizes because Read fills len | `n` is unused generality; add a `n>=16` floor | Empty tokens = universal bypass |
| `rand.Read` err branch | 19-21 | Claimed defensive propagation | **DEAD but KEPT** — provably unreachable on go1.26. Dropping the error would change three public signatures and every call site to remove an unreachable branch; declined deliberately rather than overlooked | None |
| `return b, nil` unpooled | 22 | No reuse → no entropy sharing between requests | already optimal (do not pool) | Compile error |
| `GenerateRefreshToken` shape | 26,28-30 | Raw returned, hash persisted; `""` on error cannot collide | Rename to `GenerateHex` — the name is why invites call it | Non-empty fallback = universal token |
| `hex.EncodeToString` for refresh | 31 | SPEC §2 wire-format parity; conservative cookie alphabet | Honest: hex buys **zero** security over base64url, costs 21 bytes | Node parity lost |
| `GenerateOpaque` + RawURLEncoding | 36,41 | Genuinely load-bearing: URL-borne secrets must avoid `+`/`/`/`=` | Add per-purpose aliases; no length assertion anywhere | Intermittent "invalid code" failures |
| `HashToken(raw) string` no error | 46 | At-rest form is always computable — no path tempted to store raw | Add an `Equal(raw, stored)` helper | DB dump = live refresh/invite/reset tokens |
| `sha256.Sum256([]byte(raw))` unsalted | 47 | Salt buys nothing for 256-bit inputs and would destroy the unique-index lookups | already optimal | Seq scans + Node hashes stop matching |
| `hex.EncodeToString(sum[:])` | 48 | Canonical single representation; lowercase by construction | already optimal | Total session/invite/reset invalidation |
| `GenerateInviteToken` named results | 53 | Return shape enforces "email raw, persist hash" | No paired helper for reset tokens | Raw invite token stored in plaintext |
| invite calls `GenerateRefreshToken` | 54 | Node wire parity (invites are hex) | **Weakest line** — extract `generateHex()`; couples two protocols | Coupling risk for no benefit |
| error/success returns | 56,58 | Both outputs zeroed on error; hash derived from the same `raw` | already optimal | Dead invite or plaintext secret in the hash column |
| test: internal pkg + hex/regexp | 1-7 | Independent decoder proves output is valid hex | `package tokens_test` would prove API sufficiency | Encoding regressions ship |
| `TestGenerateRefreshTokenIsHex` | 9-20 | Pins 64 chars + hex-decodability | **Never asserts two calls differ** — a constant or math/rand passes | base64 swap undetected |
| `TestHashTokenDeterministic…` KAT | 22-27 | Genuine known-answer vector; pins algo+encoding+case at once | Add a non-ASCII vector | Uppercase/base64/sha512 drift invalidates all hashes |
| `HashToken("abc")!=HashToken("abc")` | 28-30 | Claims purity | Subsumed by the KAT — zero information | None |
| `TestGenerateOpaqueIsBase64URL` regex | 33-41 | Negated class is exactly the base64-vs-base64url discriminator | **No length assertion** — the empty string passes | `+` in a redirect URL → undebuggable failures |
| `TestGenerateInviteTokenHashMatches` | 43-54 | Pins hex form and that hash == HashToken(raw) | Assert `raw != hash`, len(hash)==64, distinctness | Swapped return = dead links + plaintext secrets |

### 2.8 `internal/crypto/pkce/pkce.go` + `pkce_test.go`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `package pkce` + 3 stdlib imports | 2-8 | One implementation; deliberately does **not** share sha256 with tokens (different encodings) | already optimal | Compile error |
| `VerifyS256(verifier, challenge) bool` | 13 | Bool removes err-vs-mismatch as an oracle; name encodes the method | **Param order hazard** — both are 43-char strings; swap = 100% login failure, silent | Stolen code redeemable = ATO |
| empty-input guard | 14 | Claimed fail-closed | Only changes one input pair; **replace** with RFC 7636 §4.1 length/charset guard (43..128) | Narrow false→true case |
| `sha256.Sum256([]byte(verifier))` | 17 | RFC 7636 §4.6; ASCII==UTF-8 for the legal charset; stack-allocated | already optimal | PKCE degrades to `plain` |
| `base64.RawURLEncoding` | 18 | Only conformant encoder; encode-and-compare needs no error path | already optimal | 44 vs 43 chars → **100% of logins fail**, test still green |
| `subtle.ConstantTimeCompare(...)==1` | 19 | Content-independent timing; free length guard (unlike Node's throwing timingSafeEqual) | Constant-time here is defence-in-depth, not the control; **nothing enforces S256 anywhere** | PKCE bypass → account takeover |
| test pkg + crypto imports | 1-7 | Used only to build the expected challenge | **These imports are the defect** — a conformance test needs none | No PKCE coverage |
| Appendix-B verifier + **recomputed** challenge | 11-13 | Verifier is genuine; challenge is not | **Tautological** — switch to StdEncoding and the test still passes. Hardcode `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` | Blind to the highest-probability defect |
| 3 real assertions (valid / wrong-challenge / wrong-verifier) | 15-23 | Catch a `return true` stub, an inverted compare, swapped params | "wrong-challenge" is 15 chars → only the length early-return runs; add a 43-char variant | Full auth bypass ships |
| two empty-input assertions | 24-29 | Claim to pin the line-14 guard | **Both pass with the guard deleted** — vacuous | None |

### 2.9 `internal/platform/logger/logger.go` + test

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| package + doc "replaced wherever it appears" | 1-6 | Isolates the one `ReplaceAttr` wiring; pino parity anchor | Doc **overclaims** — keys only, values are not walked | Control deleted as noise with tests green |
| imports slog/os/strings | 8-12 | `strings` is security-relevant: Go canonicalises `Set-Cookie` | already optimal | Fresh refresh token written to stdout |
| `const censor = "[REDACTED]"` | 14 | SPEC §2 byte-exact sentinel; pino default | already optimal | Expected/actual drift |
| `sensitiveKeys` 8 entries | 17-26 | Each is a live bearer credential in this system; O(1) zero-value map | Add access_token/id_token/client_secret/cookie_secret/pass/password_hash/refresh_token_hash; rule-based suffix match | Credentials in clear to the log aggregator |
| `New(isProd bool) *slog.Logger` | 29 | Keeps platform from importing config (ARCH §1.2) | Accept `io.Writer` (zero coverage today); use `*slog.LevelVar` for §1's per-route warn | Redaction applied inconsistently |
| Debug/Info level split | 30-33 | Bounds prod volume; ARCH §6 pretty-dev | No `LOG_LEVEL`; Debug-in-dev is the riskier half | Unreviewed debug attrs in prod |
| `HandlerOptions{Level, ReplaceAttr: redact}` | 34 | The injection point; covers `With()` and `slog.Group` nesting | `AddSource: !isProd` | **Entire control disappears with the suite still green** |
| JSON/Text split + os.Stdout + `slog.New` | 36-42 | Aggregator-indexable prod, human dev, 12-factor sink | **`slog.SetDefault` never called** — stray `slog.Info` bypasses redaction entirely | Unparseable prod logs |
| `redact(_ []string, a slog.Attr)` | 46 | Blank groups param = matching is depth-independent, stronger than pino's path rules | already optimal — do not make it a path matcher | Compile error |
| `sensitiveKeys[strings.ToLower(a.Key)]` | 47 | Case fold covers canonical header casing and JSON casing | **Value-depth hole**: `slog.Any("body", req)` logs a password in clear | Identity function |
| `slog.String(a.Key, censor)` | 48 | Preserves the log schema; fixed width leaks no length | already optimal | No censoring |
| `return a` pass-through | 50 | Denylist default — fail-closed here would destroy observability | Document that coverage == the 8-key list | Logs useless or empty |
| test: internal pkg | 1 | Targets unexported `redact`/`censor` | Add an external test driving `New()` into a buffer | Compile error |
| test imports | 3-6 | Constructs Attrs in handler shape | already optimal | Compile error |
| `TestRedactCensorsSensitiveKeys` + keys slice | 8-17 | Pins the positive case incl. mixed-case fold | Slice **duplicates** the map by hand — new keys get zero coverage; iterate the map | Inverted condition ships |
| `Value.String() != censor`; non-sensitive test | 13,19-24 | Kind-agnostic; pins the pass-through path | Add `access_token` as a documented known gap | Assertions vacuous |
| **Absent**: any test of `New`, groups, or Attr values | 1-24 | n/a | Add 3 tests incl. a raw-secret-absence assertion | Deleting `ReplaceAttr` keeps CI green |

### 2.10 `internal/platform/database/db.go`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| package + doc (enum-array registration) | 1-3 | SPEC §8 landmine #11 | Doc omits the §2 "pgx query logging OFF" invariant it also upholds | Loses the rationale for the package |
| imports context/fmt/pgx/pgxpool | 5-11 | ctx bounds boot; `*pgx.Conn` for LoadType | already optimal — no ORM keeps §9's parameterisation true | Compile error |
| `enumTypes = {"IdpProvider","_IdpProvider"}` + order | 15-17 | sqlc emits `[]IdpProvider`; array codec needs the scalar registered first | **CANNOT RESOLVE** — LoadType uses `::regtype`, which case-folds; DDL type is double-quoted. Use `LoadTypes` or embed quotes | OAuth gate and client writes fail |
| `New(ctx, url) (*pgxpool.Pool, error)` | 21 | ctx-first; DSN as a string upholds config's monopoly; concrete type per ARCH §5/§7 | Return/document a closer; thread pool options | Callers skip AfterConnect |
| `ParseConfig` + `%w` | 22-25 | Mandatory — AfterConnect can only be set on a Config | Add ConnectTimeout + application_name; note redactPW makes the error safe to log | Codec never registered |
| `cfg.AfterConnect = func(...)` | 27-36 | `pgtype.Map` is per-connection and pgxpool opens lazily forever | 5 round trips/conn → 1 with LoadTypes; consider caching OIDs | Intermittent per-connection failures |
| loop + `LoadType` + `%q` + migrations hint | 28-32 | Ordered dependency; hint targets the likeliest cause | Order is expressed only by slice position | Broken connections served at query time |
| `conn.TypeMap().RegisterType(t)` | 33 | LoadType only constructs; RegisterType installs by OID+name | Pair with `RegisterTypes` | "array element OID not registered" |
| `NewWithConfig` + absent pool tuning | 38-41 | Only constructor accepting AfterConnect; unset Tracer = §2 query logging off | MaxConns=max(4,NumCPU) ceiling; Jitter=0 → hourly reconnect storm; MinConns=0; no ConnectTimeout; assert `Tracer = nil` | No pool |
| `pool.Ping(ctx)` + wrap | 42,44 | NewWithConfig creates resources in a background goroutine and swallows errors — Ping is the only boot-time surfacing of a LoadType failure | Bound with a 5s timeout | Bad revision rolls out fully |
| `pool.Close()` before returning the error | 43 | Avoids leaking the health-check goroutine and sockets per failed boot | already optimal | fd exhaustion under a retrying supervisor |
| `return pool, nil`; **no test file** | 46 | Ownership transfers to main | A single enum-array round-trip test would have caught the boot-breaking defect | Caller gets nothing usable |

### 2.11 `internal/mailer/mailer.go` + test

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| package + doc (no-op → return URL) | 1-4 | ARCH §2 Noop transport; Node parity | **Spec tension** — §2 bans raw reset tokens in responses; narrow to invitations | Callers can't tell nil from delivered |
| imports (tls/net/smtp/strconv/strings/time/config) | 6-16 | Zero third-party | `net/smtp` is **frozen**: no ctx, no timeouts, no SMTPUTF8. 5 stdlib pkgs fix most findings | Compile error |
| `Mailer{cfg}` + `New` | 18-22 | Password in one unexported field; constructor injection | Precompute addr+auth; `pass` not in the redaction set | Config re-read per send |
| `Enabled()` + two guards | 25,28-30,46-48 | Node byte-parity; §3 email must never block/500 | Host-only gate — MAIL_USER/PASS unchecked; Secure derived from the raw env string | CI and dev fail on every invite |
| `Format("2 January 2006[, 15:04]")` | 31,49 | Reproduces `toLocaleDateString('en-GB')` | **No timezone rendered** — misleading on a 60-min reset deadline | Users click stale links |
| From fallback `%q <user>` | 32-35,50-53 | Node parity; name-addr form | `%q` is Go-syntax quoting — accidentally CRLF-safe, wrong for non-ASCII. Use `mail.Address.String()` | Empty From → rejected as spam |
| Subject built by concatenation | 42,81 | Required header | **RESOLVED** — `sanitizeHeader` strips CR/LF/NUL from From, To and Subject. The HTML body was a second route: `clientName` is tenant-controlled and was interpolated raw, so an organisation name could open a link in someone else's inbox under our DKIM signature. Now `html.EscapeString` | Header injection; forged links in invitations |
| HTML bodies by raw concatenation | 38-41,56-59 | multipart/alternative half; inline styles for mail clients | **Phishing vector** — attacker `<a href>` inside DKIM-aligned mail; use `html/template` | Text-only mail |
| `smtp.PlainAuth(...)` unconditional | 66 | PLAIN over TLS; host arg binds the credential to MAIL_HOST | **Non-nil even with empty user** → "server doesn't support AUTH" on MailHog/Postfix. Guard on `User != ""` | 530 on authenticated relays |
| `envelopeFrom := envelopeAddress(...)` | 67 | Reverse-path must be a bare address | **RESOLVED** — was `m.cfg.User`, which on SendGrid is the literal `apikey` and on an empty config sends `MAIL FROM:<>` (the null sender reserved for bounces). Now parsed from the From header, username only as fallback | Rejected mail, or SPF/DMARC misalignment → silent spam-foldering |
| `send()` + JoinHostPort + Secure branch | 63-74 | IPv6-safe; 465 implicit TLS vs 587 STARTTLS is a real protocol difference | STARTTLS is **opportunistic** — a stripping MITM keeps cleartext; fails closed only by PlainAuth accident | 465 deadlocks |
| `buildMIME` + static boundary | 76-92 | Correct RFC 2046 part order and delimiters | **Source-published constant boundary** + attacker-controlled parts = MIME injection. Use `mime/multipart` | Bare body, universally rejected |
| header writes | 79-83 | Minimum renderable set | **Missing mandatory `Date:`**, Message-ID, Content-Transfer-Encoding, RFC 2047 encoding; 998-octet line limit | Deliverability loss on onboarding/recovery mail |
| `sendImplicitTLS` (tls.Dial + NewClient) | 94-102 | ServerName drives SNI **and** cert verification; NewClient marks the session TLS | Pin `MinVersion: TLS12`; **no dial timeout** | No port-465 support |
| `defer c.Close()` + Auth→Mail→Rcpt→Data→Quit | 103-123 | Exact state machine; `validateLine` fails closed on the recipient; `w.Close()` writes the terminating dot | No deadlines; `EHLO localhost` hardcoded; duplicates SendMail | Dropping `w.Close()` = **silent non-delivery** |
| Absent: recipient validation, ctx, timeouts, retry | 27,45,63 | n/a | `mail.ParseAddress`; `SendX(ctx,…)` for §3's WithoutCancel; backoff on 4xx | Goroutine+socket leak per email |
| `TestDisabledIsNoop` | 11-22 | Pins the only spec-named behaviour; zero-value = the prod condition | Add the converse (unreachable host must error) | Live SMTP dials in CI |
| `TestBuildMIMEStructure` | 24-41 | Structural presence checks | Presence-only — cannot fail on any defect found here. Add a CRLF-injection test | MIME regressions ship |

### 2.12 `db/migrations/0001_schema.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `CREATE EXTENSION pgcrypto` | 14 | Claimed for `gen_random_uuid()` | **False on PG13+** — core function; only adds a CREATE-privilege requirement | None |
| `SubscriptionStatus` enum | 17 | Closed domain, 4-byte storage | No code reads it; SUSPENDED/CANCELLED are inert | Nothing branches on it |
| `IdpProvider` enum | 18 | Backs the OAuth gate and `(provider, provider_id)`; exact-case per #11 | MICROSOFT/SAML/OIDC unreachable and **permanent** (no DROP VALUE) | Google login path breaks |
| `AccountType` enum | 19 | All three values gate a distinct auth path | already optimal | Typo drops a user out of login silently |
| `SessionRevokedReason` enum | 20 | All five written; the cast is what caught the `::text` bug | already optimal | Misspelled reasons break forensics |
| `InvitationStatus` enum | 21 | The single-use state machine behind every atomic claim | already optimal | Invites replayable |
| Quoted PascalCase type names | 17-21 | Prisma inheritance; must be quoted forever | Rename to snake_case while empty — a proven footgun | Removes a quoting-mistake class |
| `id TEXT DEFAULT gen_random_uuid()::text` ×13 | 26… | App cannot inject ids; SPEC §4/ARCH §5 pin TEXT→Go string | 37 vs 16 bytes; **add `COLLATE "C"`** — keyset ordering is collation-dependent | Every INSERT fails NOT NULL |
| TIMESTAMPTZ everywhere | 29… | D13/global-risk #9 — all expiry math shares one UTC clock | already optimal | Expired credentials accepted by the tz offset |
| `DEFAULT now()` on created/updated/etc. | 35… | Unforgeable server clock; lets INSERTs omit columns | already optimal | NOT NULL violations |
| `updated_at` columns | 36,48,62,136,183 | Replaces Prisma `@updatedAt`; maintained by convention | Add a BEFORE UPDATE trigger — one forgotten SET is invisible | Wrong forensic timestamp |
| clients `name`/`domain`/`domain_verified_at` | 27-29 | domain pair is the CORS control surface; NULL = unverified | Add `CHECK (domain = lower(domain))` + hostname format check | CORS cannot verify → all tenant frontends offline |
| `allowed_idp_providers` **nullable** | 30 | Per-tenant login policy; explicit array cast required | **Only DEFAULT-ed nullable column in the schema** — NULL is an undefined 3rd state. Make NOT NULL | Login-method policy bypass |
| `require_mfa` | 31 | No MFA endpoint, invariant, or control exists | Delete — a toggle that reports success without acting | None (its presence is the risk) |
| `subscription_status` | 32 | Tenant billing state, defaults TRIAL | No login path joins tbl_clients — cancelled tenants keep authenticating | None today |
| `max_seats` / `seat_limit` | 33,93 | Intended entitlement caps | Enforced nowhere | None |
| `is_active` ×4 | 34,46,58,92 | Live/disabled switch on four hot paths; NOT NULL removes 3-valued logic | already optimal | Deactivated employee keeps logging in |
| products `key`/`name`/`description`/`base_url` | 42-45 | `key` becomes the JWT audience and roles-map key; `base_url` is the redirect allowlist | Make `base_url` NOT NULL + https | Open redirect on /auth/authorize |
| `users.client_id NOT NULL` | 54 | Tenant discriminator; half of the composite FK target | already optimal | Total loss of tenant isolation |
| `users.email NOT NULL` | 55 | Login identifier; normalised by `lower()` on write and read | Add `CHECK (email = lower(email))` or use citext | No login possible |
| `password_hash` nullable | 56 | OAUTH_ONLY has none; projected by only 2 queries | Add `CHECK ((account_type='OAUTH_ONLY') = (password_hash IS NULL))` | Password auth removed |
| `account_type` | 57 | Decides which auth paths a user may use | DEFAULT 'EMAIL' is the password-capable value — drop the default | OAUTH_ONLY reachable via password endpoint |
| `is_global_admin DEFAULT false` | 59 | Top of RBAC precedence; deny-by-default | already optimal | Self-service escalation from an invite link |
| `permissions_version DEFAULT 1` | 60 | Instant-revocation counter; int4 per #10 | already optimal | Revocation delayed 15 min |
| `deleted_at` soft delete | 63 | Enables the partial unique index and re-invitation | already optimal | Hard deletes break audit FKs |
| sessions `user_id`/`client_id` | 69-70 | Denormalised client_id is what makes the composite FK possible | already optimal | Logout-all silently no-ops |
| `session_uuid NOT NULL` | 71 | — | **Write-only**; drop with its unique index | None |
| `family_id NOT NULL` | 72 | Blast radius of reuse detection | already optimal | Thief keeps the session, victim logged out |
| `generation DEFAULT 0` | 73 | Backstop against a forked family via the unique index | Add `CHECK (generation >= 0)` | Silent split-brain family |
| `refresh_token_hash NOT NULL` | 74 | sha256-at-rest; lookup key for rotation and logout | `COLLATE "C"` + hex format CHECK | DB read = instant account takeover |
| `prev_token_hash` nullable | 75 | Grace-race path 2 | **NO INDEX** — seq scan inside the rotation transaction under FOR UPDATE | Benign races become family burns |
| `expires_at NOT NULL` ×4 | 76,129,171,208 | Absolute lifetime; NULL would make the row both unredeemable and unsweepable | `CHECK (expires_at > created_at)` | Credentials never expire |
| `revoked_at` / `revoked_reason` nullable | 77-78 | NULL revoked_at = live; NULL reason = normal rotation | already optimal | No revocation at all |
| `ip_address`/`device_label`/`user_agent` | 79-81 | Admin session provenance | `user_agent` is write-only; consider `inet` | Admin cannot identify the attacker's session |
| `last_seen_at DEFAULT now()` | 82 | Intended activity recency | **Never UPDATEd** — permanently == created_at, misleads incident triage | ORDER BY loses its key (behaviour identical) |
| `replaced_by_id` nullable | 84 | Forward pointer for grace-race path 1 | already optimal | More traffic onto the unindexed path 2 |
| client_products cols + `starts_at`/`ends_at` | 90-95 | Entitlement join; ends_at NULL = perpetual | `starts_at` never evaluated — future-dated entitlements are live now | Entitlements never lapse |
| product_permissions cols + valid_from/until | 102-108 | **This table is the JWT roles claim**; role_name is a privilege string | `valid_from` unevaluated; `role_name` unconstrained TEXT while 'Admin' confers admin | Cross-tenant Admin grant |
| actor cols (granted_by/assigned_by/revoked_by/created_by) | 106,134,199,210 | Accountability metadata | **No FKs at all** — 3 of 4 unvalidated while siblings on the same table have FKs; **and no query reads any of them** (critic) | Untrustworthy during investigation |
| linked_identities cols | 115-118 | `provider_id` holds the immutable IdP subject, not the email | `email_verified` is written and never read | Google login breaks; email reassignment = takeover |
| invitations cols | 125-134 | token_hash at rest; status machine guards single use | No partial unique on (client_id, lower(email)) WHERE PENDING; email not lowered on insert | One leaked URL = unlimited accounts |
| invitation_products cols | 141-144 | Pre-granted roles applied at acceptance | `role_name` needs the same constraint as permissions | Invited users land with no entitlements |
| audit_logs cols | 150-156 | actor nullable for pre-auth events; JSONB; request_id correlates | `event_type` unconstrained; no metadata allowlist | No trail; credential stuffing invisible |
| authorization_codes cols | 164-172 | `code` is the secret; challenge NOT NULL; used_at = single use | No client_id — tenant/product binding lives only in the service | Code replay → unlimited tokens |
| `code_challenge_method DEFAULT 'S256'` | 169 | Records the transform | **No CHECK** — `'plain'` is storable. Add it or drop the column | PKCE downgrade reachable |
| groups cols | 179-181 | `client_id` is what requireFeature must verify | already optimal | Cross-tenant feature grant |
| group_features cols | 188-190 | Maps groups to the 12-key registry | Surrogate id is dead — use `PRIMARY KEY (group_id, feature_key)`; `feature_key` unconstrained | Admin tier collapses |
| user_groups composite PK | 195-196,200 | SPEC §2 mandated; turns duplicate adds into 23505→409 | already optimal | Removing a member leaves residual access |
| user_groups `client_id` + `assigned_at` | 197-198 | Second leg of the composite tenant FK | already optimal | Most direct cross-tenant escalation |
| password_reset_tokens cols | 205-209 | The row is the entire trust anchor of a public endpoint | already optimal | Reset link reusable forever |
| UNIQUE products(key) | 216 | Audience/roles-map key must be unambiguous | Consider `lower(key)` | Cross-product authorization bypass |
| UNIQUE users(id, client_id) | 217 | FK target — required by PG for the composite FKs | already optimal | 0002 fails to apply |
| UNIQUE sessions(session_uuid) | 218 | — | **Drop** with the column: an index insert per login and per rotation for nothing | None |
| UNIQUE sessions(refresh_token_hash) | 219 | Crown-jewel lookup; guarantees one token→one session | `COLLATE "C"` | O(n) scan under a row lock |
| UNIQUE sessions(replaced_by_id) | 220 | At most one predecessor per successor; NULLS DISTINCT allows many live rows | already optimal | Ambiguous grace-race decision |
| UNIQUE sessions(family_id, generation) | 221 | DB backstop against a forked family; also serves the burn | Makes the separate family_id index redundant | Surviving branch after a burn |
| UNIQUE client_products(client_id, product_id) | 222 | Business key; serves both entitlement queries | already optimal | Non-deterministic entitlement |
| UNIQUE permissions(user, client, product) | 223 | ON CONFLICT target + hot token-mint path | already optimal | Upsert is a syntax error |
| UNIQUE linked_identities(provider, provider_id) | 224 | One external identity → one local user | already optimal | Account-takeover primitive |
| UNIQUE invitations(token_hash) | 225 | Access path for all five token-keyed queries | already optimal | Inconsistent acceptance |
| UNIQUE invitation_products(invitation, product) | 226 | Dedup + parent-scan path | already optimal | Duplicate grants at acceptance |
| UNIQUE authorization_codes(code) | 227 | Makes the atomic claim exactly-once | already optimal | Code issued for A redeems as B |
| UNIQUE group_features(group_id, feature_key) | 228 | Dedup + group-scoped reads + cascade | Promote to PK, drop the surrogate | Inflated feature arrays; cascade scans |
| UNIQUE reset_tokens(token_hash) | 229 | Sole lookup on a public endpoint | already optimal | Reset applies to the wrong user |
| INDEX users(client_id, email) | 232 | — | **Dead** — every lookup uses `lower(email)` | None |
| INDEX sessions(family_id) | 233 | — | **Redundant** with the (family_id, generation) unique prefix | None |
| INDEX sessions(user_id, client_id) | 234 | Child-side index for the composite FK cascade + logout-all | Overlaps 235; keep for the FK | User delete seq-scans the largest table |
| INDEX sessions(user_id, revoked_at) | 235 | Matches logout-all exactly | Make partial `WHERE revoked_at IS NULL` | Falls back to 234 |
| INDEX sessions(expires_at) | 236 | Hourly sweep | Make partial `WHERE revoked_at IS NULL` | Sweep seq-scans |
| INDEX client_products(client_id, is_active) | 237 | — | **Redundant** with the unique index prefix | None |
| INDEX linked_identities(user_id) | 238 | Supports the CASCADE, not a SELECT | Policy inconsistency vs unindexed FK children | Delete seq-scans |
| INDEX invitations(email, client_id, status) | 239 | Intended for the duplicate guard | **Unusable** — query filters `lower(email)`; wrong leading column | None |
| INDEX invitations(client_id, status, created_at) | 240 | Intended for the admin list | Mis-ordered — reorder to `(client_id, created_at DESC)` | Extra sort |
| INDEX invitations(expires_at, status) | 241 | 6-hourly sweep | Range-before-equality; make partial `WHERE status='PENDING'` | Sweep seq-scans |
| 4× INDEX on audit_logs | 242-245 | Anticipated forensic paths | **None used by any query**; keep actor_user_id for the FK, use BRIN for the timeline; no retention plan | No plan change |
| INDEX auth_codes(product_id) | 246 | Supports a RESTRICT probe that never fires | Drop or apply the policy consistently | Trivial |
| INDEX auth_codes(expires_at) | 247 | Fast-churn cleanup on the login path | already optimal | Sweep competes with claims |
| INDEX group_features(feature_key, group_id) | 248 | Best secondary index here — equality-first, matches requireFeature | already optimal | Every gated request seq-scans |
| INDEX user_groups(user_id, client_id) | 249 | FK cascade coverage | Largely redundant with the PK; **the missing one is `(group_id)`** | Negligible |
| INDEX reset_tokens(user_id, client_id) | 250 | Invalidate-old-tokens before issuing | Better as `(user_id) WHERE used_at IS NULL` | Slow security operation |
| `ON UPDATE CASCADE` ×26 | 253-287 | Cargo-culted Prisma default | Unreachable, and would silently rewrite the append-only audit trail. Use RESTRICT | None |
| `ON DELETE RESTRICT` → clients | 253… | Tenant deletion must be an error, not a silent multi-table wipe | already optimal | One DELETE destroys a tenant's audit trail |
| `ON DELETE CASCADE` → user children | 255,262,266,283,286 | Credential lifetime bounded by account lifetime | already optimal | Orphaned working refresh token |
| client_products CASCADE | 259 | Pure join rows | Unreachable + inconsistent with its RESTRICT siblings | None |
| self-FK `replaced_by_id` SET NULL | 257 | Only viable action for a nullable forward pointer | already optimal | Rotation history erased |
| invitations inviter RESTRICT vs acceptor SET NULL | 269-270 | Deliberate: inviter is accountability, acceptor is the user themselves | Comment the reasoning locally | Insider erases the admission trail |
| audit actor RESTRICT + client RESTRICT | 275-276 | SPEC §2/#16; keeps every audit row attributable | **RESOLVED** — was SET NULL, which let a user deletion rewrite audit rows. A REVOKE does *not* fix it: referential actions run as the referencing table's owner and skip the caller's grants. Now RESTRICT, plus no DELETE grant on `tbl_users`. Migration `0001`; regression tests in `cmd/api/schema_invariants_test.go` | Deleting a user erases their trail |
| auth_codes user_id/product_id RESTRICT | 278-279 | Protects in-flight codes | user_id should be CASCADE — RESTRICT makes user deletes transiently fail | Transient delete failure |
| RESTRICT → products ×4 | 260,264,273,278 | Keeps the token-mint INNER JOIN loss-free | already optimal | One delete revokes access across all tenants silently |
| group_features / user_groups CASCADE | 282,284 | Deleting a group instantly revokes its features | already optimal | Orphans that re-grant on id reuse |
| invitation_products CASCADE | 272 | Offers belong to their invitation | already optimal | Leaked role grants |
| Table creation order + comment | 23-213 | Claimed dependency ordering | Cosmetic — all FKs are added by ALTER; reword | None |

### 2.13 `db/migrations/0002_constraints.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `usersession_user_client_fk` CASCADE | 13-16 | Makes a mis-tenanted session unrepresentable | Add ON UPDATE CASCADE for parity; subsumes the 0001 single-column FK | Tenant B revokes/enumerates tenant A's sessions |
| `productpermission_user_client_fk` CASCADE | 18-21 | Highest value — these rows become the JWT roles claim | Also bind `(client_id, product_id)` to tbl_client_products; drop the subsumed FK | Cross-tenant Admin in a minted token |
| `usergroup_user_client_fk` CASCADE | 23-26 | Blocks cross-tenant membership | **Group side unbound** — add `(group_id, client_id)` → tbl_groups | Tenant B's admin attaches a tenant A user |
| `auditlog_actor_client_fk` NO ACTION DEFERRABLE | 34-38 | SET NULL is impossible (client_id NOT NULL); MATCH SIMPLE + deferral make the delete pass | On PG15+, use column-list SET NULL and drop the hidden coupling | Forged/mis-tenanted audit rows, or undeletable users |
| `passwordreset_user_client_fk` CASCADE | 44-47 | Reset tokens are credential-equivalent | `created_by` still has no FK at all | Cross-tenant account takeover |
| `invitation_inviter_client_fk` RESTRICT | 49-52 | NOT NULL ⇒ always enforced; preserves provenance | Subsumed by the 0001 FK; document that inviters become undeletable | Provenance forgery |
| `invitation_acceptedby_client_fk` NO ACTION DEFERRABLE | 54-58 | Same nullable/NOT NULL mechanism as audit | PG15 column-list SET NULL gives a better error locus | Cross-tenant entitlement theft |
| shared FK target + omitted MATCH/ON UPDATE | 15-56 | Requires the 0001 unique index; MATCH SIMPLE is the semantic the NO ACTION pair depends on | Write `MATCH SIMPLE` explicitly; add ON UPDATE CASCADE | Migration fails 42830; MATCH FULL breaks NULL-actor audit |
| quoted identifiers | 13-58 | No-op for resolution; names are load-bearing for 23505 mapping | Cosmetic | Renaming the indexes breaks the 409 contract |
| `user_email_active_unique (client_id, lower(email)) WHERE deleted_at IS NULL` | 64-66 | Only expressible as an index; enables re-invitation; #14 case folding | **Login has no client_id** so this index cannot serve it; add `COLLATE "C"` | Case-variant duplicate accounts |
| `client_domain_normalized_unique` partial | 69-71 | CORS trust anchor; unverified claims block nobody | `domain IS NOT NULL` is redundant; add a CHECK upstream | Two tenants verified for one domain → CORS bypass |
| `group_name_per_client_unique` (not partial) | 74-75 | Groups carry feature grants; no soft delete exists | already optimal | Shadow group keeps granting after revocation |
| file-level: no BEGIN/COMMIT, no ledger | 1-76 | DDL is transactional; fresh DB | **No migration runner exists in the repo**; wrap and add a ledger | Partial application is undetectable |

### 2.14 `db/migrations/0003_procs.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `CREATE OR REPLACE PROCEDURE sp_revoke_token_family` | 16-20 | D11 CALL; PROCEDURE for transaction control | Transaction control is never used; FUNCTION could return a count. OR REPLACE can't change param types | Reuse detection has no family burn |
| `p_family_id TEXT` | 17 | Column is TEXT; uuid would be `42883` at CREATE | already optimal; note it is intentionally not tenant-scoped | Cannot identify the family |
| `p_revoked_reason TEXT DEFAULT` | 18 | Cast kept in one place | **Default is dead** (caller always passes both) and TEXT **downgrades** sqlc typing vs the call-site pattern. Use the enum type | Runtime 22P02 → family NOT burned |
| `LANGUAGE plpgsql` ×3 | 20-28 | Block structure, dollar quoting | All three bodies are one UPDATE — `LANGUAGE sql` parses at CREATE and is faster | Syntax error |
| `SET revoked_at=NOW(), reason::"SessionRevokedReason"` | 22-24 | One statement = atomic burn; quotes mandatory for the mixed-case type | Cast disappears if the param is typed | 42804 — every reuse call throws |
| `WHERE family_id=$1 AND revoked_at IS NULL` | 25-26 | Family scope + audit fidelity (does not overwrite an earlier revocation) | Note the theoretical deadlock window | Revokes every session in the DB / rewrites history |
| `sp_expire_sessions(p_batch_size INT DEFAULT 500)` | 31-36 | int4→int32 per #10; uniform sweep timestamp | Hygiene, not a security control (reads filter expires_at) | Expired rows keep revoked_at NULL |
| batched `id IN (SELECT … LIMIT)` | 37-41 | Bounds locks and WAL; idempotent | No loop/row count → 500/hour ceiling; no partial index; no SKIP LOCKED | Unbounded lock storm |
| `sp_expire_invitations` | 46-56 | PENDING guard is both idempotency and correctness | **Missing `updated_at = now()`** — violates the file's own invariant; index order wrong | Stale PENDING rows in the admin list |
| `udf_active_email_check(client_id, email)` | 60 | TEXT params match the columns; lower() centralised inside | Caller **must** pass the authenticated tenant or it is an enumeration oracle | 42883 at runtime |
| `RETURNS BOOLEAN LANGUAGE sql STABLE` | 61 | STABLE enables inlining → the partial index is usable; EXISTS never yields NULL | already optimal | VOLATILE = seq scan; IMMUTABLE = stale results |
| `SELECT EXISTS(...)` body | 62-67 | Exactly mirrors the partial unique index predicate | TOCTOU pre-check — the unique index is the real guard | Soft-deleted addresses block re-invitation |
| file-level: no `search_path`, PUBLIC EXECUTE | 16-68 | SECURITY INVOKER default is correct | Add `SET search_path` and `REVOKE EXECUTE FROM PUBLIC` — a mass-revocation primitive is callable by any role | Unauthenticated-adjacent session DoS |

### 2.15 `db/queries/users.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `GetUserById :one SELECT *` | 26-32 | Change-password must read password_hash | Narrow to (id, client_id, password_hash) and rename | No proof of the old password |
| `WHERE id = $1` only | 32 | $1 is the verified JWT sub — self-scoped; freshness asserted separately | Rename `GetSelfUserById` | Arbitrary user's hash to the change-password flow |
| `GetUserFreshnessById` projection | 34-40 | The three conjuncts of SPEC §2 freshness; no secrets | Add `client_id` and assert it equals the JWT claim | Revoked user keeps admin for 15 min |
| its `WHERE id = $1` | 40 | Returning raw values lets Go distinguish disabled/deleted/absent | already optimal | Authorises on a stranger's pv |
| `GetActiveUserByLowerEmail` projection | 47-48 | Login hot path; avoids a second round trip for JWT claims | `is_active` is redundant with the predicate | Second SELECT on the rate-limited path |
| `lower(email)=lower(arg)` | 50 | SPEC §8.14; correct even for legacy rows | **No usable index** — every login seq-scans; add `(lower(email)) WHERE deleted_at IS NULL` | Case-sensitivity login bug |
| `deleted_at IS NULL AND is_active` | 51-52 | Fail-closed in SQL; both filtered and absent rows yield the same 401 | Cosmetic bare-boolean | Disabled user mints tokens |
| `account_type IN ('EMAIL','HYBRID')` | 53 | Allowlist keeps OAUTH_ONLY off the password path | already optimal | NULL hash into the verifier |
| `LIMIT 1` with no ORDER BY / no client_id | 44-54 | Claimed per-tenant uniqueness | **Premise false** — same email may exist in 2 tenants; nondeterministic login, lockout attack. Add ORDER BY or tenant-scope | No functional change |
| `GetUserTenantScoped` projection | 56-61 | SPEC §2 leakage ban: no password_hash, no deleted_at | already optimal | Offline-crackable hash to every admin |
| its WHERE (id, client_id, deleted_at) | 63-65 | Tenant isolation + 404 as anti-enumeration + idempotent delete | already optimal | Cross-tenant read/modify by id |
| `GetUserDetail :many` + 9 `u.*` | 67-83 | LEFT JOIN fan-out forces `:many`; alias required | P×G repetition; use json_agg | `:one` silently drops grants |
| `perm_*` aliases | 84-89 | Prevent sqlc field collisions; product label + validity window | Nullable by construction (correct) | Raw uuids in the UI |
| group columns | 90-92 | Group membership is the third RBAC tier | `ug.group_id AS group_id` is a no-op rename | Admin revokes direct perms, group access remains |
| the two LEFT JOINs + client_id conjuncts | 94-99 | Zero-grant users still return a row; defence in depth over the composite FKs | already optimal | INNER = 404 for new users; no conjunct = cross-tenant disclosure |
| products join (no pin) vs groups join (pinned) | 96-101 | Products are a global catalog; groups are tenant-owned | Go must drop rows with non-NULL id and NULL name | Cross-tenant group name disclosure |
| `WHERE u.id/u.client_id/deleted_at` | 102-104 | Prunes the driving row before any join work | already optimal | Full cross-tenant authorization map |
| `ORDER BY p.key NULLS LAST, g.name NULLS LAST` | 105 | Intended stable UI ordering | **NULLS LAST is the ASC default**; the order isn't even total; Go regroups anyway | None |
| `ListUsersCursor` projection | 107-118 | Same DTO surface as detail; emit_empty_slices gives `[]` | Duplicate struct — one domain type + converters | Bulk hash disclosure |
| `WHERE client_id AND deleted_at IS NULL` | 120-121 | `sqlc.arg` = NOT NULL string; hides soft-deleted members | already optimal | Platform-wide user enumeration |
| narg search + triple `replace` + ESCAPE | 122-125 | One query serves both modes; **backslash must be escaped first**; §8.14 | Pre-escape in Go; `::text` needed for inference | `%` dumps the whole roster |
| keyset guard `(created_at,id) < (…)` | 126-129 | Row-value comparison is the correct keyset primitive under ties | **Half-cursor bug** — guard tests only cur_created; per critic the real effect is *tied rows silently dropped*, not an empty page | Whole cohorts vanish |
| `ORDER BY created_at DESC, id DESC` + `LIMIT arg` | 130-131 | Must mirror the keyset tuple; id is the total-order tiebreaker | **No supporting index** → full sort per page; **no server-side LIMIT cap** (siblings cap at 200/100) | Repeating/vanishing rows; unbounded response |
| `FindOAuthLinkableUser` | 133-144 | `account_type='OAUTH_ONLY'` prevents Google binding to a password account | already optimal — exactly matches the partial index | Google login takes over a password account |
| `CreateUser` column list | 146-159 | Mass-assignment defence — `is_global_admin` is not writable | already optimal | Privilege escalation from a request body |
| `lower(email)`, narg hash, RETURNING * | 153-160 | Normalised storage; NULL hash for OAuth; one round trip; 23505→409 is the real guard | already optimal | Self-inconsistent data; insert-select race |
| `UpdateUserActive :execrows` | 162-169 | Tenant scope on a mutation; 0 rows → 404; explicit updated_at | **Add `deleted_at IS NULL`** — the only tbl_users mutation ignoring soft delete | Cross-tenant enable/disable |
| `UpdateUserPasswordHash :exec` | 171-178 | Minimal blast radius for a credential rotation | `pgtype.Text` contradicts the "always non-null" comment; `:exec` reports success on a 0-row write | Cross-tenant account takeover |
| `SoftDeleteUser :exec` | 180-187 | Avoids cascading away the audit trail; frees the address | `:execrows`; also set `is_active=false`; **must be paired with session revocation + pv bump** | Cross-tenant deletion; audit destroyed |
| `IncrementUserPermissionsVersion :exec` | 189-197 | Atomic SQL avoids the lost-increment race (§8.13) | `:exec` hides a 0-row **fail-open** revocation; add RETURNING | Revocation delayed to token expiry |
| `ActiveEmailCheck` (UDF) | 199-204 | Friendly 409 before attempting the insert; D11 | TOCTOU; the label "anti-enumeration" is backwards | None — 23505 covers it |

### 2.16 `db/queries/sessions.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `GetSessionByRefreshHashForUpdate :one SELECT *` | 20-21 | Nearly every column drives the rotation state machine | already optimal | State machine collapses |
| `WHERE refresh_token_hash = $1` | 22 | Possession proof; unique index; column immutable → stable lock | already optimal | Any known session id rotates |
| `FOR UPDATE`, **no** revoked_at / expires_at filter | 17-23 | Serialises concurrent refreshes; matching a revoked row **is** the replay signal | Add `lock_timeout` — N replays pin N pool connections | Replay silently downgraded; family stays alive |
| `GetSessionById :one` | 26-28 | Generic by-PK loader | One of two byte-identical queries | None |
| `FindActiveSuccessorById` | 33-35 | Grace-race path 1; fetching regardless of revocation is correct | **Duplicate SQL + misleading name** on the crown-jewel path — delete or rename | None |
| `FindGraceSuccessorByPrevHash SELECT *` | 41-43 | Path 2 — the only way to find a successor when the predecessor is gone | **No index on prev_token_hash** → seq scan on the refresh hot path; `pgtype.Text` zero value returns no rows | Benign races → family burns |
| `revoked_at IS NULL AND created_at > $2` | 44-45 | Live successor + bounded 30s window; strict `>` | Compute the cutoff in SQL to remove clock skew | Permanent reuse-detection bypass |
| `ORDER BY created_at DESC LIMIT 1` | 46-47 | Determinism belt over a non-unique column | Add `generation DESC` tiebreak | Nondeterministic at the detection boundary |
| `GetSessionByRefreshHash` (logout) | 49-54 | Minimal projection — no hashes on an unauthenticated path | Collapse into one atomic UPDATE…RETURNING | Token hashes in unauthenticated request memory |
| `CreateSession` 9 columns | 56-66 | Omitting generation/prev_token_hash lets the schema state "login = gen 0" | **No absolute family lifetime** | Login born mid-family |
| `CreateSuccessorSession` 11 columns | 68-80 | gen+1 under the lock; unique index is the fork backstop; new session_uuid | Force `prev_token_hash` non-null — NULL disables grace path 2 | Refresh breaks after one use |
| `MarkSessionReplaced :exec` | 82-89 | Reason left NULL = "rotated normally"; identity comes from the locked row | Force `replaced_by_id` non-null; use `:execrows` | **Two live refresh tokens in one family** |
| `revoked_reason = $3::"SessionRevokedReason"` | 94-97 | Quoted cast is mandatory; enables sqlc typing | Unnamed param → generated field `Column3`; use `sqlc.arg` | Prepare-time failure; forensics lost |
| `RevokeSession` WHERE + `:execrows` | 94-100 | Tenant scope; idempotent; 0→404 | Already-revoked collapses into 404 | Cross-tenant session termination |
| `RevokeAllUserSessions` | 102-110 | user_id alone is safe **because** of the composite FK; exact index match | Comment the FK dependency | Password reset does not recover a compromised account |
| `ListActiveSessionsForClient` projection | 112-116 | SPEC §2 + D10b bans (no hashes, no reason, no user_id) | Consequence: admin cannot attribute the session being revoked | Mass session hijack from one response |
| its WHERE (client_id, revoked_at, expires_at) | 118-120 | Tenant scope + liveness in SQL (§8.9), correct only because of timestamptz | **No client_id-leading index** → seq scan + sort of the largest table | Cross-tenant surveillance + kill list |
| `ORDER BY last_seen_at DESC LIMIT 200` | 121-122 | Newest-activity-first with a hard cap | `last_seen_at` is **never written** → misinformation; 200-row cap enables session hiding | Unbounded response |
| `GetClientSessionById` | 124-131 | Ownership check + `targetUserId` for the audit; projects user_id deliberately | Not wired in — its raison d'être (already-revoked vs 404) is unrealised | Audit entry with no subject |

### 2.17 `db/queries/oauth.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `CreateAuthorizationCode :one` | 19 | sqlc directive | Downgrade to `:exec` | No Go method |
| INSERT column list | 22-30 | Stores the PKCE challenge and redirect_url for exchange-time re-validation | Hardcode the method column | Code interception; open redirect |
| `code_challenge_method` as `$6` | 27,32 | Persist the method | **Hardcode `'S256'`** — a parameter makes downgrade representable | Downgrade invisible |
| `$1..$8` placeholders | 32 | Extended-protocol binding — the basis of §9's injection claim | Use `sqlc.arg` for readable field names | SQL injection on code/redirect_url |
| `RETURNING *` ×2 | 34,52 | Returns generated id/created_at | Delete — projects the **secret `code`** back for no gain | None |
| `CreateAuthorizationCodeNoState` | 36-52 | Makes "Google stores no state" structural; removes the pgtype.Text footgun | Keep the split | NULL-vs-"" state mixups |
| `ClaimAuthorizationCode :one UPDATE` | 54-59 | Single-use redemption as one statement — no check-then-act window | already optimal | Code replay → duplicate token pairs |
| `WHERE code = $1` | 60 | 256-bit secret; unique index; no constant-time needed | already optimal | Claims every unused code |
| `AND used_at IS NULL` | 61 | EvalPlanQual re-check under READ COMMITTED proves exactly-one-winner | Only valid at READ COMMITTED (else 40001→500) | 2-minute unlimited replay window |
| `AND expires_at > now()` | 62 | Expiry adjudicated by PG, one UTC clock (#9) | already optimal | 2-min credential becomes permanent |
| RETURNING product_id/user_id/redirect_url/challenge/method | 65-69 | The five post-redemption security inputs, read from the burned tuple | **No liveness check on user_id exists anywhere** (critic) — add a token-mint query | PKCE and open-redirect checks impossible |
| RETURNING id/code/state/expires_at | 63-64,70-71 | — | Dead; `code` re-exposes the secret | None |
| `GetLinkedIdentity :one` + JOIN users | 73-84 | Resolves Google `sub` → user; tenant derived from the DB | **Missing `u.deleted_at IS NULL`** — SoftDeleteUser leaves is_active true → deprovisioned user signs back in via SSO | (defect is live today) |
| `WHERE li.provider=$1 AND provider_id=$2` | 83-84 | Enum-typed param enforces exact-case #11; unique index | already optimal | Cross-IdP subject collision → takeover |
| `CreateLinkedIdentity :one` | 86-96 | Binds the external subject; `email_verified` captures Google's claim | `:exec`; `email_verified` is never read | Email-reassignment takeover |
| `CleanupExpiredAuthCodes :execrows` | 98-101 | Bounds a per-login table | **No scheduled caller; unbatched** | None today |

### 2.18 `db/queries/invitations.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `FindPendingInviteByEmailClient :one` | 17-27 | Duplicate-invite guard; token_hash excluded | Add `LIMIT 1` (no uniqueness exists); trim to `id` | Unlimited concurrent live invites |
| `WHERE lower(email) = lower($1)` | 29 | #14 case folding, aligned with the user index | Generated field is named `Lower`; **no index can serve it** | Case-variant duplicate invites |
| `client_id`, `status='PENDING'`, `expires_at>now()` | 30-32 | Tenant scope; liveness independent of the 6h sweeper | **No `c.is_active`** (critic) — suspended tenants keep onboarding | Cross-tenant invite blocking + oracle |
| `CreateInvitation :one` | 35-47 | Pre-computed token_hash — the raw token never reaches SQL | `RETURNING *` drags token_hash into the service layer | No invitations |
| `CreateInvitationProducts :copyfrom` | 50-56 | Bulk insert inside the parent tx | Use the `unnest` INSERT the codebase already uses + an entitlement `EXISTS` guard COPY cannot carry | Invited users get no grants |
| `ListInvitationsForClient` projection | 59-67 | Admin list; omits token_hash and actor columns | Compute effective status — raw PENDING lies for up to 6h | No revocation possible in practice |
| WHERE/ORDER/LIMIT 100 | 68-70 | Tenant scope; newest-first; spec-mandated cap | Index is mis-ordered; no cursor; add an `id DESC` tiebreak | Mass cross-tenant PII leak |
| `RevokeInvitation :execrows` | 73-80 | 404 vs 204 without a preceding SELECT | `revoked_by_user_id` has **no FK** and is nullable | Mis-sent invite stays live 7 days |
| its `WHERE id/client_id/status='PENDING'` | 81-83 | Ownership + one-way state transition in one atomic UPDATE | already optimal | Cross-tenant revocation; audit rewrite |
| `ClaimInviteWithAcceptedBy` | 86-97 | Single-use redemption; correctly not tenant-scoped (possession is the authz) | Merge with the registration variant | One leaked token = unlimited accounts |
| RETURNING id/email/client_id/invited_by | 97,111 | Server-supplied email and tenant — cannot be taken from the body | already optimal | Attacker registers under any email in the tenant |
| `ClaimInviteRegistration` | 100-111 | No user row exists yet to set as acceptor | Delete — pass NULL to the other query | Registration path loses atomicity |
| `SetInviteAcceptedBy :exec` | 114-120 | Backfills the acceptor after the user exists | **Only unguarded UPDATE in the file** — add `status='ACCEPTED' AND accepted_by IS NULL` | Cannot answer "which account did this invite create" |
| `LookupPendingInvite :many` projection | 123-135 | Pre-registration preview; aliases required; enum array typed | already optimal | Blind registration |
| inner JOIN clients vs LEFT JOIN products | 136-139 | Encodes cardinality: tenant always exists, products are 0..N | Go must check `.Valid` or a phantom product renders | Product-less invites vanish |
| `token_hash/status/expires_at` guard | 140-142 | Mirrors the claim guard so preview and redemption never diverge | Add `c.is_active` | Expired token = permanent recon oracle |
| `ORDER BY p.name NULLS LAST, p.key NULLS LAST` | 143 | Deterministic ordering | `NULLS LAST` is the ASC default — no-ops | Varying preview order |
| `GetPendingInviteMinimal :one` | 146-155 | Pre-check for the email accept flow | **Strict subset of the WithIdp variant** — delete | Cannot resolve the invite |
| `GetPendingInviteWithIdp :one` + JOIN | 158-170 | Confirms the tenant permits GOOGLE before creating an OAUTH_ONLY user | Add `c.is_active` | Identity-perimeter policy bypass |
| `ListInvitationProductsByInvitation` | 173-186 | Drives the actual permission grants at accept time | Add `p.key` tiebreak; `ip.id` unused | Accepted users land with zero access |

### 2.19 `db/queries/passwordreset.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `FindValidResetToken :one` projection | 18-29 | The row **is** the tenant assertion on a public endpoint; is_active/deleted_at behind one generic 400 | `u.email` has no consumer on this path | Deprovisioned user regains login |
| inner `JOIN tbl_users` | 31 | FK guarantees the owner exists; one consistent snapshot | already optimal | Race between token and account state |
| `token_hash / used_at IS NULL / expires_at>now()` | 32-34 | Plain `=` on a hex hash (no wildcard surface); single-use; 60-min TTL in SQL | already optimal | Infinitely replayable reset |
| `FOR UPDATE OF t` | 35 | Locks the token row only; EvalPlanQual gives the loser zero rows | **Safety is caller-dependent** — collapse into one CTE `UPDATE…RETURNING` | Check-then-act race: attacker overwrites the user's new password |
| `DeleteUnusedResetTokensForUser :exec` | 37-43 | Invalidates outstanding links before issuing a new one; no client_id needed (user_id is the PK) | Consider marking rather than deleting | Multiple simultaneously usable reset links |
| `CreateResetToken :one` | 45-58 | Hash-only at rest; tenant stored so the public path can derive it | `RETURNING *` re-exposes token_hash; `created_by` has **no FK** and no reader | No admin-initiated reset |
| `MarkResetTokenUsed :exec` | 60-65 | Burns the token after the password change | Fold into the CTE; it has no guard of its own | Every reset token reusable for 60 min |

### 2.20 `db/queries/rbac.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `ListGroupsForClient :many` + `g.client_id=$1` | 18-40 | tbl_groups has no other tenant link | **Only admin list with no LIMIT/keyset** | Cross-tenant RBAC topology dump |
| projection (6 cols) | 22-27 | Maps to the oracle response | `client_id` and `updated_at` are dead | Response-shape parity break |
| `COALESCE(jsonb_agg(...), '[]')::jsonb AS features` | 28-33,53-58 | Avoids features×members fan-out; `[]` not null; deterministic order | already optimal | `null.map()` throws in the UI |
| member_count correlated subquery | 34-37 | Reproduces Prisma `_count`; `ug.client_id=g.client_id` is a second tenant guard | **Counts soft-deleted users** (critic) — join tbl_users with `deleted_at IS NULL`; also needs an index on `(group_id)` | Missing member_count; inflated counts |
| `ORDER BY g.name` | 40 | Matches the oracle | Use `lower(g.name)` to hit the unique index | Flaky ordering |
| `GetGroupDetail` LEFT JOINs | 42-64 | LEFT keeps ≥1 row so 0 rows means 404; client_id re-asserted on both | **No `u.deleted_at IS NULL`** (critic) — soft-deleted emails/user_ids returned | Empty group 404s; cross-tenant member leak |
| `WHERE g.id=$1 AND g.client_id=$2` | 65 | 404 doubles as the IDOR response | already optimal | Cross-tenant group read |
| `ORDER BY u.email` | 66 | Deterministic; NULL placeholder sorts last | Could sort in Go | Nondeterministic member order |
| `GetGroupTenantScoped :one` | 68-73 | The ownership pre-check the two unscoped feature statements depend on | Fold the check into those statements and delete this | Three mutations lose their only tenant guard |
| `CreateGroup` | 75-79 | Unique index gives 23505→409; original case stored, folded uniqueness | already optimal | Racy pre-check |
| `UpdateGroup` | 81-87 | Tenant-scoped; 0 rows → 404 | Full replace nulls omitted fields — use COALESCE(narg) | Cross-tenant rename |
| `DeleteGroup :execrows` | 89-93 | One statement gives 404/204; CASCADE clears both children | Cascade into user_groups has no `group_id` index | Cross-tenant admin lockout |
| **`CheckGroupFeatureForUser`** | 95-106 | SPEC §2 verbatim; `g.client_id=$2` constrains the group itself; EXISTS always returns one bool so err-vs-false cannot be confused; fully indexed | already optimal — **stronger than the Node oracle** | Cross-tenant privilege escalation |
| `ListUserFeatures` DISTINCT | 108-116 | Dedups multi-group grants in SQL; same tenant predicates | Also add a `CheckUserHasAnyFeatureGroup` EXISTS for the §2 login gate | Admin nav cannot render |
| `DeleteGroupFeatures :exec` (no client_id) | 118-122 | Table has no client_id column | **Guard is a comment** — rewrite `USING tbl_groups g … AND g.client_id=$2` | Wipes another tenant's features → admin lockout |
| `CreateGroupFeatures :exec` unnest | 124-129 | One statement; casts needed for sqlc; empty array is a no-op | Same self-scoping rewrite; `feature_key` unconstrained | Cross-tenant privilege grant |
| `AddGroupMember :exec` | 131-136 | Denormalised client_id + composite FK make a cross-tenant **user** impossible; PK gives 23505→409 | **Group side unverified**; `assigned_by` has no FK **and no reader** | Members cannot be added |
| `RemoveGroupMember :execrows` | 138-141 | SPEC §2 {user_id, group_id, client_id}; exact PK probe | already optimal | Evicts members from another tenant's group |

### 2.21 `db/queries/entitlements.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `GetActiveSubscription :one` | 16-26 | Blocks granting a role on an unlicensed product | Add `starts_at <= now()` and a product `is_active` join | Grant Admin on any catalog product |
| `ListClientProductsWithProduct` | 28-49 | The real GET /admin/products; `cp.client_id=$1`; aliases prevent collisions | Docs conflict with products.sql | Cross-tenant subscription roster leak |
| `ListUserPermissionsWithProduct` | 51-72 | Admin view must show expired grants; tenant-scoped | Comment's "future grants" is false (`valid_from` never written); no 404 for a foreign user | Cross-tenant grant read |
| `UpsertProductPermission` ON CONFLICT | 74-87 | Correct arbiter; idempotent PUT in one statement; composite FK blocks escape | Doesn't reset `valid_until`; no updated_at; `granted_by` unFK'd; `role_name` unconstrained | 42P10 — every grant 500s |
| `CheckProductPermissionExists :one` | 89-96 | Claimed 404 pre-check | **Redundant** with the delete's `:execrows`; adds a TOCTOU | None |
| `DeleteProductPermission :execrows` | 98-105 | Revoke; 404/204 | Must share a transaction with the pv bump | Cross-tenant revocation |

### 2.22 `db/queries/products.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| global catalog (no client_id) | 1-19 | `key` is the JWT audience — per-tenant forks would break it | Mutations are unscoped global writes with **no global-admin construct anywhere** | Adding client_id would break the audience model |
| `GetProductById :one SELECT *` | 21-24 | Claimed detail view | No route, no oracle call site — delete | None |
| `GetProductByIdActive` | 26-30 | OAuth issue-time gate; `base_url` is the redirect allowlist | **Add `base_url IS NOT NULL`** — the oracle guards it, this does not | Codes minted for retired products |
| `GetProductKeyById` | 32-35 | Builds `product:<key>` audience | Omitting is_active is deliberate (exchange after deactivation) | Product-scoped audience impossible |
| `ListActiveProducts` | 37-41 | Intended catalog picker | No consumer; unscoped | None |
| `CreateProduct :one` | 43-48 | Seeding; 23505→409 | No endpoint, no authz; `key` unnormalised | Seed via migration only |
| `UpdateProduct :one` | 50-59 | `key` deliberately excluded (baked into live audiences) | **`base_url` mutable** = redirect repoint; full-replace semantics | Catalog uneditable |

### 2.23 `db/queries/clients.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `GetClientById :one SELECT *` | 31-35 | tbl_clients *is* the tenant; safe today (no credential columns) | `SELECT *` widens silently — a future secret column auto-exports | Cross-tenant record read if $1 is body-supplied |
| `GetClientByVerifiedActiveDomain` | 37-47 | Pre-auth CORS decision; partial index usable; only `id` returned | Param named `lower`; no host-normalisation contract | Any origin approved / suspended tenants retain access |
| `domain_verified_at = $5` in UpdateClient | 99 | Domain immutable; only the flag moves | **No proof-of-control** — self-asserted verification enables a permanent squat + CORS for an unowned host | No domain can ever be verified |
| `GetClientForOAuthGate` | 49-55 | Minimal projection; enum array needs the pgx codec | Push `is_active` into the WHERE; `id` is dead | Any tenant driven through any IdP |
| `GetClientName` | 57-60 | Mailer label without the full row | Duplicates one column of GetClientById | Full row decoded on the mailer path |
| `CreateClient` (arg/narg, lower(domain)) | 62-87 | narg preserves NULL so domain-less tenants don't collide; unverified by default | `allowed_idp_providers` uses `arg` on a nullable column → nil writes NULL, overriding the DEFAULT | Second domain-less tenant fails 23505 |
| `UpdateClient` | 89-105 | Single-statement update; explicit updated_at | Full replace; same nil-slice hazard; `subscription_status`/`is_active` are tenant-settable | UPDATE with no WHERE rewrites every tenant |

### 2.24 `db/queries/auth.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| projection `p.key`, `pp.role_name` + JOIN products | 22-26 | These two columns **become** the JWT roles map; INNER is loss-free due to RESTRICT | Add `p.is_active` and a `tbl_client_products` join — neither product deactivation nor a lapsed subscription strips roles | roles={} → all group admins lose access |
| `WHERE pp.user_id=$1 AND pp.client_id=$2` | 27-28 | Tenant isolation on the token-mint path; exact index prefix | already optimal | Cross-tenant 'Admin' injected into a signed JWT |
| `(valid_until IS NULL OR valid_until > now())` | 29 | Time-boxed grants lapse without a sweeper | **Unreachable-false** — no query ever writes valid_until; `valid_from` checked nowhere | Expired grant minted forever |
| no ORDER BY / LIMIT | 22-29 | Rows fold into a map | Bounded by global catalog size — roles claim can bloat a 4 KB cookie | Wasted sort |
| Token-mint identity query | — | n/a (critic) | **ALREADY PRESENT** — `vw_UserIdentity` is that projection: id/client_id/email/is_global_admin/permissions_version, liveness in the view, `password_hash` deliberately excluded. Reached via `udf_GetUserIdentityForToken` | /auth/token would otherwise drag password_hash or lack client_id/email |

### 2.25 `db/queries/audit.sql` + `procs.sql`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `InsertAuditLog :exec` — the only statement | 18-35 | Append-only enforced by *omission*: sqlc generates no UPDATE/DELETE method | Add `REVOKE UPDATE, DELETE` — convention → permission | Attacker with repo access erases their trail |
| column list (client_id … request_id) | 20-26 | Tenant attribution; request_id correlates with logs | `event_type` unconstrained; `event_metadata` unvalidated and unredacted | No attribution during an incident |
| arg/narg split | 28-34 | Mirrors nullability; nullable actor is required for pre-auth events | jsonb override missed the nullable case → `[]byte` not `json.RawMessage` | Failed-login events silently dropped |
| omission of id/created_at | 19-27 | DB stamps the audit timestamp — not app-influenceable | already optimal | Ordering only as trustworthy as the worst clock |
| DEFERRABLE FK coupling | 18-35 | Safe only because the write is its own transaction | Make the audit repo structurally unable to take a tx-bound Queries | Business tx aborts at COMMIT |
| no read query / retention / partitioning | 1-35 | Forensics-only | 4 indexes on the hottest write path for zero in-app reads; no retention (DELETE is banned) | n/a |
| `CALL sp_revoke_token_family($1,$2)` | 14-20 | D11 — keeps the burn atomic and the enum cast in one place | Drop `$2` and rely on the DEFAULT — the string param makes the enum runtime-typed | Stolen family never burned |
| no tenant predicate | 9-11,20 | family_id is read off a row already resolved by the token hash | Add `p_client_id` so a future request-derived call site cannot mass-kill | Safe today only by precondition |
| `CALL sp_expire_sessions/invitations($1)` | 22-30 | Batching caps lock width; both idempotent | pBatchSize 0 → silent permanent no-op; one batch per tick can never drain; no SKIP LOCKED | Lock storm / stale rows |
| `HealthCheck :one SELECT 1` | 32-36 | Forces a protocol round trip, unlike pgxpool.Ping | already optimal | "ready" while the DB refuses queries |
| UDF placed in users.sql | 9-11 | Split by tenancy, not by mechanism | already optimal | Weakens the file's audit invariant |

### 2.26 `sqlc.yaml`, `go.mod`, `.gitignore`, `.env.example`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| `version: "2"` | 1 | Only schema accepting `sql:` + nested overrides | already optimal | Codegen cannot run |
| single `sql:` block | 2-3 | One package → one shared Querier → `WithTx` coherent | already optimal | Rotation tx split across packages |
| `engine: postgresql` | 3 | Needed for RETURNING/FOR UPDATE/CALL/enums/partial indexes | Add a `database:` block to unlock `sqlc vet` | Nothing parses |
| `schema: db/migrations` | 4 | DDL replay builds the nullability catalog behind `pgtype.*` | Numeric filename prefixes are load-bearing | No catalog |
| `queries: db/queries` | 5 | 12 named-query files | already optimal | Only models.go emitted |
| `gen: go:` | 6-7 | Selects the Go backend | already optimal | No output |
| `package: sqlc` | 8 | Matches the leaf dir; no import alias | `db` would read better at call sites | Required key |
| `out: internal/platform/database/sqlc` | 9 | `internal/` makes hash-bearing row structs unimportable externally | already optimal | Row structs publicly importable |
| `sql_package: pgx/v5` | 10 | Gives `WithTx(pgx.Tx)`, pgtype nullables, `:copyfrom` | already optimal | `:copyfrom` rejected; rotation tx impossible |
| `emit_interface: true` | 11 | Claimed for mocking | **Unused** — 42 KB querier.go; ARCH §7 rejects fakes | None |
| `emit_empty_slices: true` | 12 | `[]` not `null` for pass-through rows | DTO layer must re-establish it | `null` breaks empty admin lists |
| `emit_exact_table_names: false` | 13 | Singularisation | **Restates the default** — byte-identical output | None |
| jsonb → `json.RawMessage` override | 14-16 | Prevents base64 strings for the group features array | **Half-applied** — no `nullable: true` twin, so audit metadata is `[]byte` | features arrays base64 → parity break |
| `module github.com/alora/auth` | 1 | Import prefix + `internal/` anchor | Reserve the org path | No build |
| `go 1.26.4` | 3 | Language + toolchain floor | Split into `go 1.26` + `toolchain` — a patch pin forces silent toolchain downloads | go1.16 semantics |
| require argon2id v1.0.0 | 6 | D5 — PHC codec + exact params | Thin wrapper; DefaultParams is a standing footgun | No authentication |
| require google/uuid v1.6.0 | 7 | SPEC §2 jti; §3 request-id | `NewString` panics only on an unreachable path | Predictable jti |
| require pgx/v5 v5.10.0 | 8 | pgxpool, pgtype, pgconn 23505, pgx.Tx, LoadType, CopyFrom | already optimal — pair bumps with regeneration | Data layer does not compile |
| require jwx/v2 v2.1.7 | 9 | D4 — KeyProvider seam, validators, JWKS | Drags 8 transitive modules incl. assembly + unsafe JSON into the token parse path | No tokens |
| **absence of Gin** | 5-10 | Build order — httpx is step 9, main step 16 | go.mod under-declares the stated architecture | Nothing today |
| jwx indirect cluster (8) | 13-23 | All reachable only via jwx/v2/jwk | Not removable while D4 stands; run govulncheck | Build break |
| pgx indirect cluster (3) | 15-17 | .pgpass / pg_service parsing; puddle pool | Note the .pgpass fallback can mask a bad DSN | pgx does not build |
| x/ cluster (4) | 24-27 | argon2, SIMD dispatch, semaphore, SASLprep | Longest CVE history — schedule updates | Hashing/auth break |
| two-block require + `// indirect` | 5-28 | tidy convention; `go mod tidy -diff` is clean | Add the check to CI | Cosmetic |
| `/bin/` | 2 | Root-anchored build output | Nothing writes ./bin; Linux binaries have no extension and are uncovered | Committed binaries |
| `*.exe`, `*.exe~`, `*.dll` | 3-5 | Windows dev host | `*.dll` is impossible (no cgo) — delete | Committed artifacts |
| `*.test`, `*.out` | 6-7 | Test binaries and profiles | `*.out` may swallow golden files | Compiled test binaries with fixtures |
| `.env` / `.env.*` / `!.env.example` | 10-12 | The security-load-bearing rule; negation must come last | **Missing `*.pem *.key *.p12 *.dump *.sql.gz`** — the standard keygen recipe drops the signing key in the repo root | Committing the RS256 key = total IdP compromise |
| `/vendor/` | 15 | Builds from module cache + go.sum | Vendoring would make builds hermetic for an IdP | Unreviewable diffs |
| `.DS_Store`, `.idea/`, `.vscode/` | 18-20 | IDE droppings; .idea can carry DB credentials | Blocks a shareable launch.json | Credential leak via dataSources |
| `*.log` | 23 | Seatbelt behind redaction | already optimal | Bearer tokens in git history |
| generated sqlc **not** ignored | 25 | Builds without sqlc; SQL changes reviewable as Go diffs | No `sqlc diff` in CI; generator version unpinned | Dropped tenant predicates ship unreviewed |
| `.env.example` header contract | 1-3 | Documents the fail-fast rules accurately | **No .env loader exists** — the instruction cannot work | Documentation only |
| `NODE_ENV=development` | 6 | Node parity; gates isProd | Ships the insecure side of three controls; allowlist the value | Same default in code |
| `PORT=3001` | 7 | Matches the code default and the redirect URI | already optimal | Code default |
| `HOST=127.0.0.1` | 8 | Loopback — safer than the Node example's 0.0.0.0 | Note containers need 0.0.0.0 | Code default |
| `FRONTEND_URL=localhost:5173` | 9 | Vite dev origin; email link base | Optional + unvalidated → prod emails link to localhost | Code default |
| `TRUSTED_PROXIES=` empty | 10-11 | D8 fail-closed trust-none | `SetTrustedProxies` must be called **unconditionally**; nothing consumes the value | Spoofed IPs → limiter bypass |
| `DATABASE_URL=admin:password@…` | 14 | Working docker-compose default | Ships a credential pair that the prod scan does not cover; use CHANGEME | Required var fails fast (safer) |
| `JWT_PRIVATE_KEY=` / `PUBLIC_KEY=` empty + `\n` note | 16-18 | Required → verbatim copy fails fast; documents normalizePEM | Add a keygen recipe + "never write to a repo file" | Shared signing key across deployments |
| `JWT_KEY_ID=alora-key-1` | 19 | Required; kid is mandatory and drives resolution | Prefer a rotation-friendly convention | Empty kid → nothing verifies |
| `JWT_ISSUER=https://auth.alora.io` | 20 | Required; enforced byte-for-byte on verify | A prod hostname as the dev default makes envs indistinguishable | Startup failure |
| `JWT_API_AUDIENCE=alora-auth-api` | 21 | Matches SPEC §2 literal and the code default | already optimal | Code default |
| `JWT_ACCESS_EXPIRES_IN=15m` | 22 | Feeds AccessTTL | **Tunable input to a value hardcoded twice as 900**; also unvalidated for sign | Consistent default |
| `JWT_REFRESH_EXPIRES_DAYS=7` | 23 | SPEC §2 TTL | Safe to tune; needs a `>0` check | Code default |
| `COOKIE_SECRET=change-this-…` | 25-26 | 53 chars, self-defusing in prod via the hint list | **Live HMAC key in dev/staging** — ship empty and move the guards out of `isProd` | Fails everywhere (safer) |
| `COOKIE_DOMAIN=` empty | 27-28 | Host-only is the only correct dev value | State the cost: any subdomain can set the parent cookie | SSO silently stops |
| `GOOGLE_CLIENT_ID=` / `SECRET=` empty | 30-32 | Required → fail fast; secret is placeholder-scanned | already optimal | Failure at first real login |
| `GOOGLE_REDIRECT_URI=http://…` | 33 | Must byte-match the Google console entry | Assert https + non-localhost in prod | Startup failure |
| `MAIL_HOST=` empty | 35-36 | Selects the Noop path; better than the Node example | Empty in prod silently **changes the API response shape** | Code default |
| `MAIL_PORT=587` | 37 | STARTTLS branch; PlainAuth refuses cleartext | Secure derived from the raw string | Code default |
| `MAIL_USER/PASS/FROM=` empty | 38-40 | Optional while the mailer is inert; user doubles as envelope-from | Empty FROM routes into the header-injection fallback; MAIL_PASS unscanned | Same fallback path |
| `RATE_LIMIT_GLOBAL_MAX=100` | 42-43 | Node parity; strict parsing | Couples to TRUSTED_PROXIES — unset proxies makes this a self-DoS | Code default |
| `RATE_LIMIT_AUTHORIZE_IP/EMAIL 10/5` | 44-45 | Byte-parity; email-keyed bucket survives IP rotation | Only 3 of ~8 route limits are env-exposed | Code defaults |

### 2.27 `ARCHITECTURE.md` + `../SPEC.md`

| Construct | Line | Why | Optimization | If absent |
|---|---|---|---|---|
| ARCH doc-precedence clause | 3-6 | Total order between two overlapping normative docs | Add a verified-against-sha stamp | 16 drifts become unresolvable |
| ARCH stack list | 8-13 | Pins six dependency choices | **Gin is not in go.mod** — mark planned | A later contributor forks the middleware contract |
| P1 package-by-feature | 19-21 | Blast-radius containment; skeleton exists | All six feature dirs are empty; state the shared-logic escape hatch | Drifts to package-by-layer |
| P2 dependency direction | 22-24 | Keeps tenant identity an explicit argument | Not compiler-enforceable — pass a `Principal` | Services read `c.Param("clientId")` |
| P3 thin handlers | 25-26 | One mapping table for status codes | "one service call" too strict for /auth/token | Transaction boundaries leak |
| P4 DTO boundary | 27-29 | Makes the §2 leakage ban a compile error | The SQL projection is the primary control; DTO is the backstop | password_hash / refresh_token_hash serialized |
| P5 fail closed | 30-31 | Names the four decision points | CORS and authz are unbuilt; hoist the "DB error → deny" semantics | DB blip → credentialed cross-origin read |
| P6 compile-checked / test-pinned | 32-33 | sqlc half is true | **Second clause false** — no parity suite exists | Safer without the claim |
| ARCH §2 main.go composition root | 40-42 | Three real ordering constraints | `cmd/api` is empty; **`password.Warm()` missing from the list** | First-request timing oracle |
| §2 internal/config | 44-45 | All four claims verify | Omits strict numeric parsing; length ≠ entropy | Publicly known secret in prod |
| §2 platform/database | 48-49 | Enum-array codec is mandatory | 'Close' overstated; boot-order coupling unstated | Google login path 500s |
| §2 platform/logger | 50-51 | Redaction is a security control | **Overstated** — keys only, not messages or struct values | Refresh tokens in prod logs |
| §2 platform/httpx | 52-53 | Groups eight cross-cutting controls | **Empty directory** — the largest unbuilt surface, written like the built ones | No HTTP layer at all |
| §2 platform/audit | 54 | Detached ctx so audit can't fail a request | `Background()` vs `WithoutCancel` contradiction across 4 sites | Silent gaps in the trail |
| §2 platform/jobs | 55 | Ticker-driven sweeps | Empty; batch size and advisory nature unstated | Stale rows only |
| §2 crypto/tokens | 58 | Implemented and correct | **"others" is wrong — invite tokens are hex** | Invitation links break |
| §2 crypto/password | 59 | Params + DUMMY_HASH + 512 guard | Omits the pre-hash DoS guard; DummyHash panics | Total lockout / 19 MiB amplification |
| §2 crypto/jwtkeys | 60 | kid-keyed RS256, allowlist, skew | No minimum modulus check | HS256 forgery = total bypass |
| §2 crypto/pkce | 61 | Constant-time S256 | Nothing rejects a stored `plain` method | Code interception |
| §2 middleware chain + 12-key registry | 63-64 | Fixed guard order (freshness before role checks) | Empty dir; **only 8 of 12 keys gate any route** | Unauthenticated /admin/* |
| §2 feature packages | 66-74 | `internal/auth` resolves the shared-minting conflict | 7 of 8 empty; mailer shipped out of build order | IdP serves nothing |
| §2 db/migrations + queries | 76-77 | Correct 3-file inventory | 12 query files, not "one per feature"; auth.sql/entitlements.sql unlisted | Codegen errors from a stray 0004 |
| ARCH §3 middleware order | 84-95 | Every position load-bearing | Rate limit after CORS = a DB round trip before shedding | Stack trace leak; nil-pointer at boot |
| ARCH §3 "No CSRF middleware" | 97-98 | Sound for Bearer routes | **Incomplete for cookie-only /auth/refresh and /auth/logout** — needs POST-only + JSON Content-Type | CSRF-to-DoS chain |
| §4 preamble + traceability | 104-105 | Sets the acceptance bar | **"§15 of this doc" does not exist** (it is §9); claim is unfalsifiable | Mapping unusable |
| §4 JWT allowlist | 108-109 | Implemented | Add a modulus floor | Total auth bypass |
| §4 key loading / JWKS / claims / skew | 110-111 | Startup load; required claims; conditional aud | jwx doesn't enforce presence — the manual recheck is load-bearing; the 5-min cache is unbuilt | Never-expiring tokens |
| §4 refresh rotation + FOR UPDATE note | 114-115 | The parenthetical is the most important note in the doc | Add "must run via WithTx, not the pool" | Reuse detection silently dead |
| §4 family rotation | 116-117 | Creates the chain reuse detection walks | Doesn't mention the two unique indexes; no absolute family cap | Attacker keeps the other branch |
| §4 reuse detection / D1 | 118-120 | The one deliberate divergence from the oracle | Burns only unrevoked members; the Go side is unbuilt and `defer tx.Rollback()` reproduces the bug | Ineffective control that logs success |
| §4 grace race | 121-122 | Prevents burning real users on a double refresh | `PREV_TOKEN_GRACE_MS` exists nowhere in Go; the path-2 query is unindexed | Multi-tab users logged out everywhere |
| §4 RBAC precedence | 126-127 | "value, not key" is a genuine JS→Go landmine | Missing the "group must have ≥1 feature" precondition | Silent denial or cross-tenant escalation |
| §4 freshness | 128-129 | One indexed read converts a stateless JWT into a revocable one | State the throughput ceiling | Fired employee keeps access 15 min |
| §4 tenant isolation ×2 | 130-134 | Second layer is physical | **Under-counts: 7 composite FKs, not 3** | One forgotten predicate = full breach |
| §4 passwords | 137-139 | Params are a hard parity requirement | DUMMY_HASH is lazy and Warm() uncalled; units (KiB) unstated | Scriptable enumeration oracle |
| §4 opaque tokens | 140-141 | 256-bit → unsalted sha256 is safe and index-compatible | **Omits invite tokens (hex)**; unpadded rationale unstated | Index/lookup break |
| §4 PKCE | 142 | Constant-time S256 | Reconcile the "length guard" wording with the code | Code interception |
| §4 single-use redemptions | 143-144 | One statement under one row lock | Add "zero rows is the only correct already-used signal" | Two families from one login |
| §4 cookies | 147-149 | Each flag is a separate control; HttpOnly=false is a documented tradeoff | Omits Expires-vs-MaxAge and the state payload | XSS → 7-day refresh token |
| §4 no `__Host-` + clear replay | 150-151 | Documents a deliberate weakening with its justification | State the residual subdomain cookie-fixation risk | Logout leaves a live cookie |
| §4 CORS | 154-156 | DB-backed dynamic allowlist; verified domains only | **"No origin/localhost allowed" reads as denial — inverts the oracle** | Arbitrary credentialed cross-origin reads |
| §4 rate limiting + trusted proxies | 157-158 | Gin trusts all proxies by default — an IP limiter on a spoofable IP is not a limiter | Config parses it, nothing calls SetTrustedProxies; no /admin/* limits | Unlimited credential stuffing |
| §4 security headers + 64 KiB | 159-160 | CSP 'none' correct for JSON; no-referrer stops code leakage | HSTS preload is irreversible; limit must precede decode | Codes leak via Referer |
| §4 input validation | 163-165 | Reject-not-drop is the anti-mass-assignment control | Missing a JSON-only Content-Type allowlist | Empty PATCH; duplicate 23505 500s |
| §4 fail-fast config | 168-169 | Turns the commonest deploy mistake into a crash | Covers 2 of ~6 secret vars; no PEM sanity check | Forgeable state cookie in prod |
| §4 redaction + pgx logging off | 170-171 | Query params carry token hashes | "Off" is a default — say so, or a tracer silently reverses it | Session lookup keys in logs |
| §4 audit append-only | 172-173 | Enforced by codegen omission | Not enforced by DB privileges; ctx contradiction | Attacker erases their trail |
| §5 pgx + WithTx | 179-180 | The mechanism behind landmine #7 | State the rule plainly; no pool sizing | Rotation runs unlocked |
| §5 sqlc typing | 181-182 | Verified overrides | TEXT ids give **no type safety between id kinds** | Scan errors; `null` arrays |
| §5 migrations + timestamptz (D13) | 183-186 | Names two deliberate divergences and justifies both | pgcrypto unnecessary on PG13+ | 30s grace becomes hours |
| §5 DB-enforced invariants | 187-189 | Each index encodes a rule Prisma could not | SPEC's "SET NULL" for audit is **impossible** — code is right | Soft-deleted email blocks re-invitation |
| §5 typing landmines | 190-191 | Three silent-wrong-answer conversions | "Enforced in review" is the weakest enforcement; #10 pv-not-float64 missing here | Every session reads as revoked |
| §6 configuration | 197 | "No other package reads os.Getenv" is grep-checkable | Add the CI grep | Bypassed validation |
| §6 observability | 198-200 | Three-probe split matches orchestrator semantics | Handlers unbuilt; oracle's retryAfter/body unstated | Restart storms / traffic to a broken pod |
| §6 background jobs | 201-202 | After-listen start; ctx-cancel stop | **Omits the eager first run** SPEC requires; batch drain unstated | Delayed readiness; leaked goroutines |
| §6 concurrency | 203-204 | Closed enumeration of goroutine sources; recover() mandatory | `WithoutCancel` here vs `Background()` elsewhere | One panic kills the process |
| §6 errors | 205-206 | One mapping table; ≥500 collapsed | Omits that 404 carries no reqId | Schema leakage via pgx errors |
| §6 graceful shutdown | 207 | Ordering is the content | No drain deadline | 502s on every deploy |
| §7 parity oracle | 213-217 | "Real Postgres, not fakes" is exactly right | **16 suites, not 14** — licenses declaring parity at 14/16 | Vacuous crown-jewel tests |
| §8 deployment + D6 caveat | 223-226 | The one place a limitation is stated plainly | Model the rest of the doc on it; resolve what happens on a state-store miss | Half of Google logins fail intermittently |
| §9 threat table (16 rows) | 232-249 | Auditable checklist; the open-redirect double-validation appears nowhere else | Add a status column + rows for session fixation, XSS→alora_at, SSRF, argon2 DoS | Controls untraceable to threats |
| §10 decisions pointer + D13 | 255-258 | One register; D13 is genuinely additional and implemented | D13 lives in the wrong file; no status column | timestamptz reverted by a future author |
| SPEC preamble/provenance | 3-7 | Derived from code, not design notes; five hard-requirement categories | **Both counts wrong** (48 sources, 16 tests) | Cannot resolve against stale memory notes |
| SPEC §0 five corrections | 11-16 | Each pre-empts a specific wrong assumption; 15 models verified | Add: invite tokens are hex; only 8 of 12 feature keys enforced | Whole wrong auth flow built |
| SPEC §1 public endpoint table | 22-39 | Error strings **are** the parity contract; identical 401 is the anti-enumeration control | Add under-pressure Retry-After/body; mark which limits are tunable | Enumeration via distinguishable messages |
| SPEC §1 admin endpoint table | 41-54 | Authoritative authorization matrix; verified against the oracle | It is the proof 4 keys are dead; `(H-1)` is undefined | Self-service privilege escalation |
| SPEC §2 JWT invariants | 61-62 | Fixes the exact token contract; `roles` typing makes the value-not-key rule meaningful | Mandate a minimum modulus | aud rejects /auth/session; pv float64 disables revocation |
| SPEC §2 argon2 exact | 63 | Byte-level parity mandatory; PHC and RawStdEncoding spelled out | Record the pre-hash ordering as a security property | Universal login failure at cutover |
| SPEC §2 opaque tokens | 64 | Justifies unsalted hashing with the condition that makes it right | **Omits invite tokens**; "after length guard" is redundant | Index break; timing leak |
| SPEC §2 TTLs | 65 | Each is a distinct exposure window; 900 is a parity assertion | Derive `expires_in` from AccessTTL with a startup assertion | 401 flicker; wider interception window |
| SPEC §2 cookies | 67-71 | More precise than ARCH — gives the state payload and Expires-vs-MaxAge | Specify the HMAC framing; tie 600s to the store TTL | Open redirect + PKCE defeat |
| SPEC §2 session rotation | 73-78 | Most detailed section; NULL reason is the discriminator; length guards shed junk cheaply | SQL-ready, Go-unbuilt — **D1 is the highest-risk item**; tighten 32..256 to exactly 64 hex | Reuse detection silently dead |
| SPEC §2 authz | 80-86 | Nine controls incl. self-edit guard and ≥1-feature rule | All nine enforcement points are in empty packages | One-line change = full cross-tenant access |
| SPEC §2 I/O hygiene | 88-94 | Column-level output contracts, already enforced at the SQL layer | Justify the D10a invite_url exception next to the reset-token ban | Bulk hash disclosure |
| SPEC §2 DDL | 96-101 | Exact index names and predicates make the migration reviewable | 3 defects: SET NULL impossible, 4→7 FKs, dead DROP instruction | Migration fails or nullifies tenant binding |
| SPEC §3 helmet specifics | 106 | Values named rather than "helmet defaults" | Add the JSON-API rationale for CSP 'none' | Referer leakage; SSL strip |
| SPEC §3 CORS algorithm | 107 | The only unambiguous statement of the logic | Re-check is_active on cache hit; recommend RWMutex | Allow-on-error; concurrent map panic |
| SPEC §3 fire-and-forget | 108 | "NOT request ctx" is the operative clause | Mandate WithoutCancel + timeout, not "or Background" | Holes exactly during an attack |
| SPEC §3 jobs + state store | 109-110 | Eager first run; one-time delete is replay protection | Resolve Map-primary vs cookie-fallback contradiction | Callback replay |
| SPEC §4 layout tree | 114-145 | Scaffold that did its job | **Stale, drifted 4 ways** — delete and point at ARCH §2 | None |
| SPEC §5 build order (16 steps) | 149-165 | Dependency-first; crown jewels after crypto+middleware | Use it as the status ledger: 1-8 done, 9 partial, 10-16 not started | Rotation written against stubs |
| SPEC §6 query surface | 169-176 | Pre-names the surface; bracketed notes carry security semantics; all verified | Explain the LIMIT caps as DoS bounds | Unbounded admin list = memory pressure |
| SPEC §6 "see workflow output" | 177 | Names 7 real queries | **Dangling reference hiding ~20 shipped queries** incl. the whole RBAC surface and `:copyfrom` | Tenant scoping unverifiable |
| SPEC §7 D1-D12 table | 181-195 | Binding calls with rationale; D11's enum-cast catch is real | Add a status column; fold in D13 | D1 relitigated → the Node bug returns |
| SPEC §8 16 landmines | 199-216 | Highest-density security content; several facts appear nowhere else (#7 WithTx, #10 pv-not-float64, #14 ILIKE escaping) | Mark the 3 discharged; add a 17th for `defer tx.Rollback()` | `%` scans the tenant; revocation disabled |

---

## 3. Ranked Action Items (78)

### P0 — Blocks correctness or is exploitable today

| # | Item | Severity | Location |
|---|---|---|---|
| 1 | `LoadType("IdpProvider")` can never resolve — `::regtype` case-folds while the DDL type is double-quoted; `AfterConnect` fails on every connection so `database.New` always errors. Use `conn.LoadTypes` (typname = ANY) or embed quotes. | critical | `internal/platform/database/db.go:16` |
| 2 | Move the `for k,v := range claims` loop **above** the registered-claim chain (or reject reserved keys) — a caller-supplied `iss/sub/iat/exp/jti` silently overrides. | critical | `jwtkeys.go:107-109` |
| 3 | Change `tok.Expiration().IsZero()` to `Unix() <= 0` — `exp:0` passes both jwx validation and the recheck, yielding a never-expiring token. | critical | `jwtkeys.go:169-171` |
| 4 | Add `AND u.deleted_at IS NULL` (and project it) to `GetLinkedIdentity` — `SoftDeleteUser` never clears `is_active`, so deprovisioned users sign back in via Google. | critical | `db/queries/oauth.sql:77-84` |
| 5 | Sanitize/encode all MIME header values (strip CR/LF/NUL, `mime.QEncoding`) — tenant-controlled `clientName` injects headers into invitation mail. | critical | `internal/mailer/mailer.go:79-83` |
| 6 | Allowlist `NODE_ENV ∈ {development,test,production}` and fail otherwise — one typo disables Secure cookies + both prod secret guards. | critical | `config.go:100-101` |
| 7 | Add `defer func(){ _ = recover() }()` to `password.Verify` (or use `CheckHash` with param bounds) — `t=0`, `p=0` and an empty key segment **panic**. | critical | `password.go:46-54` |
| 8 | Close the fail-open dummy-hash window: compute in `init()`, or re-check `dummyHash == ""` after `Do` — `sync.Once` latches even when `f()` panics. | critical | `password.go:71-84` |
| 9 | Make `DeleteGroupFeatures` and `CreateGroupFeatures` self-scoping (`USING/SELECT … tbl_groups WHERE g.client_id=$2`) — today the tenant guard is a comment. | critical | `db/queries/rbac.sql:118-129` |
| 10 | Split `Init` into `Init` (sets active signer) and `RegisterVerifyKey` — registering an old kid currently makes it the **active signer**, inverting rotation. | critical | `jwtkeys.go:50` |
| 11 | Make the PKCE test a real conformance test (hardcode the RFC 7636 Appendix-B challenge, drop the crypto imports) — an encoder change that breaks 100% of logins keeps the suite green. | critical | `pkce_test.go:11-13` |
| 12 | Correct SPEC §2 L97: the audit FK is `NO ACTION … DEFERRABLE`, not `SET NULL` (impossible with `client_id NOT NULL`); and it is **7** composite FKs, not 4. | critical | `SPEC.md:96-97` |

### P1 — Security hardening with a concrete exploit path

| # | Item | Severity | Location |
|---|---|---|---|
| 13 | Ship `COOKIE_SECRET=` empty and move the placeholder + ≥32 checks out of the `isProd` branch — the published example is a live HMAC key in dev/staging. | high | `.env.example:25`, `config.go:103-115` |
| 14 | Validate and require `TRUSTED_PROXIES` (netip parse; non-empty in prod) and call `SetTrustedProxies` **unconditionally**. | high | `config.go:155,215-226` |
| 15 | Add a minimum RSA modulus check (`N.BitLen() >= 2048`) in both parsers — jwk explicitly declines to check length. | high | `jwtkeys.go:56-86` |
| 16 | Add `priv.PublicKey.Equal(pub)` self-test in `Init` — a mismatched pair boots clean and fails 100% of verifications. | high | `jwtkeys.go:39-54` |
| 17 | Make SMTP auth conditional on `MAIL_USER != ""` and derive `envelopeFrom` from the From header (or `MAIL_ENVELOPE_FROM`). | high | `mailer.go:66-67` |
| 18 | Escape `clientName` and URLs in the HTML part via `html/template` — attacker-authored links inside DKIM-aligned mail. | high | `mailer.go:38-41,56-59` |
| 19 | Use a crypto/rand boundary per message (`mime/multipart`) — the static published boundary permits MIME part injection. | high | `mailer.go:77` |
| 20 | Enforce S256 in two places: `CHECK (code_challenge_method = 'S256')` and a method-aware `pkce.Verify`; hardcode `'S256'` in the INSERT. | high | `0001_schema.sql:169`, `oauth.sql:27`, `pkce.go:13` |
| 21 | Implement RFC 7636 §4.1 validation (verifier 43..128, charset, challenge len 43) in place of the empty-input guard. | high | `pkce.go:14` |
| 22 | Call `slog.SetDefault(l)` in `New` and branch on `a.Value.Kind()` for struct/map values — redaction currently sees keys only and stray `slog.*` bypasses it. | high | `logger.go:36-47` |
| 23 | Widen `sensitiveKeys` to access_token, id_token, client_secret, cookie_secret, pass/mail_pass, password_hash, refresh_token_hash, proxy-authorization. | high | `logger.go:17-26` |
| 24 | Extend the prod placeholder scan to DATABASE_URL, JWT_PRIVATE_KEY, MAIL_PASS; replace `admin:password` with a CHANGEME literal. | high | `config.go:104`, `.env.example:14` |
| 25 | Add `*.pem *.key *.p8 *.p12 *.jks id_rsa* *.dump *.sql.gz` to `.gitignore` — the standard keygen recipe drops the signing key in the repo root. | high | `.gitignore:10-12` |
| 26 | Add `SET search_path` and `REVOKE EXECUTE … FROM PUBLIC` on all four routines — `sp_revoke_token_family` is callable by any connecting role. | high | `0003_procs.sql:16-68` |
| 27 | `REVOKE UPDATE, DELETE ON tbl_audit_logs` — append-only is currently enforced only by which queries were written. | high | `0001_schema.sql` / `audit.sql` |
| 28 | Add `AND c.is_active` to every invitation lookup/claim — a suspended tenant currently keeps onboarding users. | high | `invitations.sql:136,151,166,93,107` |
| 29 | Add `AND u.deleted_at IS NULL` to `GetGroupDetail`'s user join and to the `member_count` subquery (join tbl_users) — soft-deleted emails/user_ids are returned. | high | `rbac.sql:34-37,62` |
| 30 | Add `p.is_active` and a `tbl_client_products` join to the token-mint query — deactivation and lapsed subscriptions do not strip roles from new JWTs. | high | `auth.sql:22-29` |
| 31 | Add a `GetUserForTokenMint :one … WHERE id=$1 AND is_active AND deleted_at IS NULL` query — no liveness-checked identity query exists for /auth/token. | high | `db/queries/auth.sql` (missing) |
| 32 | Require `FRONTEND_URL` in prod and assert https; same for JWT_ISSUER and GOOGLE_REDIRECT_URI. | high | `config.go:154,160,172` |
| 33 | Remove `domain_verified_at` from the tenant-facing PATCH and gate it behind a DNS/HTTP challenge — self-asserted verification squats domains and grants CORS. | high | `clients.sql:99` |
| 34 | Make `allowed_idp_providers` NOT NULL and use `COALESCE(narg, DEFAULT)` on insert/update — a nil slice writes NULL and can lock a tenant out of every IdP. | high | `0001_schema.sql:30`, `clients.sql:79,94` |
| 35 | Require TLS on the 587 path (Dial → assert `Extension("STARTTLS")` → StartTLS with MinVersion TLS12). | high | `mailer.go:69-73` |
| 36 | Add `pem.Decode` validation of both JWT key vars at config time, or guarantee `jwtkeys.Init` runs before Listen. | high | `config.go:157-158` |
| 37 | Give `intEnv` min/max bounds and apply real ranges at all six call sites (`REFRESH_DAYS=0` → total logout outage; `PORT=0`; rate-limit maxima). | high | `config.go:197-207` |
| 38 | Validate `AccessTTL > 0` (critic) — `ParseDuration` accepts `0s`/`-5m`, and `Sign` then mints already-expired tokens. | high | `config.go:117` |

### P2 — Correctness, availability, and performance

| # | Item | Severity | Location |
|---|---|---|---|
| 39 | Fix `Secure: os.Getenv("MAIL_PORT")=="465"` → `mailPort == 465`. | medium | `config.go:177` |
| 40 | Fix the nondeterministic login: `GetActiveUserByLowerEmail` has no client_id and no ORDER BY while the same email may exist in two tenants. | high | `users.sql:44-54` |
| 41 | Add `CREATE INDEX ON tbl_users (lower(email)) WHERE deleted_at IS NULL` — every login seq-scans. | high | `0002_constraints.sql` |
| 42 | Add `CREATE INDEX ON tbl_user_sessions (prev_token_hash) WHERE prev_token_hash IS NOT NULL AND revoked_at IS NULL` — seq scan inside the rotation transaction under `FOR UPDATE`. | high | `0001_schema.sql` |
| 43 | Add `CREATE INDEX ON tbl_user_sessions (client_id, last_seen_at DESC) WHERE revoked_at IS NULL` — the admin session list scans + sorts the largest table. | high | `0001_schema.sql` |
| 44 | Add `CREATE INDEX ON tbl_users (client_id, created_at DESC, id DESC) WHERE deleted_at IS NULL` — keyset pagination currently sorts the whole tenant per page. | high | `0001_schema.sql` |
| 45 | Add `CREATE INDEX ON tbl_user_groups (group_id)` — starves member_count, GetGroupDetail and the group-delete CASCADE. | high | `0001_schema.sql` |
| 46 | Replace the broken invitations index with `CREATE UNIQUE INDEX ON tbl_invitations (client_id, lower(email)) WHERE status='PENDING'` — makes the guard indexable **and** closes the duplicate-invite race. | high | `0001_schema.sql:239` |
| 47 | Index the RESTRICT/SET-NULL FK child columns (critic): `tbl_invitations(invited_by_user_id)`, `(accepted_by_user_id)`, `tbl_product_permissions(client_id)`, `tbl_authorization_codes(user_id)`. | medium | `0001_schema.sql` |
| 48 | Add a `lock_timeout` (or `FOR UPDATE NOWAIT` → 409) around the rotation transaction — N replays pin N pool connections. | high | `sessions.sql:17-23` |
| 49 | Collapse `FindValidResetToken` + `MarkResetTokenUsed` into one CTE `UPDATE … RETURNING` — today safety depends on the caller using `WithTx`. | high | `passwordreset.sql:23-35,60-65` |
| 50 | Replace `CreateInvitationProducts :copyfrom` with the `unnest` INSERT plus an entitlement `EXISTS` guard COPY cannot carry. | high | `invitations.sql:50-56` |
| 51 | Set explicit pool limits (MaxConns, MinConns 2-4, MaxConnLifetimeJitter ~5m, ConnectTimeout 5s) and bound `Ping` with a 5s timeout. | high | `db.go:38-42` |
| 52 | Upgrade `:exec` → `:execrows` on `UpdateUserPasswordHash`, `IncrementUserPermissionsVersion` (fail-open revocation), `SoftDeleteUser`, `MarkSessionReplaced`. | high | `users.sql:178,197,187`, `sessions.sql:89` |
| 53 | Type-enforce the three "always non-null" params with `sqlc.arg(x)::text`: password_hash, prev_token_hash, replaced_by_id. | high | `users.sql:173`, `sessions.sql:76,88` |
| 54 | Fix the half-cursor guard — with `cur_created` set and `cur_id` NULL, **rows tied on created_at are silently dropped** (critic correction). | medium | `users.sql:126-129` |
| 55 | Cap `LIMIT LEAST(sqlc.arg('lim'), 200)` — the only list query without a server-side cap. | medium | `users.sql:131` |
| 56 | Retype `p_revoked_reason` as `"SessionRevokedReason"` and drop the internal cast — restores compile-time typing on the family burn. | medium | `0003_procs.sql:18` |
| 57 | Add `updated_at = now()` to `sp_expire_invitations`, and make both sweeps drain (`GET DIAGNOSTICS` loop + `COMMIT`, `SKIP LOCKED`); guard `p_batch_size <= 0`. | medium | `0003_procs.sql:31-56` |
| 58 | Add `AND deleted_at IS NULL` to `UpdateUserActive` and also set `is_active=false` in `SoftDeleteUser`. | medium | `users.sql:169,187` |
| 59 | Delete `FindActiveSuccessorById` (byte-identical to `GetSessionById`, with a name that falsely implies a liveness filter). | medium | `sessions.sql:33-35` |
| 60 | Fix `last_seen_at`: write it on rotation, or drop it and `ORDER BY created_at DESC` honestly. | medium | `sessions.sql:82,121` |
| 61 | Add the nullable jsonb override to sqlc.yaml so audit `event_metadata` becomes `json.RawMessage`. | medium | `sqlc.yaml:14-16` |
| 62 | Reorder/partialize the sweep indexes: `(status, expires_at)` or partial on invitations; partial `WHERE revoked_at IS NULL` on sessions.expires_at. | medium | `0001_schema.sql:236,241` |
| 63 | Add `CHECK ((account_type='OAUTH_ONLY') = (password_hash IS NULL))`, `CHECK (generation >= 0)`, `CHECK (expires_at > created_at)`, hex-format CHECKs on the hash columns. | medium | `0001_schema.sql` |
| 64 | Add `COLLATE "C"` to every id/hash column and to the three `lower()` expression indexes (collation-version corruption risk). | medium | `0001_schema.sql`, `0002_constraints.sql` |
| 65 | Add the missing composite FKs: `(group_id, client_id) → tbl_groups`, `(client_id, product_id) → tbl_client_products`, and FKs on the four actor columns. | medium | `0002_constraints.sql` |
| 66 | Change `ON UPDATE CASCADE` → RESTRICT on all 26 FKs (unreachable, and would silently rewrite the audit trail). | medium | `0001_schema.sql:253-287` |
| 67 | Rewrite `utf16Len` allocation-free with early exit + the `len(s) <= Max` fast path (~384 KiB garbage per unauthenticated attempt today). | medium | `password.go:57-59` |
| 68 | Memoize the marshalled JWKS bytes; add an ~8 KB token-length guard and `jwt.Settings(WithCompactOnly(true))`. | medium | `jwtkeys.go:165,176-191` |
| 69 | Break the invite↔refresh coupling (`generateHex()`), export `RefreshTokenLen`/`OpaqueLen`, and delete the dead `rand.Read` error branches. | medium | `tokens.go:19-21,54`, `password.go:73-75` |
| 70 | Add `mail.ParseAddress(to)`, a `ctx` parameter, dial/read/write deadlines, and Date/Message-ID/Content-Transfer-Encoding headers. | medium | `mailer.go:27,45,63,79-83,94` |
| 71 | Add a depguard/forbidigo ban on `math/rand`, and a CI grep banning `os.Getenv` outside `internal/config`. | medium | repo-wide |
| 72 | Add CI: `sqlc diff`, `go mod tidy -diff`, `go mod verify`, `govulncheck`, and pin sqlc v1.31.1 via a `tool` directive. | medium | (absent) |
| 73 | Delete the confirmed dead constructs (see §4 dead-weight list): `emit_interface`, `emit_exact_table_names`, `*.dll`, `Config.Env`, `session_uuid` + its index, 4 redundant/unusable indexes, `CheckProductPermissionExists`, `GetProductById`, `ListActiveProducts`, `GetPendingInviteMinimal`, `ClaimInviteRegistration`, `jwt.WithValidate(true)`, the dead `Issuer()==""` clause, `NULLS LAST` ×4. | low | multiple |
| 74 | Make the config test fixture hermetic and close the named coverage gaps (GOOGLE_CLIENT_SECRET arm, 31/32 boundary, JWT_PUBLIC_KEY normalization, `splitNonEmpty`, mis-cased NODE_ENV). | high | `config_test.go` |
| 75 | Add the crypto tests that would catch silent criticals: two generated tokens must differ; base64url length assertion; salt=16B/key=32B and no `=` padding; the three panicking hash shapes; HS256-with-public-key; JWKS must contain no `d`/`p`/`q`. | high | `tokens_test.go`, `password_test.go`, `jwtkeys_test.go` |
| 76 | Delete SPEC §4's stale layout tree and the dead "DROP legacy tbl_users_client_id_email_key" instruction; enumerate SPEC §6's "see workflow output" queries; fix the `§15` reference, the ARCH CORS sentence, the audit-context contradiction, the 14→16 suite count and the 43→48 source count. | medium | `ARCHITECTURE.md`, `SPEC.md` |
| 77 | Add implementation-status markers to ARCH §2 and SPEC §5/§7 — 12 of 22 named packages are empty while the prose is present-indicative. | high | docs |
| 78 | Resolve the `expires_in` triple source: derive from `cfg.JWT.AccessTTL` or assert `== 900*time.Second` at boot. | medium | `config.go:117,162` |

---

## 4. Adversarial Critic — Corrections & Resolutions

### 4.1 Rubber-stamped verdicts (auditor said "already optimal"; critic is right)

| Item | Auditor verdict | Critic finding | Resolution |
|---|---|---|---|
| `rbac.sql:33-37` member_count | "second-layer tenant guard … justified" | Counts **soft-deleted** users; no join to `tbl_users` | **Critic right.** Join `tbl_users … deleted_at IS NULL`. /admin/groups otherwise contradicts /admin/users. |
| `rbac.sql:60-62` GetGroupDetail user join | "Keeping it LEFT is defensible … already optimal" | No `u.deleted_at IS NULL`; projects `u.email` → soft-deleted emails/user_ids returned | **Critic right.** Same class of leak §2 bans on /admin/users. Add the predicate. |
| `invitations.sql:158-170` GetPendingInviteWithIdp | "already optimal — one round trip" | Joins `tbl_clients` and never checks `c.is_active`; same in LookupPendingInvite and (no join at all) GetPendingInviteMinimal | **Critic right.** A suspended tenant keeps onboarding users. |
| `jwtkeys.go:106` `uuid.NewString` | "panics on rand failure … free correctness" | Unreachable on go1.26 — `crypto/rand.Read` cannot error; the tokens-pkce audit used the same fact to call `tokens.go:19-21` dead | **Critic right.** Two audits reached opposite conclusions from one premise. Drop the item; keep the dead-branch deletions. |
| `config.go:112` COOKIE_SECRET `len()` | "byte count is strictly tighter than Node's UTF-16 length — an improvement" | Direction is inverted (see 4.3) | **Critic right.** Not an improvement; a loosening. |
| `oauth.sql:63-71` ClaimAuthorizationCode RETURNING | "each column maps to a named security check" | No query anywhere lets the exchange verify the returned `user_id` is still active/undeleted | **Critic right.** The projection is optimal only relative to a liveness check that does not exist — hence action item #31. |

### 4.2 Constructs no auditor examined

| Missed construct | Consequence |
|---|---|
| Absence of `deleted_at IS NULL` on `tbl_users` throughout the rbac unit (`rbac.sql:33-37`, `47-64`) | Soft-deleted users remain visible members and inflate member_count. |
| Absence of `c.is_active` across the whole invitation surface (`invitations.sql:93,107,136,151,166`) | A suspended tenant can still gain members — the invite path creates users, and no auditor checked it. |
| `db/queries/auth.sql` contains **one** query; no liveness-checked identity query exists for token minting | /auth/token must use `GetUserById` (`SELECT *`, drags password_hash) or a projection lacking client_id/email/is_global_admin. Structural cause of the GetLinkedIdentity gap. |
| `config.go:117` — `ParseDuration` accepts `0s`/`-5m`; nothing validates `AccessTTL` sign | `Expiration(now.Add(ttl))` mints tokens already expired at issue. |
| No index on the FK **child** columns actually probed by RESTRICT/SET NULL: `tbl_invitations(invited_by_user_id)`, `(accepted_by_user_id)`, `tbl_product_permissions(client_id)`, `tbl_authorization_codes(user_id)` | Every user hard-delete seq-scans `tbl_invitations` twice; the DEFERRABLE check repeats it at COMMIT. Auditors debated the wrong indexes. |
| Write-only accountability columns with **no reader anywhere**: `tbl_user_groups.assigned_by`, `tbl_invitations.revoked_by_user_id/revoked_at/accepted_at`, `tbl_password_reset_tokens.created_by` | Auditors flagged the missing FKs but not that no generated query ever reads them — the accountability story is unreachable from the application. |

### 4.3 Auditor claims that are wrong

| Claim | Correction | Resolution |
|---|---|---|
| Half-cursor: "`(created_at,id) < (ts, NULL)` → NULL for every row → **empty page**" (`users.sql:126-129`) | PG row-comparison short-circuits at the first unequal pair; only rows **tied** on created_at yield NULL | **Critic right.** Real defect: tied rows silently dropped — precisely the case the id tiebreaker exists for. Still fix the guard. |
| "Go's `len()` is strictly tighter than Node's UTF-16 `.length`" (`config.go:112`) | For non-ASCII, UTF-8 bytes ≥ UTF-16 units (é = 2/1; emoji = 4/2), so Go's count is **larger** and the ≥32 gate **looser**. 11 emoji = 44 bytes (passes Go) / 22 units (fails Node) | **Critic right.** Go accepts secrets Node rejects. Remove the "improvement" framing; the entropy point stands. |
| `uuid.NewString` panic listed as live hardening (`jwtkeys.go:106`) | Unreachable on the pinned toolchain | **Critic right.** Removed from action items. |
| ARCH audit-context: "`context.Background()` drops the request id" presented as a code defect | `internal/platform/audit/` is empty and `InsertAuditLogParams.RequestID` is an explicit parameter, not context-extracted | **Critic partly right.** The *doc contradiction* is real (kept as item #76); the claimed runtime consequence is not. |
| `oauth.sql` header self-contradiction (L5-6 "the `code` is the secret" vs L15-16 "no secret columns exist") | Verified genuine | **Auditor right, confirmed.** Three units read this file; only one caught it. |
| docs: 16 `.test.js` suites; 12 registry keys with only 8 enforced | Both verified against the oracle | **Auditor right, confirmed.** Do not relitigate. |

### 4.4 Confirmed dead weight (consolidated, verified)

`sqlc.yaml:11` `emit_interface` (42 KB unused querier.go) · `sqlc.yaml:13` `emit_exact_table_names` (restates the default) · `.gitignore:5` `*.dll` (no cgo) · `config.go:19` `Config.Env` (write-only) · `sessions.sql:33-35` `FindActiveSuccessorById` (byte-identical duplicate) · `0001_schema.sql:71,218` `session_uuid` + its unique index (write-only, indexed on both hot write paths) · `0001_schema.sql:232,233,237,239` four redundant/unusable indexes · `0001_schema.sql:14` `CREATE EXTENSION pgcrypto` · `0001_schema.sql:31` `require_mfa` · `entitlements.sql:89-96` `CheckProductPermissionExists` · `products.sql:21-24,37-41` `GetProductById`, `ListActiveProducts` · `invitations.sql:146-155` `GetPendingInviteMinimal` · `invitations.sql:100-111` `ClaimInviteRegistration` · `jwtkeys.go:158` `jwt.WithValidate(true)` · `jwtkeys.go:169` `tok.Issuer()==""` clause · `NULLS LAST` ×4 (`users.sql:105`, `invitations.sql:143`) · `tokens.go:19-21` and `password.go:73-75` dead `rand.Read` error branches · `tokens_test.go:28-30` and `pkce_test.go:24-29` vacuous assertions · `oauth.sql:98-101` `CleanupExpiredAuthCodes` (no caller, unbatched) · `password.go:90` `Warm()` (zero call sites) · `ON UPDATE CASCADE` ×26.

