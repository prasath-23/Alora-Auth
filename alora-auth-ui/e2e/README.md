# End-to-end tests (Playwright)

Drives the real App Central SPA against the real Go API (HTTP and gRPC), a real
Postgres, real product backends, and the demo gRPC product and application
built from `alora-auth-go`. Nothing is mocked.

## Run

```bash
# 1. Postgres, the schema, the API (as alora_app) and the platform Owner
bash ../alora-auth-api/scripts/e2e-up.sh

# 2. The suite (Vite starts automatically)
npx playwright test

# 3. Tear down
bash ../alora-auth-api/scripts/e2e-up.sh --down
```

`e2e-up.sh` starts Postgres on :55532 (`ALORA_DB_PORT` overrides it). It then:

- builds the schema and the least-privilege role;
- generates a signing key;
- runs `cmd/bootstrap platform` to create the Owner;
- builds the demo gRPC server and client from `../alora-auth-go`;
- boots the API on :3001, the port the Vite proxy targets, with its gRPC door on
  :3002.

It writes `stack.json` to Node's temp directory (`ALORA_E2E_STATE` overrides it). `seed.js` reads the Owner's credentials and the seeding command from there, and `grpc.spec.js` the gRPC address and the demo binaries.

## What runs where

| Piece | Address | Why there |
|---|---|---|
| App Central (Vite) | `http://localhost:5173` | Serves the SPA and proxies `/api`, `/auth`, `/oauth`, `/.well-known` and `/health` to the API. The browser sees one origin, as in production behind a reverse proxy. It is also the issuer. |
| The API | `http://127.0.0.1:3001` | Reached through the proxy, never directly by the browser. |
| The API's gRPC door | `127.0.0.1:3002` (plaintext) | Where the demo application gets its tokens (`TokenService.GetToken`). |
| The demo gRPC product | `127.0.0.1:<free port>` | An inventory that checks every call with the helper's `Verifier` and interceptors. |
| Sample products | `http://127.0.0.1:<free port>` | A different **host** from `localhost`, so the browser keeps their cookies apart from App Central's exactly as it would for two real sites. |
| Stub identity provider | `http://127.0.0.1:<free port>` | In-process. It stands in for a company's Okta or Entra ID. |

## The files

| File | What it holds |
|---|---|
| `seed.js` | `seedCompany()` runs `cmd/bootstrap demo` as the schema owner. That gives a company with an Admin, and a product registered for a sample backend (launch address, exact redirect URI, roles, client secret), subscribed, with the Admins group granted it. |
| `product.js` | Runs `../sample-product.cjs` as its own process for a seeded product. |
| `idp.js` | A strict stub OIDC provider. It checks the client secret, the exact redirect URI, PKCE and single-use codes, and signs RS256 ID tokens. |
| `helpers.js` | Browser sign-in, an HTTP client with its own cookie jar, `newMember()` (a member made by invitation, the way real members are made), and the v3 set-ups: extras for a person, a product that accepts API clients, a ready API client and its client-credentials token. |
| `auth.spec.js` | App Central sign-in, cookies, `return_to`, the company chooser, product launch, renewal, sign-out and the product's own checks, invitations, resets and password changes. |
| `admin.spec.js` | The company admin area: sections, membership and the last-Admin guard, groups and the scopes they give (never the apps they open), session revocation, rename; delegated users with `users:read`, `users:edit` and `groups:edit` (rules 1 and 2, in the page and at the API); **Your access**, and access given mid-session showing up without a reload. |
| `owner.spec.js` | The Owner console. It covers access, company setup end to end, product registration and its show-once secret, the target-company header, platform protections, direct grants, login policies, and company SSO through the stub provider. |
| `contract.spec.js` | The response shapes the SPA and products read, the login token's `scope`, `products` and `manages`, a manager's `/api/me` and group page, and discovery. Also the transport rules: CORS only on `/.well-known`, same-origin sign-in, JSON only, the `return_to` clean-up, and the provider driven as a product backend (audience separation both ways, single-use codes, PKCE, client authentication). |
| `rolematrix.spec.js` | Every page for every role: a member, the reader and the editor of each feature, a group manager, a company Admin and the Owner. The navigation offers exactly what each may open, a page reached directly opens or refuses, edit controls appear only with the edit scope, and the Owner console is the Owner's alone. |
| `companies.spec.js` | Three companies side by side: each Admin sees only their own people, groups, invitations, API clients and products, on every page and the launcher; another company's things are not there even by address; the Owner sees each company through its own door. |
| `limits.spec.js` | The SPA's limits are the API's: every length in `src/utils/limits.js` is accepted exactly and refused one past, at the API; every list's count and entry length likewise; the SPA's domain, URL, issuer and product-key rules give the API's verdict on valid and invalid samples alike; and every input carries its `maxLength`, which the browser holds to. |
| `ownerforms.spec.js` | The Owner console's forms refuse in words and save nothing: a domain that is no domain, a bad product key or URL, a redirect-URI or role list past its limits, a policy that allows nothing or takes a priority in use, an SSO issuer or domain the API would refuse — and an SSO connection whose domains are refused after it was saved is finished by saving again, never made twice. |
| `latecomers.spec.js` | Double clicks and late answers: every form that creates or revokes something — groups, members, managers, API clients and their secrets, invitations, companies, products, policies, SSO connections — sends once however often it is pressed while sending, and shows no spurious error after; and a page of an earlier search that answers late never joins a later one. |
| `hardening.spec.js` | Markup in every kind of name shown as text on every page that shows it, with no script run and no dialog opened; a hostile browser identity shown as a fixed label; every form refusing what the API refuses, in words, saving nothing; a finished session staying finished for the back button and a second tab. |
| `groupmanagers.spec.js` | Group managers: an Admin appoints one and their open page gains **Groups you manage** without a reload; they add a colleague (who gets the group's access) and remove them; they are refused someone above their reach, themselves, and every other group; appointing yourself, an unknown address or someone twice is refused on the page, and without the group's access there is no form; the user page and Profile list the groups managed; the Owner appoints from the Owner console, and the Admins group has none. |
| `apiclients.spec.js` | API clients in the admin area and the Owner console: a secret shown once, rotation with two live secrets, only products that accept API clients on a list, `api-clients:read` seeing but not changing; the Owner's **Client credentials** page. |
| `clientcredentials.spec.js` | An application end to end over HTTP: set up in the admin area, a client-credentials token, the sample product's `GET /api/items`; still working through a rotation, and stopping when its secret is revoked or it is switched off. |
| `grpc.spec.js` | The same over gRPC, with the real demo binaries: a token from App Central's `TokenService`, the inventory read with `grpc:read`, a change refused without `grpc:edit` and allowed with it; a wrong secret refused by App Central, and one product's token refused by another. |

## Design

- **Nothing is mocked.** A mocked API cannot catch contract drift, which is the
  risk the suite exists for.
- **Serial.** Specs share one API and one database.
- **Every spec seeds its own companies.** Addresses, names and product keys carry
  a random suffix, so specs never collide on the unique indexes and can run in
  any order.
- **The API runs with raised rate limits** (`RATE_LIMIT_SCALE` and friends). The
  suite drives every flow from one address far faster than any person would.
