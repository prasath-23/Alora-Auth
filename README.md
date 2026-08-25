# Alora Auth

A multi-tenant B2B identity provider: OAuth 2.0 authorization-code + PKCE login,
refresh-token rotation with replay detection, invitations, password reset, and a
tenant-scoped admin surface.

Three projects, one repository. Each builds, runs and tests **independently** —
they are together because a change to a stored procedure and the Go call site
that binds to it are one logical change.

| Project | What it is | Stack |
|---|---|---|
| [`alora-auth-db`](alora-auth-db/) | The database. Owns the schema and every stored procedure. | PostgreSQL 16 |
| [`alora-auth-api`](alora-auth-api/) | The service. Contains no SQL of its own. | Go 1.26, Gin, pgx, sqlc |
| [`alora-auth-ui`](alora-auth-ui/) | The login page and admin portal. | React 18, Vite, Tailwind |

---

## Prerequisites

| Tool | Needed for | Check |
|---|---|---|
| Go 1.26+ | the API | `go version` |
| Node 20+ | the UI | `node --version` |
| Docker | a local PostgreSQL | `docker info` |
| `psql` (PostgreSQL 16 client) | applying to a real database. Not needed for `./migrate.sh --docker`, which uses the throwaway container's own client | `psql --version` |
| [sqlc](https://sqlc.dev) | only if you change the database | `sqlc version` |

On Windows, run the shell scripts from **Git Bash**.

---

## Quick start

Four terminals' worth of work, but only the first time.

### 1. Database

```bash
cd alora-auth-db
./migrate.sh --docker          # throwaway PostgreSQL on :55532, fully built
```

That verifies the whole build, then throws the container away. For a database
you want to keep — this one needs `psql` on PATH:

```bash
export DATABASE_URL="postgres://postgres:secret@localhost:5432/alora"
./migrate.sh              # apply
./migrate.sh --status     # report what is pending, change nothing
```

### 2. API

```bash
cd alora-auth-api
cp .env.example .env           # then fill in the values below
go run ./cmd/api
```

You need an RS256 key pair before it will start:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -in private.pem -pubout -out public.pem
```

Put their contents in `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` (newlines may be
written as `\n`), and set `COOKIE_SECRET` to at least 32 random bytes. The server
refuses to start if anything required is missing — that is deliberate, so a
misconfigured deployment fails at boot rather than at the first login.

### 3. First tenant and administrator

There is no signup endpoint: anyone who could call it could create tenants. Seed
the first one out of band.

```bash
cd alora-auth-api
go run ./cmd/bootstrap \
  -tenant "Acme Corp" \
  -email  admin@acme.com \
  -product CRM \
  -product-url http://127.0.0.1:5173
```

It prompts for the password without echoing it (or reads `BOOTSTRAP_PASSWORD`
when there is no terminal), and prints the sign-in URL to use next.

### 4. UI

```bash
cd alora-auth-ui
npm install
npm run dev                    # http://127.0.0.1:5173
```

Vite proxies `/auth`, `/admin` and `/health` to the API on `:3001`, so the
browser sees a single origin exactly as it would behind a reverse proxy.

---

## Signing in

`/` is an **authorization endpoint**, not a self-contained login page. A product
application sends the user there with PKCE parameters; the SPA posts the
credentials and redirects back to the product carrying a one-time code, which the
product exchanges for tokens.

So opening `http://127.0.0.1:5173/` on its own shows *"Missing required
parameters"* — that is correct. Use the URL `bootstrap` printed:

```
http://127.0.0.1:5173/?product_id=<uuid>
                      &redirect_url=http://127.0.0.1:5173
                      &code_challenge=<base64url(sha256(verifier))>
                      &code_challenge_method=S256
                      &state=<random>
```

Then exchange the returned `?code=` at `POST /auth/token` with the original
verifier. `alora-auth-ui/e2e/auth.spec.js` does exactly this and is the clearest
working example.

To drive it from a shell — this is the whole flow, and it is the exact sequence
used to verify these instructions:

```bash
PRODUCT=<product uuid from bootstrap>
VERIFIER=$(openssl rand -hex 32)
CHALLENGE=$(printf "%s" "$VERIFIER" | openssl dgst -sha256 -binary             | openssl base64 | tr '+/' '-_' | tr -d '=
')

CODE=$(curl -s -X POST http://127.0.0.1:3001/auth/authorize   -H 'Content-Type: application/json'   -d "{\"email\":\"admin@acme.com\",\"password\":\"…\",
       \"product_id\":\"$PRODUCT\",\"redirect_url\":\"http://127.0.0.1:5173\",
       \"code_challenge\":\"$CHALLENGE\",\"code_challenge_method\":\"S256\"}"   | grep -oE '"code":"[^"]+' | cut -d'"' -f4)

curl -s -X POST http://127.0.0.1:3001/auth/token   -H 'Content-Type: application/json'   -d "{\"code\":\"$CODE\",\"code_verifier\":\"$VERIFIER\",
       \"redirect_url\":\"http://127.0.0.1:5173\"}"
```

The code is single-use: exchanging it twice fails, by design.

---

## Running the tests

```bash
# API: unit + integration, against a throwaway PostgreSQL
cd alora-auth-api && ./scripts/integration-test.sh

# UI: end-to-end in a real browser, against the real API and database
cd alora-auth-api && ./scripts/e2e-up.sh      # database + API on :3001
cd ../alora-auth-ui && npm run test:e2e
cd ../alora-auth-api && ./scripts/e2e-up.sh --down
```

Nothing is mocked. The end-to-end suite exists because a mocked backend cannot
catch contract drift between the SPA and the API, which is the failure mode that
returns `200` while rendering nothing.

---

## How the pieces fit

```
Browser ──► alora-auth-ui  (Vite proxy)
                 │
                 ▼
            alora-auth-api  ──►  alora-auth-db
             Gin handlers          CALL stp_…
             no SQL                SELECT … udf_…
```

**The API runs no ad-hoc SQL.** Every database interaction is a call to a stored
procedure or function, so predicates, projections and tenant scoping live in one
reviewable place. `sqlc` reads `alora-auth-db` to generate typed Go bindings,
which makes a procedure-signature change a compile error rather than a runtime
one.

If you change the database:

```bash
cd alora-auth-db  && ./migrate.sh          # apply
cd ../alora-auth-api && sqlc generate && go build ./...
```

---

## Production notes

**Least-privilege database role.** By default the API connects as the owner. For
production, create the restricted role — it makes the audit trail append-only at
the database rather than by convention:

```bash
cd alora-auth-db
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v app_password="'…'" -f Security/roles.sql
# then: DATABASE_URL=postgres://alora_app:…@host:5432/alora
```

Two controls, and both are required. The role holds `INSERT` on `tbl_audit_logs`
and nothing else; and the trail's actor key is `ON DELETE RESTRICT`, so a user
who has done anything cannot be deleted. Without the second, the first is
theatre — a referential action runs as the referencing table's owner, so
deleting a user would strip the actor from existing audit rows while every
direct `UPDATE` stayed denied. `roles.sql` refuses to finish if either has
drifted.

`cmd/bootstrap` still connects as the **owner**: subscribing a tenant to a
product is provisioning, and `alora_app` deliberately cannot write
`tbl_client_products`.

**Set `TRUSTED_PROXIES`** to your load balancer's CIDRs. It defaults to trusting
nothing; leaving it empty behind a proxy makes every client look like the proxy
and collapses per-IP rate limiting.

**Set `NODE_ENV=production`.** It is what turns on `Secure` cookies, HSTS, the
placeholder-secret rejection and the `COOKIE_SECRET` length floor. The value is
checked against an allowlist, so a typo is a startup failure rather than a
silently insecure deployment.

**Known limitation — single instance.** OAuth state is held in process, so the
Google callback breaks across replicas: the callback may land on a different pod
than the one that started the flow. Running more than one instance needs that
state externalised to Redis first.

---

## Documentation

| Document | What it covers |
|---|---|
| [`alora-auth-db/README.md`](alora-auth-db/README.md) | Database conventions, the PostgreSQL constraints that shaped them |
| [`alora-auth-db/Migrations/README.md`](alora-auth-db/Migrations/README.md) | When a change needs a migration, and when it does not |
| [`alora-auth-api/ARCHITECTURE.md`](alora-auth-api/ARCHITECTURE.md) | Layering, request lifecycle, threat model → controls |
| [`alora-auth-api/JUSTIFICATION.md`](alora-auth-api/JUSTIFICATION.md) | Construct-level audit: why each piece exists, what breaks without it |
| [`MIGRATION_SPEC.md`](MIGRATION_SPEC.md) | The behavioural contract, including exact security invariants |

---

## Troubleshooting

**`bind: An attempt was made to access a socket in a way forbidden…`**
Windows has reserved the port into its dynamic-exclusion range; nothing is
listening, but it cannot be bound. Use another:
`ALORA_DB_PORT=55600 ./scripts/e2e-up.sh` (set the same variable for the UI's
end-to-end run, so its seed helper finds the container).

**A shell script exits with no output at all.**
Usually `openssl` failing silently because `MSYS_NO_PATHCONV=1` was exported
globally — it stops Git Bash converting `/tmp/x` into a Windows path, which
native binaries need. Scope it to `docker` only; the scripts here do.

**`type "idpprovider" does not exist`**
The enum types are created quoted, so `pg_type.typname` keeps its mixed case.
Compare against `'IdpProvider'`, not the lower-cased form.

**`/auth/authorize` returns `Invalid request` and the code challenge looks right.**
Check its length — it must be exactly 43 characters. On Git Bash, `openssl
base64` ends its output with CRLF, and a `tr -d '=
'` that omits `` leaves the
carriage return in your JSON. The server reports an invalid character in a string
literal, which does not obviously point at the challenge. Strip `` too, as the
snippet above does.

**API exits at startup with a config error.**
That is the intended behaviour. Required variables are listed in
`alora-auth-api/.env.example`; the message names the one that is missing.
