---
type: Playbook
title: Run the stack and the tests
description: Focused and full test runs, a fast persistent dev database, the end-to-end stack, the generated-file check, and Windows notes.
tags: [testing, docker, playwright, windows]
status: stable
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-03T17:47:32Z }
stale_after: 2027-01-03T00:00:00Z
sources:
  - id: itest
    resource: ../../../alora-auth-api/scripts/integration-test.sh
    title: Integration test runner
  - id: e2e
    resource: ../../../alora-auth-api/scripts/e2e-up.sh
    title: End-to-end stack
  - id: e2ereadme
    resource: ../../../alora-auth-ui/e2e/README.md
    title: The browser suite
  - id: readme
    resource: ../../../README.md
    title: README — prerequisites, troubleshooting
---

# Run the stack and the tests

Needs Go 1.26+, Node 20+, Docker running (`docker info`), and sqlc v1.31.1 for
database changes. `psql` is optional: the scripts use the container's.[^readme]

## API tests — simplest

```bash
cd alora-auth-api
bash scripts/integration-test.sh                    # whole module, fresh throwaway Postgres on :55533
bash scripts/integration-test.sh -run 'SeatLimit'   # focus: -run is an unanchored regex over test names
```

Each run builds a new database from `alora-auth-db` and connects as `alora_app`,
exactly as production does.[^itest] Use it for the final, full run. Check that a
focused run printed the tests you meant: a pattern that matches nothing still
says `ok`.

## A fast loop: a persistent dev database

Agent shells keep no state between calls, so the recipe writes an env file to
`source` each time. Run from the repository root.

```bash
# Once: start Postgres and make a signing key
d() { MSYS_NO_PATHCONV=1 docker "$@"; }        # path conversion off for docker only
DEV=/tmp/alora-dev; mkdir -p "$DEV"
d run -d --name alora-dev -p 127.0.0.1:55540:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=alora_test \
  --tmpfs /var/lib/postgresql/data postgres:16-alpine -c fsync=off -c synchronous_commit=off
for i in $(seq 200); do d exec alora-dev pg_isready -h 127.0.0.1 -U postgres -d alora_test >/dev/null 2>&1 && break; done
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$DEV/priv.pem" 2>/dev/null
openssl rsa -in "$DEV/priv.pem" -pubout -out "$DEV/pub.pem" 2>/dev/null
cat > "$DEV/env.sh" <<EOF
export ALORA_TEST_DB=postgres://alora_app:app-test@127.0.0.1:55540/alora_test
export ALORA_TEST_OWNER_DB=postgres://postgres:test@127.0.0.1:55540/alora_test
export ALORA_TEST_PRIV="\$(cat $DEV/priv.pem)"
export ALORA_TEST_PUB="\$(cat $DEV/pub.pem)"
EOF

# After every change under alora-auth-db: rebuild from scratch
d exec alora-dev sh -c 'rm -rf /db'            # docker cp NESTS into an existing directory
d exec alora-dev psql -h 127.0.0.1 -U postgres -d alora_test -q -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
d cp ./alora-auth-db alora-dev:/db
d exec -w /db alora-dev psql -h 127.0.0.1 -U postgres -d alora_test -v ON_ERROR_STOP=1 -q -f build.sql
d exec -w /db alora-dev psql -h 127.0.0.1 -U postgres -d alora_test -v ON_ERROR_STOP=1 -q \
  -v app_password="'app-test'" -f Security/roles.sql

# Each test run
source /tmp/alora-dev/env.sh
cd alora-auth-api && go test -count=1 -v -run 'SeatLimit' ./cmd/api/ | grep -E '^(--- |ok|FAIL)'

# Done with it
docker rm -f alora-dev
```

Check readiness over TCP (`-h 127.0.0.1`): during first start the image runs a
socket-only server, and a socket check passes too early. Remove only containers
you started.

## End to end, in a real browser

```bash
cd alora-auth-api && bash scripts/e2e-up.sh      # Postgres :55532, API :3001, gRPC :3002, the Owner
cd ../alora-auth-ui && npx playwright test       # starts Vite on :5173; serial
cd ../alora-auth-api && bash scripts/e2e-up.sh --down
```

`e2e-up.sh` refuses to start if something already answers on `:3001`. It writes
`stack.json`, with the Owner's credentials, to Node's temp directory under
`alora-e2e/`; specs seed their own companies, and budgets are raised with
`RATE_LIMIT_SCALE`.[^e2e] To exercise the API by hand, seed a company against the
stack's database. It prints the product's client secret once:

```bash
cd alora-auth-api
DATABASE_URL=postgres://postgres:test@127.0.0.1:55532/alora_e2e BOOTSTRAP_PASSWORD='choose-one-12+' \
  go run ./cmd/bootstrap demo -company "QA Corp" -email admin@qa.test \
  -product CRM -product-name "QA CRM" -base-url http://127.0.0.1:4100/ \
  -initiate-login-uri http://127.0.0.1:4100/login/initiate \
  -redirect-uri http://127.0.0.1:4100/callback -roles Admin,Editor,Viewer
```

What each spec covers: `alora-auth-ui/e2e/README.md`.[^e2ereadme]

## Before you call it done

```bash
bash scripts/check-generated.sh            # repository root: DB objects, sqlc, OpenAPI, protos
cd alora-auth-go && go test ./...          # the Go helper, when it or the token endpoint changed
```

## Timing

The first `go build` or `go test` after sqlc or model changes recompiles widely and
can take minutes. The full `cmd/api` suite takes a few minutes, and Playwright about
a quarter of an hour, serially. Run them in the background, and keep their output
out of the main conversation.

## Windows

- Run the scripts from Git Bash.
- Set `MSYS_NO_PATHCONV=1` only around `docker`. Exported globally, it makes
  native `openssl` fail silently.
- Native `openssl` ends output with CRLF; strip it (`| tr -d '\r\n'`).
- A "forbidden" socket error means the port is in Windows' reserved range (see
  `netsh int ipv4 show excludedportrange protocol=tcp`). Pick another:
  `ALORA_DB_PORT=55600 bash scripts/integration-test.sh`.

[^readme]: README — prerequisites, troubleshooting
[^itest]: Integration test runner
[^e2e]: End-to-end stack
[^e2ereadme]: The browser suite
