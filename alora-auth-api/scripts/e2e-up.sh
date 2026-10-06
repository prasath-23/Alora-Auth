#!/usr/bin/env bash
# Bring up everything the Playwright suite needs:
#   - a throwaway Postgres with the schema and the least-privilege role,
#   - the Go API on :3001 (the port the Vite proxy targets), running as that
#     role exactly as in production, with its gRPC TokenService on :3002,
#   - the platform company and its first Owner (cmd/bootstrap platform),
#   - stack.json, which e2e/seed.js reads to seed each spec.
#
# App Central is served by Vite on http://localhost:5173 and proxies the API,
# so the issuer and the frontend are that one origin. Products under test run
# on 127.0.0.1 — a different host, so they never share App Central's cookies.
#
#   bash scripts/e2e-up.sh          # start
#   bash scripts/e2e-up.sh --down   # stop
set -euo pipefail
cd "$(dirname "$0")/.."

# Host port for the throwaway PostgreSQL. Overridable because Windows can reserve
# a port into its dynamic-exclusion range, after which binding fails even though
# nothing is listening ("access permissions" from docker). Pick another and go.
DB_PORT="${ALORA_DB_PORT:-55532}"

# Path conversion is disabled ONLY for docker, whose container-side paths must
# stay POSIX. Exporting it globally would break native Windows binaries like
# openssl, which need a converted host path for -out.
d() { MSYS_NO_PATHCONV=1 docker "$@"; }
# A native Windows openssl ends its output with CRLF, and $(…) strips only the
# LF: the carriage return would ride along into every secret.
rand() { openssl rand "$@" | tr -d '\r\n'; }

# The state directory must be the one e2e/seed.js reads: Node's temp directory
# unless ALORA_E2E_STATE names another. Asking Node is what keeps the two in
# step on Windows, where bash's /tmp and Node's tmpdir are spelled differently.
STATE_DIR="${ALORA_E2E_STATE:-$(node -e "process.stdout.write(require('path').join(require('os').tmpdir(), 'alora-e2e'))")}"
mkdir -p "$STATE_DIR"

stop() {
  [ -f "$STATE_DIR/api.pid" ] && kill "$(cat "$STATE_DIR/api.pid")" 2>/dev/null || true
  [ -f "$STATE_DIR/cid" ] && d stop "$(cat "$STATE_DIR/cid")" >/dev/null 2>&1 || true
  rm -f "$STATE_DIR/api.pid" "$STATE_DIR/cid" "$STATE_DIR/stack.json"
}

if [ "${1:-}" = "--down" ]; then
  stop
  echo "e2e stack stopped"
  exit 0
fi

# A second API on :3001 would leave the specs talking to whichever won the port.
if curl -sf http://127.0.0.1:3001/health >/dev/null 2>&1; then
  echo "something already answers on :3001 — run: bash scripts/e2e-up.sh --down" >&2
  exit 1
fi
stop

echo "==> starting postgres"
CID=$(d run -d --rm -p "127.0.0.1:$DB_PORT":5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=alora_e2e postgres:16-alpine)
echo "$CID" > "$STATE_DIR/cid"
for _ in $(seq 1 40); do sleep 2; d exec "$CID" pg_isready -U postgres -d alora_e2e >/dev/null 2>&1 && break; done

echo "==> building database objects"
# The database repo (alora-auth-db) owns one idempotent build script that applies
# every object -- tables, views, functions and procedures -- in dependency order.
d cp ../alora-auth-db "$CID:/db" >/dev/null
d exec -w /db "$CID" psql -U postgres -d alora_e2e -v ON_ERROR_STOP=1 -q -f build.sql
d exec -w /db "$CID" psql -U postgres -d alora_e2e -v ON_ERROR_STOP=1 -q \
  -v app_password="'app-e2e'" -f Security/roles.sql

echo "==> generating signing keys"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$STATE_DIR/priv.pem" 2>/dev/null
openssl rsa -in "$STATE_DIR/priv.pem" -pubout -out "$STATE_DIR/pub.pem" 2>/dev/null

echo "==> building the API, bootstrap and the gRPC demo"
go build -o "$STATE_DIR/api.exe" ./cmd/api
go build -o "$STATE_DIR/bootstrap.exe" ./cmd/bootstrap
# The demo product and application (alora-auth-go/examples/grpcdemo), which
# grpc.spec.js runs against this stack.
(cd ../alora-auth-go && go build -o "$STATE_DIR/demo-server.exe" ./examples/grpcdemo/server \
  && go build -o "$STATE_DIR/demo-client.exe" ./examples/grpcdemo/client)

ISSUER="http://localhost:5173"
# The schema owner seeds (the app role cannot write Owners, by design); the API
# itself connects as alora_app.
OWNER_DSN="postgres://postgres:test@127.0.0.1:$DB_PORT/alora_e2e"
APP_DSN="postgres://alora_app:app-e2e@127.0.0.1:$DB_PORT/alora_e2e"
OWNER_EMAIL="owner@alora-e2e.test"
OWNER_PASSWORD="e2e-$(rand -hex 12)"

echo "==> provisioning the platform Owner"
DATABASE_URL="$OWNER_DSN" BOOTSTRAP_PASSWORD="$OWNER_PASSWORD" \
  "$STATE_DIR/bootstrap.exe" platform -name "Alora Platform" -email "$OWNER_EMAIL" >/dev/null

echo "==> starting the API on :3001 (gRPC on :3002)"
# Google is left unconfigured: its round trip needs Google. Company SSO works
# against any OpenID provider, so its key is set. gRPC is plaintext here, as it
# may be outside production.
# RATE_LIMIT_*: the suite drives every flow from one address, far faster than
# any person; the budgets are raised so a spec is never throttled mid-flow.
NODE_ENV=development \
PORT=3001 HOST=127.0.0.1 GRPC_PORT=3002 \
DATABASE_URL="$APP_DSN" \
JWT_PRIVATE_KEY="$(cat "$STATE_DIR/priv.pem")" \
JWT_PUBLIC_KEY="$(cat "$STATE_DIR/pub.pem")" \
JWT_KEY_ID=e2e-key JWT_ISSUER="$ISSUER" FRONTEND_URL="$ISSUER" \
COOKIE_SECRET="$(rand -hex 32)" \
SSO_SECRET_KEY="$(rand -base64 32)" \
RATE_LIMIT_SCALE=100 RATE_LIMIT_GLOBAL_MAX=100000 RATE_LIMIT_AUTHORIZE_IP_MAX=1000 \
  "$STATE_DIR/api.exe" > "$STATE_DIR/api.log" 2>&1 &
echo $! > "$STATE_DIR/api.pid"

for _ in $(seq 1 30); do
  sleep 1
  curl -sf http://127.0.0.1:3001/health/ready >/dev/null 2>&1 && break
done
curl -sf http://127.0.0.1:3001/health/ready >/dev/null || { echo "API failed to start:"; cat "$STATE_DIR/api.log"; exit 1; }

# Written by Node so every path is valid JSON, backslashes and all.
STACK="$STATE_DIR/stack.json" ISSUER="$ISSUER" OWNER_DSN="$OWNER_DSN" BOOTSTRAP="$STATE_DIR/bootstrap.exe" \
DEMO_SERVER="$STATE_DIR/demo-server.exe" DEMO_CLIENT="$STATE_DIR/demo-client.exe" \
OWNER_EMAIL="$OWNER_EMAIL" OWNER_PASSWORD="$OWNER_PASSWORD" node -e '
const e = process.env
require("fs").writeFileSync(e.STACK, JSON.stringify({
  issuer: e.ISSUER, api: "http://127.0.0.1:3001", grpc: "127.0.0.1:3002", ownerDsn: e.OWNER_DSN, bootstrap: e.BOOTSTRAP,
  owner: { email: e.OWNER_EMAIL, password: e.OWNER_PASSWORD },
  demo: { server: e.DEMO_SERVER, client: e.DEMO_CLIENT },
}, null, 2))'

echo "==> ready"
echo "    postgres : 127.0.0.1:$DB_PORT (db alora_e2e)"
echo "    api      : http://127.0.0.1:3001 (issuer $ISSUER, via Vite)"
echo "    grpc     : 127.0.0.1:3002 (TokenService, plaintext)"
echo "    state    : $STATE_DIR"
echo "    log      : $STATE_DIR/api.log"
