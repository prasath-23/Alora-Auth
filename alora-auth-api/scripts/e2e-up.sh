#!/usr/bin/env bash
# Bring up everything the Playwright suite needs: Postgres + migrations + the Go
# API on :3001 (the port the Vite proxy targets).
#
#   bash scripts/e2e-up.sh          # start
#   bash scripts/e2e-up.sh --down   # stop
set -euo pipefail
cd "$(dirname "$0")/.."

# Path conversion is disabled ONLY for docker, whose container-side paths must
# stay POSIX. Exporting it globally would break native Windows binaries like
# openssl, which need a converted host path for -out.
d() { MSYS_NO_PATHCONV=1 docker "$@"; }

STATE_DIR="${TMPDIR:-/tmp}/alora-e2e"
mkdir -p "$STATE_DIR"

if [ "${1:-}" = "--down" ]; then
  [ -f "$STATE_DIR/api.pid" ] && kill "$(cat "$STATE_DIR/api.pid")" 2>/dev/null || true
  [ -f "$STATE_DIR/cid" ] && d stop "$(cat "$STATE_DIR/cid")" >/dev/null 2>&1 || true
  rm -f "$STATE_DIR/api.pid" "$STATE_DIR/cid"
  echo "e2e stack stopped"
  exit 0
fi

echo "==> starting postgres"
CID=$(d run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=alora_e2e postgres:16-alpine)
echo "$CID" > "$STATE_DIR/cid"
for _ in $(seq 1 40); do sleep 2; d exec "$CID" pg_isready -U postgres -d alora_e2e >/dev/null 2>&1 && break; done

echo "==> building database objects"
# The database repo (alora-auth-db) owns one idempotent build script that applies
# every object -- tables, views, functions and procedures -- in dependency order.
d cp ../alora-auth-db "$CID:/db" >/dev/null
d exec -w /db "$CID" psql -U postgres -d alora_e2e -v ON_ERROR_STOP=1 -q -f build.sql

echo "==> generating signing keys"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$STATE_DIR/priv.pem" 2>/dev/null
openssl rsa -in "$STATE_DIR/priv.pem" -pubout -out "$STATE_DIR/pub.pem" 2>/dev/null

echo "==> building + starting the API on :3001"
go build -o "$STATE_DIR/api.exe" ./cmd/api
NODE_ENV=development \
PORT=3001 HOST=127.0.0.1 \
DATABASE_URL="postgres://postgres:test@127.0.0.1:55432/alora_e2e" \
JWT_PRIVATE_KEY="$(cat "$STATE_DIR/priv.pem")" \
JWT_PUBLIC_KEY="$(cat "$STATE_DIR/pub.pem")" \
JWT_KEY_ID=e2e-key JWT_ISSUER=https://auth.alora.test \
COOKIE_SECRET=0123456789012345678901234567890123456789 \
GOOGLE_CLIENT_ID=e2e-gid GOOGLE_CLIENT_SECRET=e2e-gsecret \
GOOGLE_REDIRECT_URI=http://127.0.0.1:3001/auth/google/callback \
FRONTEND_URL=http://127.0.0.1:5173 \
  "$STATE_DIR/api.exe" > "$STATE_DIR/api.log" 2>&1 &
echo $! > "$STATE_DIR/api.pid"

for _ in $(seq 1 30); do
  sleep 1
  curl -sf http://127.0.0.1:3001/health >/dev/null 2>&1 && break
done
curl -sf http://127.0.0.1:3001/health >/dev/null || { echo "API failed to start:"; cat "$STATE_DIR/api.log"; exit 1; }

echo "==> ready"
echo "    postgres : 127.0.0.1:55432 (db alora_e2e)"
echo "    api      : http://127.0.0.1:3001"
echo "    log      : $STATE_DIR/api.log"
