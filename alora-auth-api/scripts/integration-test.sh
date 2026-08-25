#!/usr/bin/env bash
# Spin up a throwaway Postgres, apply migrations, run the integration suite.
#   bash scripts/integration-test.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Host port for the throwaway PostgreSQL. Overridable because Windows can reserve
# a port into its dynamic-exclusion range, after which binding fails even though
# nothing is listening ("access permissions" from docker). Pick another and go.
DB_PORT="${ALORA_DB_PORT:-55532}"

# Path conversion is disabled ONLY for docker, whose container-side paths must
# stay POSIX. Exporting it globally breaks native Windows binaries such as
# openssl, which need a converted host path for -out -- and it fails silently.
d() { MSYS_NO_PATHCONV=1 docker "$@"; }

CID=$(d run -d --rm -p "$DB_PORT":5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=alora_test postgres:16-alpine)
cleanup() { d stop "$CID" >/dev/null 2>&1 || true; }
trap cleanup EXIT

for _ in $(seq 1 40); do sleep 2; d exec "$CID" pg_isready -U postgres -d alora_test >/dev/null 2>&1 && break; done
# The database repo (alora-auth-db) owns one idempotent build script that applies
# every object -- tables, views, functions and procedures -- in dependency order.
d cp ../alora-auth-db "$CID:/db" >/dev/null
d exec -w /db "$CID" psql -U postgres -d alora_test -v ON_ERROR_STOP=1 -q -f build.sql

TMP=$(mktemp -d)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/priv.pem" 2>/dev/null
openssl rsa -in "$TMP/priv.pem" -pubout -out "$TMP/pub.pem" 2>/dev/null

export ALORA_TEST_DB="postgres://postgres:test@127.0.0.1:$DB_PORT/alora_test"
export ALORA_TEST_PRIV="$(cat "$TMP/priv.pem")"
export ALORA_TEST_PUB="$(cat "$TMP/pub.pem")"

go test ./... "$@"
