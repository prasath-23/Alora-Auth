#!/usr/bin/env bash
# Fails when a checked-in generated file differs from what its source produces,
# or when a generated file is checked in that its source no longer produces:
#
#   alora-auth-db   Tables/, Views/, Programmability/Functions/,
#                   Programmability/StoredProcedures/ and build.sql, from gen_*.py
#                   (Tables/tbl_schema_migrations.sql and
#                   Programmability/Types/enums.sql are hand-written)
#   alora-auth-api  internal/database/sqlc, from the database (sqlc v1.31.1)
#                   docs/, the OpenAPI document, from the annotations (swag v1.16.6)
#   alora-auth-go   authpb/ and the demo's inventorypb/, from proto/ (buf)
#
#   bash scripts/check-generated.sh
#
# A generator that cannot run is reported as such, with its output — never as
# drift. SQLC names the sqlc binary (default: sqlc on PATH, else ~/go/bin/sqlc);
# it must be v1.31.1. PYTHON names the interpreter (default: the first of
# python3 and python that runs).
set -uo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0

# The first interpreter that really runs: on Windows, "python3" may be a store
# stub that exists on PATH and does nothing.
if [ -z "${PYTHON:-}" ]; then
  for p in python3 python; do
    if "$p" -c 'import sys' >/dev/null 2>&1; then PYTHON="$p"; break; fi
  done
fi
SQLC="${SQLC:-$(command -v sqlc || echo "$HOME/go/bin/sqlc")}"

echo "==> database objects (gen_*.py)"
cp -r alora-auth-db "$tmp/db"
if (
  cd "$tmp/db" || exit 1
  find Tables -name '*.sql' ! -name 'tbl_schema_migrations.sql' -delete
  rm -rf Views Programmability/Functions Programmability/StoredProcedures build.sql
  for g in gen_tables gen_views gen_functions gen_procedures gen_build; do
    "$PYTHON" "$g.py" >"$tmp/$g.log" 2>&1 || { echo "$g.py did not run:"; cat "$tmp/$g.log"; exit 1; }
  done
); then
  diff -r -q -x '__pycache__' alora-auth-db "$tmp/db" || fail=1
else
  fail=1
fi

echo "==> sqlc code"
if ! "$SQLC" version 2>/dev/null | grep -q 'v1.31.1'; then
  echo "sqlc v1.31.1 is required (found: $("$SQLC" version 2>&1 | head -1)); set SQLC"
  fail=1
else
  (cd alora-auth-api && "$SQLC" diff) || fail=1
fi

echo "==> OpenAPI document (swag)"
if (cd alora-auth-api && go run github.com/swaggo/swag/cmd/swag@v1.16.6 init -q -g cmd/api/swagger.go \
  -o "$tmp/docs" --parseInternal --parseDepth 2) >"$tmp/swag.log" 2>&1; then
  diff -r -q alora-auth-api/docs "$tmp/docs" || fail=1
else
  echo "swag did not run:"
  cat "$tmp/swag.log"
  fail=1
fi

echo "==> protos (buf)"
bash alora-auth-go/scripts/generate.sh --check || fail=1

if [ "$fail" -ne 0 ]; then
  echo "FAIL: see above — a generator that did not run, or generated code that is out of date"
  exit 1
fi
echo "==> every generated file matches its source"
