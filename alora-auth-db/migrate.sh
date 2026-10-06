#!/usr/bin/env bash
#
# Applies the database: idempotent object scripts first, then any pending
# versioned migrations, recording each one in tbl_schema_migrations.
#
#   ./migrate.sh                                    # uses $DATABASE_URL
#   ./migrate.sh "postgres://user:pw@host:5432/db"   # explicit target
#   ./migrate.sh --status                            # report, change nothing
#   ./migrate.sh --docker                            # throwaway container (dev)
#
# Order is deliberate: the object build runs FIRST so tbl_schema_migrations and
# every table exist before a migration tries to alter them.
set -euo pipefail
cd "$(dirname "$0")"

MODE=apply
TARGET="${DATABASE_URL:-}"

# Host port for --docker. Overridable because Windows can reserve a port into its
# dynamic-exclusion range, after which binding fails even though nothing is
# listening ("access permissions" from docker). Pick another and go.
DB_PORT="${ALORA_DB_PORT:-55534}"

for arg in "$@"; do
  case "$arg" in
    --status) MODE=status ;;
    --docker) MODE=docker ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) TARGET="$arg" ;;
  esac
done

# --docker spins up a throwaway PostgreSQL so the whole build can be verified
# without touching a real database.
CONTAINER=""
cleanup() { [ -n "$CONTAINER" ] && docker stop "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if [ "$MODE" = docker ]; then
  echo "==> starting throwaway PostgreSQL"
  CONTAINER=$(MSYS_NO_PATHCONV=1 docker run -d --rm -p "127.0.0.1:$DB_PORT":5432 \
    -e POSTGRES_PASSWORD=test -e POSTGRES_DB=alora postgres:16-alpine)
  for _ in $(seq 1 40); do
    sleep 2
    MSYS_NO_PATHCONV=1 docker exec "$CONTAINER" pg_isready -U postgres -d alora >/dev/null 2>&1 && break
  done
  TARGET="postgres://postgres:test@127.0.0.1:$DB_PORT/alora"
  MODE=apply
fi

if [ -z "$TARGET" ]; then
  echo "error: no target database. Set DATABASE_URL, pass a connection string, or use --docker." >&2
  exit 2
fi

# psql is required locally; when only Docker is available the container's client
# is used instead, so a developer without a local psql can still run this.
if command -v psql >/dev/null 2>&1; then
  psql_run() { psql "$TARGET" -v ON_ERROR_STOP=1 "$@"; }
elif [ -n "$CONTAINER" ]; then
  MSYS_NO_PATHCONV=1 docker cp . "$CONTAINER:/db" >/dev/null
  psql_run() { MSYS_NO_PATHCONV=1 docker exec -w /db "$CONTAINER" psql -U postgres -d alora -v ON_ERROR_STOP=1 "$@"; }
else
  # Reached only for a real target with no local client. The container fallback
  # above needs a container this script started, and a client container cannot
  # be pointed at an arbitrary host database reliably across platforms -- the
  # loopback in the URL would resolve to the container itself.
  cat >&2 <<'MSG'
error: psql is required to apply to this database, and was not found on PATH.

  * to verify the build with no local PostgreSQL:  ./migrate.sh --docker
  * to apply to a real database:                   install the PostgreSQL client
      Windows   winget install PostgreSQL.PostgreSQL.16
      macOS     brew install libpq
      Debian    apt-get install postgresql-client
MSG
  exit 2
fi

query() { psql_run -t -A -c "$1"; }

# ---------------------------------------------------------------------------
# 1. Object build. Idempotent, so this is both a fresh install and an upgrade.
# ---------------------------------------------------------------------------
if [ "$MODE" = apply ]; then
  echo "==> applying object build (tables, views, functions, procedures)"
  psql_run -q -f build.sql
fi

# ---------------------------------------------------------------------------
# 2. Versioned migrations, in filename order, each exactly once.
# ---------------------------------------------------------------------------
shopt -s nullglob
FILES=(Migrations/[0-9]*.sql)
shopt -u nullglob

if [ ${#FILES[@]} -eq 0 ]; then
  echo "==> no migration scripts"
  exit 0
fi

# A checksum mismatch means an APPLIED script was edited afterwards. Continuing
# would leave this database permanently different from a fresh install, with no
# record of the difference — so it is a hard stop, not a warning.
pending=0
for f in "${FILES[@]}"; do
  version=$(basename "$f" .sql)
  sum=$(sha256sum "$f" | cut -d' ' -f1)
  recorded=$(query "SELECT checksum FROM tbl_schema_migrations WHERE version = '$version'" || true)

  if [ -z "$recorded" ]; then
    pending=$((pending + 1))
    if [ "$MODE" = status ]; then
      echo "  PENDING  $version"
      continue
    fi
    echo "==> applying $version"
    start=$(date +%s%3N 2>/dev/null || echo 0)
    psql_run -q -f "$f"
    end=$(date +%s%3N 2>/dev/null || echo 0)
    psql_run -q -c "INSERT INTO tbl_schema_migrations (version, checksum, duration_ms)
                    VALUES ('$version', '$sum', $((end - start)))"
  elif [ "$recorded" != "$sum" ]; then
    echo "ERROR: $version was modified after it was applied." >&2
    echo "       recorded: $recorded" >&2
    echo "       on disk:  $sum" >&2
    echo "       Applied migrations are immutable. Add a NEW migration instead." >&2
    exit 1
  elif [ "$MODE" = status ]; then
    echo "  applied  $version"
  fi
done

if [ "$MODE" = status ]; then
  echo "==> $pending pending, $(( ${#FILES[@]} - pending )) applied"
else
  echo "==> up to date ($pending applied this run)"
fi
