---
type: Playbook
title: Change a database object
description: Table, view, function, procedure or enum value — edit the generator, grant, bind with sqlc, wrap in a table service, prove it.
tags: [database, sqlc, generators, postgres, migrations]
status: stable
generated: { by: claude-code/claude-opus-5-5, at: 2026-10-03T17:47:32Z }
stale_after: 2027-01-03T00:00:00Z
sources:
  - id: db-readme
    resource: ../../../alora-auth-db/README.md
    title: Database conventions
  - id: check
    resource: ../../../scripts/check-generated.sh
    title: Generated-file check
  - id: build
    resource: ../../../alora-auth-db/gen_build.py
    title: Build-script generator (TABLE_ORDER)
  - id: roles
    resource: ../../../alora-auth-db/Security/roles.sql
    title: The application role's grants
  - id: migrations
    resource: ../../../alora-auth-db/Migrations/README.md
    title: When a change needs a migration
  - id: sqlc
    resource: ../../../alora-auth-api/sqlc.yaml
    title: sqlc configuration
---

# Change a database object

> [!WARNING]
> Never hand-edit `Tables/`, `Views/`, `Programmability/Functions/`,
> `Programmability/StoredProcedures/` or `build.sql`. They are generated:
> `scripts/check-generated.sh` deletes them, regenerates them and fails on any
> difference.[^check] Hand-written files: `Programmability/Types/enums.sql`,
> `Tables/tbl_schema_migrations.sql`, `Security/roles.sql`, `Migrations/*` and the
> queries in `api/*.sql`.

## 1. Edit the generator that owns the object

All under `alora-auth-db/`:

| Object | Generator · list | Notes |
|---|---|---|
| Table | `gen_tables.py` · `TABLES` | A tuple: `(table, purpose, [(column, type, extra)], [pk columns], [(index, columns, kind, predicate, note)], [(fk, child columns, parent table, parent columns, on delete, note)], notes)`. Seed rows go in `SEEDS`. A new table also goes in `TABLE_ORDER` in `gen_build.py`, after every table it references.[^build] |
| View | `gen_views.py` · `VIEWS` | Applied alphabetically, so a view reading another must sort after it. Cast computed columns (`::boolean`, `::int`): sqlc types columns from the cast, and an uncast `EXISTS` or aggregate becomes `interface{}`. |
| Read (`udf_`) | `gen_functions.py` · `SCALARS` or `TVFS` | `STABLE`. Table-valued functions return `SETOF vw_*` or `SETOF tbl_*` — a view gives a narrow, secret-minimised shape. |
| Write (`stp_`) | `gen_procedures.py` · `WRITES` or `EXPLICIT` | `WRITES` tuples are plain SQL: kind `"proc"` is a `CREATE PROCEDURE` called with `CALL`; `"func"` is a `VOLATILE` function, for when the caller needs a row or a count. Anything that takes a lock, guards or raises is plpgsql: move it to `EXPLICIT`, which holds the whole file text. |

Scope tenant data in the procedure (`WHERE client_id = p_clientId`); never trust
the caller to have done it.

## 2. Regenerate

```bash
cd alora-auth-db
python gen_procedures.py      # each generator you edited: gen_tables, gen_views, gen_functions, gen_procedures
python gen_build.py           # always
```

Use `python`; on Windows `python3` can be a Store stub that does nothing.

## 3. Grant what the application role needs

`Security/roles.sql` starts from `REVOKE ALL`, so a new table is unreachable by
`alora_app` until granted. Grant per verb — an `INSERT … ON CONFLICT DO UPDATE`
needs `UPDATE` too. Integration tests connect as `alora_app`, so a missing grant
fails as `permission denied`. Also add the table and verb to the fixed list in
`TestAppRoleHoldsWhatTheRoutinesNeed` (`cmd/api/schema_invariants_test.go`).
`roles.sql` refuses to finish if the audit, Owner, scope, secret or session
protections drift — never loosen them.[^roles]

## 4. Bind it with sqlc

Add a named query to `alora-auth-db/api/<area>.sql`. Each entry is either a
`CALL stp_…` or a `SELECT` from a function:

```sql
-- name: RevokeAllClientSessions :one
SELECT stp_RevokeAllClientSessions(sqlc.arg('client_id'), sqlc.arg('reason')::"SessionRevokedReason");
```

Then generate the bindings and check the signature in
`internal/database/sqlc/<area>.sql.go`:

```bash
cd alora-auth-api && sqlc generate        # sqlc v1.31.1
```

> [!WARNING]
> A function declared `RETURNS TABLE(...)` comes back as `interface{}`. Return
> a scalar (call it as `SELECT fn(…)`) or `SETOF` a view or table instead.

## 5. Wrap it in the table service

Put the method in `internal/database/services/<table>/<table>DbService.go`; views,
lookups and sweeps go in `customs/<table>DbCustoms.go`. The constructor takes a
`contexts.Querier`, so the same service runs on the pool or inside a transaction:

```go
tx, err := s.db.Begin(ctx)
defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
sessions.NewSessionDbService(tx).RevokeAllForClient(ctx, clientID, dbmodels.RevokeReasonSuspended)
// … other writes on tx …
err = tx.Commit(ctx)
```

Convert `pgtype` values to plain Go: in `internal/database/models` a nullable
column is a pointer. Feature services call table services, never `sqlc` directly
(`TestArchitecture`).

## 6. Refusals the API must answer

Raise a custom SQLSTATE in plpgsql and map it once in `MapError`
(`internal/exceptions/errors.go`). For example, `AL001` (a seat limit) becomes
409:

```sql
RAISE EXCEPTION 'company % is at its seat limit of %', p_clientId, v_max USING ERRCODE = 'AL001';
```

A bare `RAISE` is SQLSTATE `P0001`, which becomes a 500. The other convention, for
functions returning a count, is a negative sentinel (`-1` = not found in this
tenant), translated in the feature service. A race-safe limit locks the row it
counts against first (`SELECT … FOR UPDATE`).

## 7. Prove it

1. Rebuild a database and run the focused tests: [dev-and-test](./dev-and-test.md).
2. Run the full API suite, and check it really ran (minutes, not seconds).
3. Run `bash scripts/check-generated.sh` from the repository root.

## Enum values

Enum types are plain `CREATE TYPE` statements in
`Programmability/Types/enums.sql` (a guard would hide them from sqlc), and
`build.sql` includes them only when the types are absent. So an existing database
never gains a new value from a rebuild:

1. Add the value to `enums.sql`, for fresh builds.
2. Add the next migration for built databases, and a row in
   `Migrations/README.md`:[^migrations]
   ```sql
   BEGIN;
   ALTER TYPE "SessionRevokedReason" ADD VALUE IF NOT EXISTS 'SUSPENDED';
   COMMIT;
   ```
   A transaction may add a value but not use it. `IF NOT EXISTS` makes the
   migration a no-op on a fresh build. Never edit an applied migration:
   `migrate.sh` refuses on a checksum change.
3. Add the Go constant in `alora-auth-api/internal/database/models/enums.go`, then
   run `sqlc generate`.
4. Rebuild your local database from scratch; re-running `build.sql` will not add
   the value.

Enum type names are quoted and mixed-case: compare
`pg_type.typname = 'SessionRevokedReason'`.

## When a migration is needed

Rarely. Object scripts are idempotent and re-applied on every build, so a new
column, index, view or procedure needs no migration. Migrations are for what
cannot be re-run: a rename, a backfill, a narrowed type, a drop, or an enum
value.[^migrations]

## Notes

- PostgreSQL only syntax-checks plpgsql at `CREATE`, so a procedure may call one
  that is created later in the build.
- `migrate.sh --docker` verifies the whole build in a throwaway container.

[^check]: Generated-file check
[^build]: Build-script generator (TABLE_ORDER)
[^roles]: The application role's grants
[^migrations]: When a change needs a migration
