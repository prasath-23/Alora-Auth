# Database — structure and conventions

The API never runs a query against a table. It calls stored procedures and
functions only, so every predicate, projection and tenant check lives here and
can be reviewed in one place.

## Layout

One file per object, mirroring the house layout used across our SQL Server
projects:

```
db/
├── Tables/                              tbl_*.sql   (15)
├── Views/                               vw_*.sql    (18)
├── Programmability/
│   ├── Types/                           enums
│   ├── StoredProcedures/                stp_*.sql   (38)  writes
│   └── Functions/
│       ├── Scalar-valued Functions/     udf_*.sql   ( 9)  single-value reads
│       └── Table-valued Functions/      udf_*.sql   (31)  row-set reads
├── api/                                 the API's call surface (78 operations)
├── data/                                seed / reference data
└── build.sql                            applies everything, in order
```

## Naming

| Prefix | Object | Purpose |
|---|---|---|
| `tbl_` | TABLE | storage |
| `vw_` | VIEW | reusable projection; carries standing predicates |
| `udf_` | FUNCTION (`STABLE`) | reads |
| `stp_` | PROCEDURE, or `VOLATILE` FUNCTION where a value must be returned | writes |

Constraints are always explicitly named — never left to PostgreSQL's generated
names, which differ between databases and make `DROP CONSTRAINT` unreliable
during migration:

`PK_<table>` · `FK_<child>_<parent>_<cols>` · `UQ_<table>_<cols>` ·
`IX_<table>_<cols>`

Parameters are `p_camelCase`, so a parameter can never be mistaken for a column
of the same name inside a body.

## Two PostgreSQL constraints worth knowing

**1. `stp_` is sometimes a FUNCTION, not a PROCEDURE.** A PostgreSQL procedure
cannot return a result set, and its `INOUT` parameters are not usable through the
query interface this API uses. So a write that must return the inserted row or an
affected-row count is implemented as a `VOLATILE` function. Each file states
which form it uses and why. Writes returning nothing are true procedures, called
with `CALL`.

**2. A scalar function always returns one row, possibly NULL.** `SELECT
udf_Something(...)` therefore never produces "no rows", so a lookup whose answer
may be absent is wrapped in `db/api`:

```sql
SELECT id FROM (SELECT udf_ActiveSubscriptionId($1, $2) AS id) t
WHERE id IS NOT NULL;
```

That turns "not found" into zero rows, which is what the caller distinguishes.
Without the wrapper a missing row surfaces as a NULL-scan error — a 500 where a
403 was intended.

## Views are the projection mechanism

A read function declares `RETURNS SETOF vw_Something`. That is what lets it
return a narrow, secret-minimised shape instead of a whole table row — for
example `vw_SessionSummary` omits `refresh_token_hash`, `prev_token_hash`,
`revoked_reason` and `user_id`, so no caller can leak token material even by
accident.

Views also carry the STANDING predicates. "Active session", "pending
invitation", "redeemable reset token" are each defined exactly once, and every
function built on them inherits the definition.

## Idempotency

`build.sql` is safe to re-run, so it serves as both a fresh install and an
upgrade:

```bash
psql -v ON_ERROR_STOP=1 -f db/build.sql
```

- Tables use `CREATE TABLE IF NOT EXISTS`; constraints are guarded against
  `pg_constraint`; indexes use `IF NOT EXISTS`.
- Views, functions and procedures use `CREATE OR REPLACE`.
- Enum types are the exception. They are written as plain `CREATE TYPE` because a
  `DO`-block guard makes them invisible to sqlc's parser, which silently degrades
  every enum to `interface{}` and every enum array to `[]interface{}` in the
  generated Go. `build.sql` therefore contains a guarded copy generated from the
  same file — see `gen_build.py`, so the two cannot drift.

## Regenerating

The object files are generated so the layout stays consistent across 100+ files:

```bash
python db/gen_tables.py       # Tables/
python db/gen_views.py        # Views/
python db/gen_functions.py    # Functions/
python db/gen_procedures.py   # StoredProcedures/
python db/gen_build.py        # build.sql, from whatever is on disk
sqlc generate                 # typed Go bindings for db/api
```

`gen_build.py` reads the filesystem, so adding an object file is enough to
include it in the build — there is no hand-maintained list to fall out of date.

## Verifying a change

```bash
bash scripts/integration-test.sh   # throwaway Postgres + build.sql + Go tests
```

The build is verified by applying it to a clean PostgreSQL 16 three times in a
row: the first proves it installs, the second and third prove it is idempotent.
