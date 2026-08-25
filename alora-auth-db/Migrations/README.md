# Migrations

Most schema changes do NOT belong here. The object scripts under `Tables/`,
`Views/` and `Programmability/` are idempotent and re-applied on every build, so
adding a column, an index, a view or a procedure is just an edit to the object's
own file.

A migration is for a change that **cannot be re-run safely**:

- renaming a column or table
- backfilling or transforming existing rows
- narrowing a type or adding a NOT NULL to a populated column
- dropping something (each drop needs a deliberate, reviewed record)

## Naming

```
NNNN_short_description.sql
0001_example_backfill.sql
```

Four-digit sequence, applied in filename order. Never renumber or edit an applied
script — the runner compares checksums and will refuse to continue if one
changed, because a silent edit leaves environments diverged with no signal.

## Rules

- One logical change per file.
- Wrap in `BEGIN; ... COMMIT;` so a failure leaves nothing half-applied.
- Guard anyway (`IF EXISTS`, `NOT EXISTS`) so a partially-applied environment can
  be brought forward.
- If a migration renames a column that a table script also defines, update the
  table script in the SAME commit — a fresh install runs the table script only,
  so the two must agree.

## Current state

This folder is intentionally EMPTY. Nothing has needed a run-once migration yet:
every change so far has been expressible as an edit to an idempotent object
script. The first entry will most likely be a column rename or a backfill after
the first production deployment.

## Running

`migrate.sh` applies the object build first, then any pending migrations, and
records each in `tbl_schema_migrations`.
