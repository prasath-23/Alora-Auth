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
0007_backfill_user_timezones.sql
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

| Migration | Why it could not be an object-script edit |
|---|---|
| `0001_audit_actor_restrict.sql` | Changes an existing foreign key's delete action. The table script is guarded on `conname` and skips a constraint that already exists, so a built database would never pick the change up. |

`0001` closes a real hole: the audit actor key was `ON DELETE SET NULL`, which
let a user deletion rewrite existing audit rows and erase who performed each
action. Revoking `UPDATE` does not prevent it — a referential action runs as the
referencing table's owner and never consults the caller's grants.
