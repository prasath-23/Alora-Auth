# Migrations

## The v3 baseline

The object scripts now build **v3**: App Central as v2 built it — session
families, platform Owners, per-company login policies and SSO connections,
products registered as OAuth clients — with access expressed as **scopes** (a
closed catalogue, given through groups and to one person as extras, with
`admin_version` to tell a token's snapshot stale) and **API clients**, the
applications that get product tokens with client credentials.

There is **no upgrade path from v1 or v2**. Nothing ran on either in
production, so each change of model was made as a new baseline rather than as
migrations nobody would ever run:

- v1 → v2: one global token became two kinds of token, and `is_global_admin`
  became the Owner and each company's Admins group;
- v2 → v3: the nine delegated feature keys (`tbl_group_features`) became
  read/edit scopes from `tbl_scopes`, and API clients arrived.

`build.sql` refuses to run over an older database. Its first step looks for
`tbl_users.is_global_admin` (v1) and for `tbl_group_features` (v2), and raises
`v1 schema detected` or `v2 schema detected; rebuild the database from scratch`
before touching anything. It has to: `CREATE TABLE IF NOT EXISTS` adds no column
to a table that exists, and a view cannot drop a column through `CREATE OR
REPLACE`, so running over an older schema would half-apply. To rebuild, drop and
recreate the database, then run `./migrate.sh` (or `build.sql` followed by
`Security/roles.sql`).

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
| `0002_session_revoked_reason_suspended.sql` | Adds the `SUSPENDED` value to the `"SessionRevokedReason"` enum. `enums.sql` is `CREATE TYPE` applied only when the type is absent, so a built database never gains a new value from a rebuild; the `ALTER TYPE … ADD VALUE IF NOT EXISTS` is needed, and is a no-op on a fresh build. |

`0001` predates v2. The table script has declared the key `RESTRICT` since v2,
and the migration is guarded, so on a v3 build it verifies and changes nothing.

`0001` closes a real hole: the audit actor key was `ON DELETE SET NULL`, which
let a user deletion rewrite existing audit rows and erase who performed each
action. Revoking `UPDATE` does not prevent it — a referential action runs as the
referencing table's owner and never consults the caller's grants.
