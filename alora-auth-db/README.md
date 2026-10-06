# Database — structure and conventions

The API never runs a query against a table. It calls stored procedures and
functions only, so every predicate, projection and tenant check lives here and
can be reviewed in one place.

## Layout

One file per object, mirroring the house layout used across our SQL Server
projects:

```
alora-auth-db/
├── Tables/                              tbl_*.sql   (32)
├── Views/                               vw_*.sql    (33)
├── Programmability/
│   ├── Types/                           enums
│   ├── StoredProcedures/                stp_*.sql   (73)  writes
│   └── Functions/
│       ├── Scalar-valued Functions/     udf_*.sql   (12)  single-value reads
│       └── Table-valued Functions/      udf_*.sql   (61)  row-set reads
├── api/                                 the API's call surface (146 operations)
├── Security/roles.sql                   alora_app, the least-privilege role, and its grants
├── Migrations/                          the few changes a re-run cannot make (README.md)
├── gen_*.py                             the generators every object file comes from
├── build.sql                            applies everything, in order (generated)
└── migrate.sh                           build.sql, then pending migrations
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
`IX_<table>_<cols>` · `CK_<table>_<what>`

**Every name fits in 63 characters.** PostgreSQL silently truncates a longer
identifier, and the truncated name no longer matches the `pg_constraint` guard
that makes the build re-runnable, so the second run fails. `gen_tables.py`
refuses such a name; a long one is shortened by hand
(`FK_tbl_api_client_scopes_api_client`).

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
may be absent is wrapped in `api/`:

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
`revoked_reason` and `user_id`, and `vw_ApiClientSecret` omits the secret's
hash, so no caller can leak token material even by accident.

Views also carry the STANDING predicates. "Active session", "pending
invitation", "redeemable reset token", "live API client secret" are each defined
exactly once, and every function built on them inherits the definition.

Two things sqlc needs from a view: a `UNION` must give a column the same
nullability in every branch (an empty string, not `NULL`, where one branch has
no value), and an aggregate the API reads as a list is `ARRAY(…)::text[]` (a
`[]string`) or `jsonb` decoded in the table service.

## Scopes and API clients (schema v3)

- **`tbl_scopes` is the closed catalogue**: each scope, its kind — `PERSON` (what
  a person may do in App Central) or `CLIENT` (where an API client's credential
  may be used) — its feature and level. The build upserts it from
  `gen_tables.py`; the app role can only read it, and
  `internal/core/shared/scopes.go` must list exactly the same (a test holds the
  two in step). `apps:read` and `owner` are not in it: nobody grants them.
- **Every grant references the catalogue by `(scope, kind)` and pins its kind**
  with a CHECK: `tbl_group_scopes` and `tbl_user_scopes` (a person's extras,
  with who gave them) are `PERSON`, `tbl_api_client_scopes` is `CLIENT`. An
  unknown scope, or one of the other kind, cannot be stored. The `ADMINS` group
  has no rows: it holds every `PERSON` scope by definition.
- **`tbl_users.admin_version`** is bumped by every procedure that changes what a
  person may do in App Central (their groups, a group's scopes, their extras), as
  `permissions_version` is by every change to their product access — in the same
  transaction, so a token's snapshot can always be told stale.
- **API clients:** `tbl_api_clients` (id `aci_…`, one creator), its scopes, its
  products (a composite key to the company's subscription, `RESTRICT`) and its
  secrets (`tbl_api_client_secrets`: the hash and an `acc_…` prefix). The
  procedure that makes a secret locks the client row and refuses a third live
  one. `roles.sql` lets the app role UPDATE only a secret's `revoked_at` and
  `last_used_at`, and never an API client's id or company, and refuses to finish
  if that has drifted.
- **Group managers:** `tbl_group_managers` — who runs which group, with exactly
  one appointer and never the appointee (CHECKs), tenant-bound both ways by
  composite keys; the app role may INSERT and DELETE, never UPDATE, and
  `roles.sql` refuses to finish otherwise. `stp_AddGroupManager` refuses a
  system group. A manager's own writes, `stp_ManagerAddGroupMember` and
  `stp_ManagerRemoveGroupMember`, share-lock the group row — which
  `stp_RemoveGroupManager` locks for update — and only then check, in a new
  statement, that the caller still manages the group. `vw_ScopeReach` is rule
  2's measure (held scopes plus managed groups'); it grants nothing.
- **One live invitation per address per company** is a unique index
  (`UQ_tbl_invitations_client_email_pending`), not a check before an insert: two
  invitations arriving at once cannot both be made. `stp_CreateInvitation` marks a
  pending invitation past its expiry EXPIRED first, so it never blocks a new one.
- **A name a standard bounds is bounded by its table:** a domain, a company's or
  an SSO connection's, is at most 253 characters (RFC 1035) and a provider's
  subject at most 255 (OpenID Connect Core), each by its own CHECK, so a value
  past them is refused by name rather than by an index that cannot hold it.
- **Client authentication** reads `vw_OAuthClientCredential` — a product's secret
  or an API client's live ones, 0–2 rows per client id — and a token request
  reads `vw_ApiClientGrant`: whether the client may have a token for that product
  right now, and its scopes.

## Idempotency

`build.sql` is safe to re-run, so it serves as both a fresh install and an
upgrade within v3:

```bash
psql -v ON_ERROR_STOP=1 -f build.sql
```

- Tables use `CREATE TABLE IF NOT EXISTS`; constraints are guarded against
  `pg_constraint`; indexes use `IF NOT EXISTS`.
- Views, functions and procedures use `CREATE OR REPLACE`.
- Reference rows (the scope catalogue) are upserted.
- Enum types are the exception. They are written as plain `CREATE TYPE` because a
  `DO`-block guard makes them invisible to sqlc's parser, which silently degrades
  every enum to `interface{}` and every enum array to `[]interface{}` in the
  generated Go. `build.sql` therefore contains a guarded copy generated from the
  same file — see `gen_build.py`, so the two cannot drift.
- Its first step refuses a v1 or v2 database outright, before touching anything
  (`Migrations/README.md`).

## Regenerating

The object files are generated so the layout stays consistent across 200+ files.
Edit the generator that owns an object, never the object file:

```bash
python gen_tables.py       # Tables/
python gen_views.py        # Views/
python gen_functions.py    # Functions/
python gen_procedures.py   # StoredProcedures/
python gen_build.py        # build.sql, from whatever is on disk
cd ../alora-auth-api && sqlc generate   # typed Go bindings for api/
```

`gen_build.py` reads the filesystem, so adding an object file is enough to
include it in the build — there is no hand-maintained list to fall out of date,
except `TABLE_ORDER`, which puts the tables in foreign-key order. The generators
never delete a file they no longer produce: when an object goes, delete its file
by hand. `../scripts/check-generated.sh` fails on a file that differs from what
its generator produces, one no generator produces any more, and stale sqlc code.

## Verifying a change

```bash
./migrate.sh --docker                          # a throwaway PostgreSQL 16: build.sql, then the migrations
bash ../scripts/check-generated.sh             # every generated file matches its source
bash ../alora-auth-api/scripts/integration-test.sh   # build.sql + roles.sql + the Go suite, as alora_app
```

To prove a change is idempotent, apply `build.sql` again to the database it just
built: the second run must succeed and change nothing.
