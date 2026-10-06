/****** Object: Roles and grants ******/
-- Creates a least-privilege role for the application to connect as.
--
-- WHY THIS EXISTS
-- Until now "the audit trail is append-only" and "the API cannot run ad-hoc SQL"
-- were true only because of which stored procedures happened to exist. That is a
-- convention, not a control: anything holding the connection string could run
-- any statement it liked. These grants make both properties enforced by the
-- database, so they survive a bug, a new endpoint, or an attacker with the
-- application's credentials.
--
-- WHAT THE APPLICATION ROLE CAN DO
--   * EXECUTE every udf_ / stp_ routine
--   * read and write the tables those routines touch
--   * INSERT into tbl_audit_logs, and nothing else -- no UPDATE, no DELETE
--
-- WHAT IT CANNOT DO
--   * rewrite or erase audit history
--   * create, alter or drop any object
--   * touch tbl_schema_migrations (migrations run as the owner, not the app)
--
-- Run AFTER build.sql, as a superuser or the schema owner:
--   psql -v ON_ERROR_STOP=1 -v app_password="'...'" -f Security/roles.sql
--
-- Then point the application at it:
--   DATABASE_URL=postgres://alora_app:<password>@host:5432/alora
--
-- This file is NOT part of build.sql. Creating roles needs privileges the build
-- does not assume, and in managed environments roles are often provisioned
-- separately. It is idempotent and safe to re-run.

\set ON_ERROR_STOP on

-- ── The role ────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'alora_app') THEN
        -- NOLOGIN until a password is set below, so the role never exists in a
        -- connectable state without credentials.
        CREATE ROLE alora_app NOLOGIN;
    END IF;
END $$;

-- Set the password only when one was supplied, so re-running without it does not
-- silently blank an existing credential.
\if :{?app_password}
    ALTER ROLE alora_app LOGIN PASSWORD :app_password;
\endif

-- ── Baseline ────────────────────────────────────────────────────────────────
-- :DBNAME is psql's built-in for the database being connected to, so this file
-- does not hardcode a database name.
GRANT CONNECT ON DATABASE :"DBNAME" TO alora_app;
GRANT USAGE   ON SCHEMA   public    TO alora_app;

-- Start from nothing and grant back deliberately: a table added later gets no
-- access until someone re-runs this file and thinks about what it needs.
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM alora_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM alora_app;

-- ── Routines: the entire API surface ────────────────────────────────────────
-- The application calls procedures and functions only, so this is the whole of
-- what it needs to operate.
GRANT EXECUTE ON ALL FUNCTIONS  IN SCHEMA public TO alora_app;
GRANT EXECUTE ON ALL PROCEDURES IN SCHEMA public TO alora_app;

-- ── Read access ─────────────────────────────────────────────────────────────
-- SELECT on every relation, which covers the views the read functions return.
-- The exceptions below are then carved out.
GRANT SELECT ON ALL TABLES IN SCHEMA public TO alora_app;

-- ── Write access ───────────────────────────────────────────────────────────
-- Granted per verb, not per table. Every line below corresponds to a statement
-- that actually exists in Programmability/; a verb no routine uses is a verb an
-- attacker holding these credentials gets for free.
--
-- The routines are INVOKER-rights (the PostgreSQL default), so they run with
-- the caller's privileges and the caller still needs table access. That is the
-- point: the grants stay meaningful instead of being bypassed by SECURITY
-- DEFINER.

-- Rows are created and amended, never removed. These are the records whose
-- disappearance would itself be the incident. Sessions and their families are
-- revoked by stamping revoked_at, never deleted: the chain is the evidence
-- reuse detection reads. A subscription is switched off, not deleted, and an
-- SSO connection is deactivated.
GRANT INSERT, UPDATE ON
    tbl_clients,
    tbl_products,
    tbl_users,
    tbl_session_families,
    tbl_user_sessions,
    tbl_invitations,
    tbl_client_products,
    tbl_sso_connections
TO alora_app;

-- Rows that are meant to be destroyed: a code once expired, a reset token once
-- used, a group or login policy when it is removed.
GRANT INSERT, UPDATE, DELETE ON
    tbl_authorization_codes,
    tbl_password_reset_tokens,
    tbl_groups,
    tbl_login_policies
TO alora_app;

-- A product role is granted and re-granted in place: stp_UpsertProductPermission
-- is an INSERT ... ON CONFLICT DO UPDATE, and PostgreSQL requires UPDATE on the
-- table for that statement even when no conflict occurs.
GRANT INSERT, UPDATE, DELETE ON
    tbl_product_permissions
TO alora_app;

-- Shared rate-limit counters: stp_RateLimitHit is an INSERT ... ON CONFLICT DO
-- UPDATE (so UPDATE is required even when no conflict occurs), and the cleanup
-- sweep deletes a counter once its window has passed.
GRANT INSERT, UPDATE, DELETE ON
    tbl_rate_limit_counters
TO alora_app;

-- Membership, grant and registration rows, and sign-in states. Each is replaced
-- by delete-then-insert (or consumed by a delete) and never edited in place, so
-- UPDATE is withheld. An external identity is deleted to unlink it.
GRANT INSERT, DELETE ON
    tbl_group_scopes,
    tbl_user_scopes,
    tbl_user_groups,
    tbl_group_managers,
    tbl_group_product_grants,
    tbl_product_redirect_uris,
    tbl_product_roles,
    tbl_sso_connection_domains,
    tbl_linked_identities,
    tbl_login_states
TO alora_app;

-- Write-once: the groups an invitation offers are fixed when it is issued.
GRANT INSERT ON
    tbl_invitation_groups
TO alora_app;

-- API clients: created and deleted by their tenant's people or an Owner, and
-- amended only in the columns a routine sets. An API client's id and tenant are
-- fixed for life, so no bug can move one into another tenant.
GRANT INSERT, DELETE ON
    tbl_api_clients
TO alora_app;
GRANT UPDATE (name, description, is_active, last_used_at, updated_at) ON
    tbl_api_clients
TO alora_app;

-- Where an API client may be used and what it may get a token for: replaced by
-- delete-then-insert, never edited in place.
GRANT INSERT, DELETE ON
    tbl_api_client_scopes,
    tbl_api_client_products
TO alora_app;

-- A secret is made, revoked and stamped when used -- never rewritten, and never
-- deleted by the application (only with its API client, by cascade): its hash is
-- fixed at insert, so the application cannot swap a known secret in.
GRANT INSERT ON
    tbl_api_client_secrets
TO alora_app;
GRANT UPDATE (revoked_at, last_used_at) ON
    tbl_api_client_secrets
TO alora_app;

-- tbl_scopes is READ-ONLY here too: the catalogue is reference data the build
-- writes. An application that could add a scope could invent a permission.
--
-- tbl_platform_owners is deliberately READ-ONLY here (SELECT comes from the
-- baseline grant above). Who is an Owner is decided by provisioning, connected
-- as the schema owner, so no bug or stolen credential of the application can
-- promote anyone. stp_CreatePlatformOwner runs with the caller's rights and so
-- fails under this role, on purpose.

-- ── The audit trail: INSERT ONLY ────────────────────────────────────────────
-- This is the point of the whole file. An append-only trail the application can
-- rewrite is not an audit trail, and "we only wrote an insert procedure" is a
-- convention, not an enforcement mechanism. The REVOKE is redundant with the
-- grants above and is kept anyway: it states the intent, and it survives
-- someone adding this table to one of those lists by accident.
REVOKE UPDATE, DELETE ON tbl_audit_logs FROM alora_app;
GRANT  INSERT           ON tbl_audit_logs TO   alora_app;

-- These grants alone are NOT sufficient. A referential action runs as the
-- referencing table's owner, so an ON DELETE SET NULL pointing at this table
-- would rewrite audit rows no matter what is revoked here -- deleting a user
-- would erase them from the trail while every direct UPDATE stayed denied.
-- That is why the actor foreign key is ON DELETE RESTRICT, and why DELETE on
-- tbl_users is not granted above: the two together are what make this table
-- append-only in fact rather than by intention.

-- ── Migrations ledger: owner only ───────────────────────────────────────────
-- Migrations run as the schema owner. The application has no business reading or
-- writing which migrations have been applied.
REVOKE ALL ON tbl_schema_migrations FROM alora_app;

-- ── Verification ────────────────────────────────────────────────────────────
-- Fails loudly rather than leaving a silently-misconfigured database.
DO $$
DECLARE
    v_bad TEXT;
BEGIN
    SELECT string_agg(privilege_type, ', ')
    INTO   v_bad
    FROM   information_schema.table_privileges
    WHERE  grantee    = 'alora_app'
      AND  table_name = 'tbl_audit_logs'
      AND  privilege_type IN ('UPDATE', 'DELETE');

    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'alora_app still holds % on tbl_audit_logs', v_bad;
    END IF;

    -- The indirect route. DELETE on tbl_users plus an ON DELETE SET NULL actor
    -- key erases the trail without touching tbl_audit_logs at all, so checking
    -- the audit grants alone would certify a database that is still exposed.
    IF EXISTS (
        SELECT 1 FROM information_schema.table_privileges
        WHERE  grantee = 'alora_app' AND table_name = 'tbl_users'
          AND  privilege_type = 'DELETE'
    ) THEN
        RAISE EXCEPTION
            'alora_app holds DELETE on tbl_users: deleting a user would erase them from the audit trail';
    END IF;

    -- Nobody promotes themselves: the application can read the Owners, never
    -- write them.
    SELECT string_agg(privilege_type, ', ')
    INTO   v_bad
    FROM   information_schema.table_privileges
    WHERE  grantee    = 'alora_app'
      AND  table_name = 'tbl_platform_owners'
      AND  privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE');

    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'alora_app holds % on tbl_platform_owners: it could promote an Owner', v_bad;
    END IF;

    -- Nobody invents a permission: the scope catalogue is written by the build.
    SELECT string_agg(privilege_type, ', ')
    INTO   v_bad
    FROM   information_schema.table_privileges
    WHERE  grantee    = 'alora_app'
      AND  table_name = 'tbl_scopes'
      AND  privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE');

    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'alora_app holds % on tbl_scopes: it could invent a scope', v_bad;
    END IF;

    -- A secret's hash is fixed at insert: an application that could rewrite one
    -- could swap a secret it knows in for any API client.
    SELECT string_agg(column_name, ', ')
    INTO   v_bad
    FROM   information_schema.columns
    WHERE  table_name = 'tbl_api_client_secrets'
      AND  column_name NOT IN ('revoked_at', 'last_used_at')
      AND  has_column_privilege('alora_app', 'tbl_api_client_secrets', column_name, 'UPDATE');

    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'alora_app may UPDATE % on tbl_api_client_secrets: it could swap a secret in', v_bad;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.table_privileges
        WHERE  grantee = 'alora_app' AND table_name = 'tbl_api_client_secrets'
          AND  privilege_type IN ('DELETE', 'TRUNCATE')
    ) THEN
        RAISE EXCEPTION 'alora_app may delete API client secrets: revocation must stamp, never delete';
    END IF;

    -- An API client's tenant is fixed for life.
    IF has_column_privilege('alora_app', 'tbl_api_clients', 'client_id', 'UPDATE')
       OR has_column_privilege('alora_app', 'tbl_api_clients', 'id', 'UPDATE') THEN
        RAISE EXCEPTION 'alora_app may UPDATE the id or tenant of tbl_api_clients';
    END IF;

    -- An appointment is made and ended, never edited: an UPDATE could move it to
    -- another person or group without anyone appointing them.
    IF EXISTS (
        SELECT 1 FROM information_schema.table_privileges
        WHERE  grantee = 'alora_app' AND table_name = 'tbl_group_managers'
          AND  privilege_type IN ('UPDATE', 'TRUNCATE')
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE  table_name = 'tbl_group_managers'
          AND  has_column_privilege('alora_app', 'tbl_group_managers', column_name, 'UPDATE')
    ) THEN
        RAISE EXCEPTION 'alora_app may UPDATE tbl_group_managers: an appointment could be moved to someone else';
    END IF;

    -- A deleted generation would erase the evidence reuse detection reads.
    IF EXISTS (
        SELECT 1 FROM information_schema.table_privileges
        WHERE  grantee = 'alora_app'
          AND  table_name IN ('tbl_user_sessions', 'tbl_session_families')
          AND  privilege_type = 'DELETE'
    ) THEN
        RAISE EXCEPTION 'alora_app holds DELETE on the session tables: revocation must stamp, never delete';
    END IF;

    -- The upsert behind every product-role grant needs UPDATE; without it each
    -- grant fails with "permission denied" under this role.
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_privileges
        WHERE  grantee = 'alora_app' AND table_name = 'tbl_product_permissions'
          AND  privilege_type = 'UPDATE'
    ) THEN
        RAISE EXCEPTION
            'alora_app lacks UPDATE on tbl_product_permissions: stp_UpsertProductPermission would fail';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE  conname = 'fk_tbl_audit_logs_tbl_users_actor_user_id'
          AND  confdeltype = 'r'   -- r = RESTRICT
    ) THEN
        RAISE EXCEPTION
            'audit actor FK is not ON DELETE RESTRICT: apply Migrations/0001_audit_actor_restrict.sql';
    END IF;

    RAISE NOTICE 'alora_app configured: audit trail is INSERT-only and cannot be erased by deleting a user.';
END $$;
