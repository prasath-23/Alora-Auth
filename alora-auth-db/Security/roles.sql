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

-- ── Write access ────────────────────────────────────────────────────────────
-- Listed explicitly rather than granted wholesale, so a table added later has no
-- write access until someone decides it should. Routines here are INVOKER-rights
-- (the PostgreSQL default), so they run with the caller's privileges and the
-- caller still needs table access.
GRANT INSERT, UPDATE, DELETE ON
    tbl_clients,
    tbl_products,
    tbl_users,
    tbl_user_sessions,
    tbl_client_products,
    tbl_product_permissions,
    tbl_linked_identities,
    tbl_invitations,
    tbl_invitation_products,
    tbl_authorization_codes,
    tbl_groups,
    tbl_group_features,
    tbl_user_groups,
    tbl_password_reset_tokens
TO alora_app;

-- ── The audit trail: INSERT ONLY ────────────────────────────────────────────
-- This is the point of the whole file. An append-only trail the application can
-- rewrite is not an audit trail, and "we only wrote an insert procedure" is a
-- convention, not an enforcement mechanism. Note tbl_audit_logs is absent from
-- the write grant above; this makes the intent explicit and survives someone
-- adding it there by accident.
REVOKE UPDATE, DELETE ON tbl_audit_logs FROM alora_app;
GRANT  INSERT           ON tbl_audit_logs TO   alora_app;

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

    RAISE NOTICE 'alora_app configured: audit trail is INSERT-only.';
END $$;
