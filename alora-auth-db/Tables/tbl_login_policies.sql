/****** Object: Table [tbl_login_policies] ******/
-- How a tenant's users may sign in: password, Google, and/or one SSO
-- connection. Each tenant has exactly one default; groups and users may
-- point at another, and the higher priority wins among a user's groups.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_login_policies (
    id                 TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    client_id          TEXT         NOT NULL,
    name               TEXT         NOT NULL,
    allow_password     BOOLEAN      NOT NULL DEFAULT true,
    allow_google       BOOLEAN      NOT NULL DEFAULT true,
    sso_connection_id  TEXT         NULL,
    priority           INTEGER      NOT NULL DEFAULT 0,
    is_default         BOOLEAN      NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_login_policies PRIMARY KEY (id),
    CONSTRAINT CK_tbl_login_policies_some_method CHECK (allow_password OR allow_google OR sso_connection_id IS NOT NULL)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_login_policies_tbl_clients_client_id') THEN
        ALTER TABLE tbl_login_policies ADD CONSTRAINT FK_tbl_login_policies_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- A policy can only name its own tenant's connection.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_login_policies_sso_connection') THEN
        ALTER TABLE tbl_login_policies ADD CONSTRAINT FK_tbl_login_policies_sso_connection
            FOREIGN KEY (sso_connection_id, client_id) REFERENCES tbl_sso_connections (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- The target of the users' and groups' composite keys, so a policy can only
-- be assigned inside its own tenant.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_login_policies_id_client_id
    ON tbl_login_policies (id, client_id);
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_login_policies_client_name
    ON tbl_login_policies (client_id, lower(name));
--
-- Priorities are unique per tenant, so resolving a user in several groups is
-- never a tie.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_login_policies_client_priority
    ON tbl_login_policies (client_id, priority);
--
-- Exactly one default per tenant: stp_CreateClient creates it, and
-- stp_SetDefaultLoginPolicy moves it.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_login_policies_client_default
    ON tbl_login_policies (client_id) WHERE is_default;
