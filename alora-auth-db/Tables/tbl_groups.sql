/****** Object: Table [tbl_groups] ******/
-- A named bundle of grants within one tenant: App Central scopes, product
-- roles and optionally a login policy. The system group ADMINS is created
-- with its tenant, holds every scope, and cannot be renamed, re-scoped or
-- deleted.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_groups (
    id               TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    client_id        TEXT         NOT NULL,
    name             TEXT         NOT NULL,
    description      TEXT         NULL,
    system_key       TEXT         NULL,
    login_policy_id  TEXT         NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_groups PRIMARY KEY (id),
    CONSTRAINT CK_tbl_groups_system_key CHECK (system_key IS NULL OR system_key IN ('ADMINS'))
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_groups_tbl_clients_client_id') THEN
        ALTER TABLE tbl_groups ADD CONSTRAINT FK_tbl_groups_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_groups_tbl_login_policies_login_policy_id_client_id') THEN
        ALTER TABLE tbl_groups ADD CONSTRAINT FK_tbl_groups_tbl_login_policies_login_policy_id_client_id
            FOREIGN KEY (login_policy_id, client_id) REFERENCES tbl_login_policies (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- Case-insensitive so 'Sales' and 'sales' cannot both exist in one tenant.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_groups_client_name
    ON tbl_groups (client_id, lower(name));
--
-- The target of the composite keys that keep memberships, grants and
-- invitations inside the group's own tenant.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_groups_id_client_id
    ON tbl_groups (id, client_id);
--
-- One of each system group per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_groups_client_system_key
    ON tbl_groups (client_id, system_key) WHERE system_key IS NOT NULL;
