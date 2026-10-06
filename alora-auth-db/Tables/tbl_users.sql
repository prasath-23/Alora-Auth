/****** Object: Table [tbl_users] ******/
-- A member of a tenant. Soft-deleted via deleted_at so an audit trail
-- survives GDPR erasure of the account.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_users (
    id                   TEXT           NOT NULL DEFAULT gen_random_uuid()::text,
    client_id            TEXT           NOT NULL,
    email                TEXT           NOT NULL,
    password_hash        TEXT           NULL,
    account_type         "AccountType"  NOT NULL DEFAULT 'EMAIL',
    is_active            BOOLEAN        NOT NULL DEFAULT true,
    permissions_version  INTEGER        NOT NULL DEFAULT 1,
    admin_version        INTEGER        NOT NULL DEFAULT 1,
    login_policy_id      TEXT           NULL,
    created_at           TIMESTAMPTZ    NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ    NOT NULL DEFAULT now(),
    deleted_at           TIMESTAMPTZ    NULL,
    CONSTRAINT PK_tbl_users PRIMARY KEY (id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_users_tbl_clients_client_id') THEN
        ALTER TABLE tbl_users ADD CONSTRAINT FK_tbl_users_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- A user's own policy must belong to their tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_users_tbl_login_policies_login_policy_id_client_id') THEN
        ALTER TABLE tbl_users ADD CONSTRAINT FK_tbl_users_tbl_login_policies_login_policy_id_client_id
            FOREIGN KEY (login_policy_id, client_id) REFERENCES tbl_login_policies (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- Not redundant with the primary key: this is the TARGET of the composite
-- foreign keys that pin child rows to one tenant, and PostgreSQL requires a
-- unique constraint on the referenced columns.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_users_id_client_id
    ON tbl_users (id, client_id);
--
-- Email is unique per tenant only among LIVE users, and case-insensitively.
-- Partial so a soft-deleted account never blocks re-invitation of the same
-- address; lower() so Bob@x and bob@x cannot both exist.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_users_email_active
    ON tbl_users (client_id, lower(email)) WHERE deleted_at IS NULL;
--
-- The login lookup matches lower(email) with NO client_id, so the composite
-- index above cannot serve it and every sign-in would seq-scan.
CREATE INDEX IF NOT EXISTS IX_tbl_users_lower_email_active
    ON tbl_users (lower(email)) WHERE deleted_at IS NULL;
