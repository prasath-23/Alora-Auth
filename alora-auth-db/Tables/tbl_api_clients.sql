/****** Object: Table [tbl_api_clients] ******/
-- An application's identity: a sync job, a backend or an agent that calls
-- products with no person present. Its id is its OAuth client_id -- 'aci_'
-- and a uuid, so it can never be mistaken for a product's. It belongs to one
-- tenant and holds where its credential may be used (CLIENT scopes), which
-- of the tenant's products it may get a token for, and its secrets. Created
-- by a user of the tenant or by an Owner, never both.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_api_clients (
    id                   TEXT         NOT NULL DEFAULT 'aci_' || gen_random_uuid()::text,
    client_id            TEXT         NOT NULL,
    name                 TEXT         NOT NULL,
    description          TEXT         NULL,
    is_active            BOOLEAN      NOT NULL DEFAULT true,
    created_by_user_id   TEXT         NULL,
    created_by_owner_id  TEXT         NULL,
    last_used_at         TIMESTAMPTZ  NULL,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_api_clients PRIMARY KEY (id),
    CONSTRAINT CK_tbl_api_clients_id CHECK (id ~ '^aci_[0-9a-f-]{36}$'),
    CONSTRAINT CK_tbl_api_clients_one_creator CHECK (num_nonnulls(created_by_user_id, created_by_owner_id) = 1)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_api_clients_tbl_clients_client_id') THEN
        ALTER TABLE tbl_api_clients ADD CONSTRAINT FK_tbl_api_clients_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- TENANT ISOLATION: a user who creates one must belong to its tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_api_clients_created_by_user') THEN
        ALTER TABLE tbl_api_clients ADD CONSTRAINT FK_tbl_api_clients_created_by_user
            FOREIGN KEY (created_by_user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- An Owner may create one in any tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_api_clients_created_by_owner') THEN
        ALTER TABLE tbl_api_clients ADD CONSTRAINT FK_tbl_api_clients_created_by_owner
            FOREIGN KEY (created_by_owner_id) REFERENCES tbl_platform_owners (user_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- Case-insensitive, like group names, so a tenant can tell its API clients
-- apart.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_api_clients_client_name
    ON tbl_api_clients (client_id, lower(name));
--
-- The target of the composite keys that keep an API client's scopes,
-- products and secrets inside its own tenant.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_api_clients_id_client_id
    ON tbl_api_clients (id, client_id);
--
-- Child side of a RESTRICT foreign key, probed on every user delete.
CREATE INDEX IF NOT EXISTS IX_tbl_api_clients_created_by
    ON tbl_api_clients (created_by_user_id);
