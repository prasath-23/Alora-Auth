/****** Object: Table [tbl_platform_owners] ******/
-- The Owners: platform staff who manage every tenant. The application role
-- can only READ this table, so no application bug can promote anyone; rows
-- are written by provisioning, as the schema owner.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_platform_owners (
    user_id      TEXT         NOT NULL,
    client_id    TEXT         NOT NULL,
    is_platform  BOOLEAN      NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_platform_owners PRIMARY KEY (user_id),
    CONSTRAINT CK_tbl_platform_owners_is_platform CHECK (is_platform)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_platform_owners_tbl_users_user_id_client_id') THEN
        ALTER TABLE tbl_platform_owners ADD CONSTRAINT FK_tbl_platform_owners_tbl_users_user_id_client_id
            FOREIGN KEY (user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- Together with the CHECK, only a member of the platform company can be an
-- Owner.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_platform_owners_tbl_clients_client_id_is_platform') THEN
        ALTER TABLE tbl_platform_owners ADD CONSTRAINT FK_tbl_platform_owners_tbl_clients_client_id_is_platform
            FOREIGN KEY (client_id, is_platform) REFERENCES tbl_clients (id, is_platform)
            ON DELETE RESTRICT;
    END IF;
END $$;
