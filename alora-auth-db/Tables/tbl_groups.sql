/****** Object: Table [tbl_groups] ******/
-- A named bundle of admin feature grants within one tenant.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_groups (
    id           TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    client_id    TEXT         NOT NULL,
    name         TEXT         NOT NULL,
    description  TEXT         NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_groups PRIMARY KEY (id)
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

-- Unique constraints and indexes.
--
-- Case-insensitive so 'Sales' and 'sales' cannot both exist in one tenant.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_groups_client_name
    ON tbl_groups (client_id, lower(name));
