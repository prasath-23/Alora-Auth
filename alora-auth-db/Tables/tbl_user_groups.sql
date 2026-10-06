/****** Object: Table [tbl_user_groups] ******/
-- Group membership. The composite primary key is the membership itself, so
-- no surrogate id is needed.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_user_groups (
    user_id      TEXT         NOT NULL,
    group_id     TEXT         NOT NULL,
    client_id    TEXT         NOT NULL,
    assigned_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    assigned_by  TEXT         NULL,
    CONSTRAINT PK_tbl_user_groups PRIMARY KEY (user_id, group_id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_groups_tbl_users_user_id') THEN
        ALTER TABLE tbl_user_groups ADD CONSTRAINT FK_tbl_user_groups_tbl_users_user_id
            FOREIGN KEY (user_id) REFERENCES tbl_users (id)
            ON DELETE CASCADE;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_groups_tbl_groups_group_id') THEN
        ALTER TABLE tbl_user_groups ADD CONSTRAINT FK_tbl_user_groups_tbl_groups_group_id
            FOREIGN KEY (group_id) REFERENCES tbl_groups (id)
            ON DELETE CASCADE;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_groups_tbl_clients_client_id') THEN
        ALTER TABLE tbl_user_groups ADD CONSTRAINT FK_tbl_user_groups_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- TENANT ISOLATION: a user from tenant A cannot join a group in tenant B.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_groups_tbl_users_user_id_client_id') THEN
        ALTER TABLE tbl_user_groups ADD CONSTRAINT FK_tbl_user_groups_tbl_users_user_id_client_id
            FOREIGN KEY (user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- TENANT ISOLATION, the other side: the membership's tenant is the group's
-- own.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_groups_tbl_groups_group_id_client_id') THEN
        ALTER TABLE tbl_user_groups ADD CONSTRAINT FK_tbl_user_groups_tbl_groups_group_id_client_id
            FOREIGN KEY (group_id, client_id) REFERENCES tbl_groups (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE INDEX IF NOT EXISTS IX_tbl_user_groups_user_client
    ON tbl_user_groups (user_id, client_id);
