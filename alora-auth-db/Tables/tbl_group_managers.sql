/****** Object: Table [tbl_group_managers] ******/
-- The people who run one group: they add and remove its members, and nothing
-- else. Appointed by a user of the same tenant or by an Owner, never both,
-- and never by themselves. A system group never has managers:
-- stp_AddGroupManager refuses one, since whoever decides the Admins group's
-- members decides who is an Admin.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_group_managers (
    group_id               TEXT         NOT NULL,
    client_id              TEXT         NOT NULL,
    user_id                TEXT         NOT NULL,
    appointed_by_user_id   TEXT         NULL,
    appointed_by_owner_id  TEXT         NULL,
    appointed_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_group_managers PRIMARY KEY (group_id, user_id),
    CONSTRAINT CK_tbl_group_managers_one_appointer CHECK (num_nonnulls(appointed_by_user_id, appointed_by_owner_id) = 1),
    CONSTRAINT CK_tbl_group_managers_not_self CHECK (appointed_by_user_id IS DISTINCT FROM user_id AND appointed_by_owner_id IS DISTINCT FROM user_id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
--
-- TENANT ISOLATION: the appointment lives in the group's tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_group_managers_group') THEN
        ALTER TABLE tbl_group_managers ADD CONSTRAINT FK_tbl_group_managers_group
            FOREIGN KEY (group_id, client_id) REFERENCES tbl_groups (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- TENANT ISOLATION, the other side: only the group's own tenant's users
-- manage it.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_group_managers_user') THEN
        ALTER TABLE tbl_group_managers ADD CONSTRAINT FK_tbl_group_managers_user
            FOREIGN KEY (user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- A user who appoints must belong to the same tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_group_managers_appointed_by_user') THEN
        ALTER TABLE tbl_group_managers ADD CONSTRAINT FK_tbl_group_managers_appointed_by_user
            FOREIGN KEY (appointed_by_user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- An Owner may appoint in any tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_group_managers_appointed_by_owner') THEN
        ALTER TABLE tbl_group_managers ADD CONSTRAINT FK_tbl_group_managers_appointed_by_owner
            FOREIGN KEY (appointed_by_owner_id) REFERENCES tbl_platform_owners (user_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- The groups a person manages: read by /api/me, the manager door and rule
-- 2's reach.
CREATE INDEX IF NOT EXISTS IX_tbl_group_managers_user_client
    ON tbl_group_managers (user_id, client_id);
--
-- Child side of a RESTRICT foreign key, probed on every user delete.
CREATE INDEX IF NOT EXISTS IX_tbl_group_managers_appointed_by
    ON tbl_group_managers (appointed_by_user_id);
