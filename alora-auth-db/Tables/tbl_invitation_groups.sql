/****** Object: Table [tbl_invitation_groups] ******/
-- The groups an invitation adds its user to on acceptance.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_invitation_groups (
    invitation_id  TEXT  NOT NULL,
    client_id      TEXT  NOT NULL,
    group_id       TEXT  NOT NULL,
    CONSTRAINT PK_tbl_invitation_groups PRIMARY KEY (invitation_id, group_id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_invitation_groups_invitation') THEN
        ALTER TABLE tbl_invitation_groups ADD CONSTRAINT FK_tbl_invitation_groups_invitation
            FOREIGN KEY (invitation_id, client_id) REFERENCES tbl_invitations (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- TENANT ISOLATION: an invitation can only offer its own tenant's groups.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_invitation_groups_tbl_groups_group_id_client_id') THEN
        ALTER TABLE tbl_invitation_groups ADD CONSTRAINT FK_tbl_invitation_groups_tbl_groups_group_id_client_id
            FOREIGN KEY (group_id, client_id) REFERENCES tbl_groups (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
