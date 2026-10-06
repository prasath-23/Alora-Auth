/****** Object: Table [tbl_group_scopes] ******/
-- The App Central scopes a group gives its members. The ADMINS group holds
-- every scope implicitly and has no rows here.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_group_scopes (
    group_id   TEXT  NOT NULL,
    client_id  TEXT  NOT NULL,
    scope      TEXT  NOT NULL,
    kind       TEXT  NOT NULL DEFAULT 'PERSON',
    CONSTRAINT PK_tbl_group_scopes PRIMARY KEY (group_id, scope),
    CONSTRAINT CK_tbl_group_scopes_kind CHECK (kind = 'PERSON')
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
--
-- TENANT ISOLATION: the grant lives in the group's tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_group_scopes_tbl_groups_group_id_client_id') THEN
        ALTER TABLE tbl_group_scopes ADD CONSTRAINT FK_tbl_group_scopes_tbl_groups_group_id_client_id
            FOREIGN KEY (group_id, client_id) REFERENCES tbl_groups (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- Only a person scope from the catalogue can be given.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_group_scopes_tbl_scopes_scope_kind') THEN
        ALTER TABLE tbl_group_scopes ADD CONSTRAINT FK_tbl_group_scopes_tbl_scopes_scope_kind
            FOREIGN KEY (scope, kind) REFERENCES tbl_scopes (scope, kind)
            ON DELETE RESTRICT;
    END IF;
END $$;
