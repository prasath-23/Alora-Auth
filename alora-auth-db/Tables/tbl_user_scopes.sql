/****** Object: Table [tbl_user_scopes] ******/
-- Extra App Central scopes given to one person, on top of what their groups
-- give. Granted by a user of the same tenant or by an Owner.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_user_scopes (
    user_id              TEXT         NOT NULL,
    client_id            TEXT         NOT NULL,
    scope                TEXT         NOT NULL,
    kind                 TEXT         NOT NULL DEFAULT 'PERSON',
    granted_by_user_id   TEXT         NULL,
    granted_by_owner_id  TEXT         NULL,
    granted_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_user_scopes PRIMARY KEY (user_id, scope),
    CONSTRAINT CK_tbl_user_scopes_kind CHECK (kind = 'PERSON'),
    CONSTRAINT CK_tbl_user_scopes_one_granter CHECK (num_nonnulls(granted_by_user_id, granted_by_owner_id) <= 1)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
--
-- TENANT ISOLATION: the grant lives in the user's tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_scopes_tbl_users_user_id_client_id') THEN
        ALTER TABLE tbl_user_scopes ADD CONSTRAINT FK_tbl_user_scopes_tbl_users_user_id_client_id
            FOREIGN KEY (user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- Only a person scope from the catalogue can be given.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_scopes_tbl_scopes_scope_kind') THEN
        ALTER TABLE tbl_user_scopes ADD CONSTRAINT FK_tbl_user_scopes_tbl_scopes_scope_kind
            FOREIGN KEY (scope, kind) REFERENCES tbl_scopes (scope, kind)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- A user who grants must belong to the same tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_scopes_tbl_users_granted_by_user_id_client_id') THEN
        ALTER TABLE tbl_user_scopes ADD CONSTRAINT FK_tbl_user_scopes_tbl_users_granted_by_user_id_client_id
            FOREIGN KEY (granted_by_user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- An Owner may grant in any tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_scopes_tbl_platform_owners_granted_by_owner_id') THEN
        ALTER TABLE tbl_user_scopes ADD CONSTRAINT FK_tbl_user_scopes_tbl_platform_owners_granted_by_owner_id
            FOREIGN KEY (granted_by_owner_id) REFERENCES tbl_platform_owners (user_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- Child side of a RESTRICT foreign key, probed on every user delete.
CREATE INDEX IF NOT EXISTS IX_tbl_user_scopes_granted_by
    ON tbl_user_scopes (granted_by_user_id);
