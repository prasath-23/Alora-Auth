/****** Object: Table [tbl_session_families] ******/
-- One login: a CENTRAL family at App Central, or a PRODUCT family a product
-- obtained through it. The refresh-token generations of a family live in
-- tbl_user_sessions; this row carries what applies to all of them, including
-- the absolute lifetime cap.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_session_families (
    id                   TEXT                    NOT NULL DEFAULT gen_random_uuid()::text,
    user_id              TEXT                    NOT NULL,
    client_id            TEXT                    NOT NULL,
    kind                 "SessionKind"           NOT NULL,
    product_id           TEXT                    NULL,
    parent_family_id     TEXT                    NULL,
    auth_method          "IdpProvider"           NOT NULL,
    auth_connection_id   TEXT                    NULL,
    authenticated_at     TIMESTAMPTZ             NOT NULL DEFAULT now(),
    absolute_expires_at  TIMESTAMPTZ             NOT NULL,
    revoked_at           TIMESTAMPTZ             NULL,
    revoked_reason       "SessionRevokedReason"  NULL,
    created_at           TIMESTAMPTZ             NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_session_families PRIMARY KEY (id),
    CONSTRAINT CK_tbl_session_families_kind CHECK ((kind = 'CENTRAL' AND product_id IS NULL AND parent_family_id IS NULL) OR (kind = 'PRODUCT' AND product_id IS NOT NULL AND parent_family_id IS NOT NULL)),
    CONSTRAINT CK_tbl_session_families_auth_connection CHECK ((auth_method = 'OIDC') = (auth_connection_id IS NOT NULL))
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
--
-- TENANT ISOLATION: a family belongs to one user in one tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_session_families_tbl_users_user_id_client_id') THEN
        ALTER TABLE tbl_session_families ADD CONSTRAINT FK_tbl_session_families_tbl_users_user_id_client_id
            FOREIGN KEY (user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- A product login exists only under that tenant's subscription.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_session_families_subscription') THEN
        ALTER TABLE tbl_session_families ADD CONSTRAINT FK_tbl_session_families_subscription
            FOREIGN KEY (client_id, product_id) REFERENCES tbl_client_products (client_id, product_id)
            ON DELETE RESTRICT;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_session_families_auth_connection') THEN
        ALTER TABLE tbl_session_families ADD CONSTRAINT FK_tbl_session_families_auth_connection
            FOREIGN KEY (auth_connection_id, client_id) REFERENCES tbl_sso_connections (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- The target of the keys that pin a child family, its generations and its
-- codes to the same user and tenant as the family itself.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_session_families_id_user_client
    ON tbl_session_families (id, user_id, client_id);
--
-- Revoking a central login revokes its children.
CREATE INDEX IF NOT EXISTS IX_tbl_session_families_parent_family_id
    ON tbl_session_families (parent_family_id) WHERE parent_family_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS IX_tbl_session_families_user_live
    ON tbl_session_families (user_id) WHERE revoked_at IS NULL;
--
-- Serves revoking every live login of a whole company on suspension.
CREATE INDEX IF NOT EXISTS IX_tbl_session_families_client_live
    ON tbl_session_families (client_id) WHERE revoked_at IS NULL;
--
-- Serves the expiry sweep.
CREATE INDEX IF NOT EXISTS IX_tbl_session_families_absolute_expires_at
    ON tbl_session_families (absolute_expires_at) WHERE revoked_at IS NULL;

-- Foreign keys that target an index created above.
--
-- A product login's parent is a central login of the SAME user and tenant,
-- and revoking the parent revokes it.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_session_families_parent_family') THEN
        ALTER TABLE tbl_session_families ADD CONSTRAINT FK_tbl_session_families_parent_family
            FOREIGN KEY (parent_family_id, user_id, client_id) REFERENCES tbl_session_families (id, user_id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
