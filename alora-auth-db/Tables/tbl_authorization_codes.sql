/****** Object: Table [tbl_authorization_codes] ******/
-- A single-use OAuth2 authorization code, stored as its SHA-256 only, with
-- its PKCE challenge and the central login that authorized it. Redeemed by
-- exactly one atomic UPDATE, so it cannot be double-spent.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_authorization_codes (
    id                     TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    code_hash              TEXT         NOT NULL,
    product_id             TEXT         NOT NULL,
    user_id                TEXT         NOT NULL,
    client_id              TEXT         NOT NULL,
    parent_family_id       TEXT         NOT NULL,
    redirect_uri           TEXT         NOT NULL,
    code_challenge         TEXT         NOT NULL,
    code_challenge_method  TEXT         NOT NULL DEFAULT 'S256',
    nonce                  TEXT         NULL,
    scope                  TEXT         NULL,
    expires_at             TIMESTAMPTZ  NOT NULL,
    used_at                TIMESTAMPTZ  NULL,
    issued_family_id       TEXT         NULL,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_authorization_codes PRIMARY KEY (id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_authorization_codes_tbl_products_product_id') THEN
        ALTER TABLE tbl_authorization_codes ADD CONSTRAINT FK_tbl_authorization_codes_tbl_products_product_id
            FOREIGN KEY (product_id) REFERENCES tbl_products (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_authorization_codes_tbl_users_user_id_client_id') THEN
        ALTER TABLE tbl_authorization_codes ADD CONSTRAINT FK_tbl_authorization_codes_tbl_users_user_id_client_id
            FOREIGN KEY (user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- A code is issued under one central login of the same user and tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_authorization_codes_parent_family') THEN
        ALTER TABLE tbl_authorization_codes ADD CONSTRAINT FK_tbl_authorization_codes_parent_family
            FOREIGN KEY (parent_family_id, user_id, client_id) REFERENCES tbl_session_families (id, user_id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- The product login the code produced, revoked if the code is ever replayed.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_authorization_codes_issued_family') THEN
        ALTER TABLE tbl_authorization_codes ADD CONSTRAINT FK_tbl_authorization_codes_issued_family
            FOREIGN KEY (issued_family_id) REFERENCES tbl_session_families (id)
            ON DELETE SET NULL;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_authorization_codes_code_hash
    ON tbl_authorization_codes (code_hash);
CREATE INDEX IF NOT EXISTS IX_tbl_authorization_codes_product_id
    ON tbl_authorization_codes (product_id);
CREATE INDEX IF NOT EXISTS IX_tbl_authorization_codes_user_id
    ON tbl_authorization_codes (user_id);
CREATE INDEX IF NOT EXISTS IX_tbl_authorization_codes_expires_at
    ON tbl_authorization_codes (expires_at);
