/****** Object: Table [tbl_authorization_codes] ******/
-- A single-use OAuth2 authorization code with its PKCE challenge. Redeemed
-- by exactly one atomic UPDATE, so it cannot be double-spent.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_authorization_codes (
    id                     TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    code                   TEXT         NOT NULL,
    product_id             TEXT         NOT NULL,
    user_id                TEXT         NOT NULL,
    redirect_url           TEXT         NOT NULL,
    code_challenge         TEXT         NOT NULL,
    code_challenge_method  TEXT         NOT NULL DEFAULT 'S256',
    state                  TEXT         NULL,
    expires_at             TIMESTAMPTZ  NOT NULL,
    used_at                TIMESTAMPTZ  NULL,
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
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_authorization_codes_tbl_users_user_id') THEN
        ALTER TABLE tbl_authorization_codes ADD CONSTRAINT FK_tbl_authorization_codes_tbl_users_user_id
            FOREIGN KEY (user_id) REFERENCES tbl_users (id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_authorization_codes_code
    ON tbl_authorization_codes (code);
CREATE INDEX IF NOT EXISTS IX_tbl_authorization_codes_product_id
    ON tbl_authorization_codes (product_id);
--
-- Child side of a RESTRICT foreign key, probed on user delete.
CREATE INDEX IF NOT EXISTS IX_tbl_authorization_codes_user_id
    ON tbl_authorization_codes (user_id);
CREATE INDEX IF NOT EXISTS IX_tbl_authorization_codes_expires_at
    ON tbl_authorization_codes (expires_at);
