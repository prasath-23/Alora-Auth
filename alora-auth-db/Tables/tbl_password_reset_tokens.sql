/****** Object: Table [tbl_password_reset_tokens] ******/
-- A single-use password reset token, stored as its SHA-256 only. At most one
-- is live per user at a time.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_password_reset_tokens (
    id          TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    user_id     TEXT         NOT NULL,
    client_id   TEXT         NOT NULL,
    token_hash  TEXT         NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    used_at     TIMESTAMPTZ  NULL,
    created_by  TEXT         NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_password_reset_tokens PRIMARY KEY (id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_password_reset_tokens_tbl_users_user_id') THEN
        ALTER TABLE tbl_password_reset_tokens ADD CONSTRAINT FK_tbl_password_reset_tokens_tbl_users_user_id
            FOREIGN KEY (user_id) REFERENCES tbl_users (id)
            ON DELETE CASCADE;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_password_reset_tokens_tbl_clients_client_id') THEN
        ALTER TABLE tbl_password_reset_tokens ADD CONSTRAINT FK_tbl_password_reset_tokens_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- TENANT ISOLATION: a reset token cannot span tenants.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_password_reset_tokens_tbl_users_user_id_client_id') THEN
        ALTER TABLE tbl_password_reset_tokens ADD CONSTRAINT FK_tbl_password_reset_tokens_tbl_users_user_id_client_id
            FOREIGN KEY (user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_password_reset_tokens_token_hash
    ON tbl_password_reset_tokens (token_hash);
CREATE INDEX IF NOT EXISTS IX_tbl_password_reset_tokens_user_client
    ON tbl_password_reset_tokens (user_id, client_id);
