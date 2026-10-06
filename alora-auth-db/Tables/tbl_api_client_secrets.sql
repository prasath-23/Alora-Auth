/****** Object: Table [tbl_api_client_secrets] ******/
-- An API client's secrets, as SHA-256 hashes only: the plaintext is shown
-- once, when it is made. At most two are live at a time, so a secret rotates
-- without downtime -- make a second, deploy it, revoke the first. A secret
-- is revoked by stamping revoked_at, never deleted.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_api_client_secrets (
    id                   TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    api_client_id        TEXT         NOT NULL,
    client_id            TEXT         NOT NULL,
    secret_hash          TEXT         NOT NULL,
    prefix               TEXT         NOT NULL,
    expires_at           TIMESTAMPTZ  NULL,
    revoked_at           TIMESTAMPTZ  NULL,
    last_used_at         TIMESTAMPTZ  NULL,
    created_by_user_id   TEXT         NULL,
    created_by_owner_id  TEXT         NULL,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_api_client_secrets PRIMARY KEY (id),
    CONSTRAINT CK_tbl_api_client_secrets_prefix CHECK (prefix ~ '^acc_[A-Za-z0-9_-]{4,12}$'),
    CONSTRAINT CK_tbl_api_client_secrets_one_creator CHECK (num_nonnulls(created_by_user_id, created_by_owner_id) = 1)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
--
-- TENANT ISOLATION: the secret lives in the API client's tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_api_client_secrets_api_client') THEN
        ALTER TABLE tbl_api_client_secrets ADD CONSTRAINT FK_tbl_api_client_secrets_api_client
            FOREIGN KEY (api_client_id, client_id) REFERENCES tbl_api_clients (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- A user who makes one must belong to its tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_api_client_secrets_created_by_user') THEN
        ALTER TABLE tbl_api_client_secrets ADD CONSTRAINT FK_tbl_api_client_secrets_created_by_user
            FOREIGN KEY (created_by_user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_api_client_secrets_created_by_owner') THEN
        ALTER TABLE tbl_api_client_secrets ADD CONSTRAINT FK_tbl_api_client_secrets_created_by_owner
            FOREIGN KEY (created_by_owner_id) REFERENCES tbl_platform_owners (user_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_api_client_secrets_secret_hash
    ON tbl_api_client_secrets (secret_hash);
--
-- Serves client authentication: the live secrets of one API client.
CREATE INDEX IF NOT EXISTS IX_tbl_api_client_secrets_api_client
    ON tbl_api_client_secrets (api_client_id, client_id);
--
-- Child side of a RESTRICT foreign key, probed on every user delete.
CREATE INDEX IF NOT EXISTS IX_tbl_api_client_secrets_created_by
    ON tbl_api_client_secrets (created_by_user_id);
