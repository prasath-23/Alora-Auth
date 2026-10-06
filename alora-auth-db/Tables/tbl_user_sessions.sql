/****** Object: Table [tbl_user_sessions] ******/
-- One refresh-token generation. A login opens a family (family_id); each
-- refresh appends a generation and revokes its predecessor, which is what
-- makes token replay detectable.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_user_sessions (
    id                  TEXT                    NOT NULL DEFAULT gen_random_uuid()::text,
    user_id             TEXT                    NOT NULL,
    client_id           TEXT                    NOT NULL,
    session_uuid        TEXT                    NOT NULL,
    family_id           TEXT                    NOT NULL,
    generation          INTEGER                 NOT NULL DEFAULT 0,
    refresh_token_hash  TEXT                    NOT NULL,
    prev_token_hash     TEXT                    NULL,
    expires_at          TIMESTAMPTZ             NOT NULL,
    revoked_at          TIMESTAMPTZ             NULL,
    revoked_reason      "SessionRevokedReason"  NULL,
    ip_address          TEXT                    NULL,
    device_label        TEXT                    NULL,
    user_agent          TEXT                    NULL,
    last_seen_at        TIMESTAMPTZ             NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ             NOT NULL DEFAULT now(),
    replaced_by_id      TEXT                    NULL,
    CONSTRAINT PK_tbl_user_sessions PRIMARY KEY (id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_sessions_tbl_users_user_id') THEN
        ALTER TABLE tbl_user_sessions ADD CONSTRAINT FK_tbl_user_sessions_tbl_users_user_id
            FOREIGN KEY (user_id) REFERENCES tbl_users (id)
            ON DELETE CASCADE;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_sessions_tbl_clients_client_id') THEN
        ALTER TABLE tbl_user_sessions ADD CONSTRAINT FK_tbl_user_sessions_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_sessions_tbl_user_sessions_replaced_by_id') THEN
        ALTER TABLE tbl_user_sessions ADD CONSTRAINT FK_tbl_user_sessions_tbl_user_sessions_replaced_by_id
            FOREIGN KEY (replaced_by_id) REFERENCES tbl_user_sessions (id)
            ON DELETE SET NULL;
    END IF;
END $$;
--
-- TENANT ISOLATION. Makes a session belonging to user A but tenant B
-- physically unrepresentable, independently of any application check.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_sessions_tbl_users_user_id_client_id') THEN
        ALTER TABLE tbl_user_sessions ADD CONSTRAINT FK_tbl_user_sessions_tbl_users_user_id_client_id
            FOREIGN KEY (user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- Every generation belongs to a family of the same user and tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_user_sessions_family') THEN
        ALTER TABLE tbl_user_sessions ADD CONSTRAINT FK_tbl_user_sessions_family
            FOREIGN KEY (family_id, user_id, client_id) REFERENCES tbl_session_families (id, user_id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_user_sessions_session_uuid
    ON tbl_user_sessions (session_uuid);
--
-- Only the SHA-256 of the token is stored, so a database leak yields no
-- usable credentials. Unique because it is the rotation lookup key.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_user_sessions_refresh_token_hash
    ON tbl_user_sessions (refresh_token_hash);
--
-- A session may be superseded by at most one successor, so the family cannot
-- fork.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_user_sessions_replaced_by_id
    ON tbl_user_sessions (replaced_by_id);
--
-- Database-level backstop against two concurrent rotations both minting the
-- same generation.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_user_sessions_family_generation
    ON tbl_user_sessions (family_id, generation);
--
-- Burning a family on reuse detection updates every row sharing it.
CREATE INDEX IF NOT EXISTS IX_tbl_user_sessions_family_id
    ON tbl_user_sessions (family_id);
CREATE INDEX IF NOT EXISTS IX_tbl_user_sessions_user_client
    ON tbl_user_sessions (user_id, client_id);
--
-- Serves revoking every session of a user.
CREATE INDEX IF NOT EXISTS IX_tbl_user_sessions_user_revoked
    ON tbl_user_sessions (user_id, revoked_at);
--
-- Serves the hourly expiry sweep.
CREATE INDEX IF NOT EXISTS IX_tbl_user_sessions_expires_at
    ON tbl_user_sessions (expires_at);
--
-- The grace-race lookup runs INSIDE the rotation transaction while holding a
-- FOR UPDATE lock; unindexed it would hold that lock for O(n).
CREATE INDEX IF NOT EXISTS IX_tbl_user_sessions_prev_token_hash
    ON tbl_user_sessions (prev_token_hash) WHERE prev_token_hash IS NOT NULL AND revoked_at IS NULL;
