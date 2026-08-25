/****** Object: Table [tbl_audit_logs] ******/
-- Append-only audit trail. No procedure in this schema updates or deletes
-- from this table, which is what makes the trail trustworthy.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_audit_logs (
    id              TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    client_id       TEXT         NOT NULL,
    actor_user_id   TEXT         NULL,
    event_type      TEXT         NOT NULL,
    event_metadata  JSONB        NULL,
    ip_address      TEXT         NULL,
    user_agent      TEXT         NULL,
    request_id      TEXT         NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_audit_logs PRIMARY KEY (id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_audit_logs_tbl_clients_client_id') THEN
        ALTER TABLE tbl_audit_logs ADD CONSTRAINT FK_tbl_audit_logs_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_audit_logs_tbl_users_actor_user_id') THEN
        ALTER TABLE tbl_audit_logs ADD CONSTRAINT FK_tbl_audit_logs_tbl_users_actor_user_id
            FOREIGN KEY (actor_user_id) REFERENCES tbl_users (id)
            ON DELETE SET NULL;
    END IF;
END $$;
--
-- TENANT ISOLATION for a nullable actor. ON DELETE SET NULL is impossible
-- here: it would null client_id too, which is NOT NULL. Instead the
-- single-column actor FK nulls the actor first, and MATCH SIMPLE lets this
-- composite pass once actor_user_id IS NULL. DEFERRABLE so the check runs at
-- COMMIT, after that SET NULL has applied.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_audit_logs_tbl_users_actor_user_id_client_id') THEN
        ALTER TABLE tbl_audit_logs ADD CONSTRAINT FK_tbl_audit_logs_tbl_users_actor_user_id_client_id
            FOREIGN KEY (actor_user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE INDEX IF NOT EXISTS IX_tbl_audit_logs_client_created
    ON tbl_audit_logs (client_id, created_at);
CREATE INDEX IF NOT EXISTS IX_tbl_audit_logs_client_event_created
    ON tbl_audit_logs (client_id, event_type, created_at);
CREATE INDEX IF NOT EXISTS IX_tbl_audit_logs_request_id
    ON tbl_audit_logs (request_id);
CREATE INDEX IF NOT EXISTS IX_tbl_audit_logs_actor_user_id
    ON tbl_audit_logs (actor_user_id);
