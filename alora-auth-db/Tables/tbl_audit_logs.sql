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
--
-- RESTRICT, NOT SET NULL. This was SET NULL, and that quietly defeated the
-- whole table: deleting a user made PostgreSQL rewrite existing audit rows and
-- erase WHO performed each action. Revoking UPDATE on this table does not
-- prevent it, because a referential action runs as the referencing table's
-- owner rather than as the caller -- verified against PostgreSQL 16, where the
-- app role was refused a direct UPDATE and then erased the same column anyway
-- by deleting the user.
--
-- With RESTRICT, a user who has done anything cannot be hard-deleted at all.
-- That costs nothing: every procedure here soft-deletes (deleted_at) and no
-- code path in this system hard-deletes a user. Erasure requests are served by
-- scrubbing the PII on tbl_users while the actor linkage stays intact, which
-- is the outcome you want anyway -- "some deleted account did this" is not an
-- audit trail.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_audit_logs_tbl_users_actor_user_id') THEN
        ALTER TABLE tbl_audit_logs ADD CONSTRAINT FK_tbl_audit_logs_tbl_users_actor_user_id
            FOREIGN KEY (actor_user_id) REFERENCES tbl_users (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- TENANT ISOLATION. Stops an audit row naming an actor from one tenant against
-- another tenant's client_id. MATCH SIMPLE (the default) skips the check when
-- actor_user_id IS NULL, which is what lets unauthenticated events -- a failed
-- login, a password-reset request -- be recorded with no actor.
--
-- NO ACTION rather than a cascade: the single-column FK above is RESTRICT, so
-- a delete is refused before this constraint is ever consulted. DEFERRABLE is
-- kept so a procedure may insert the audit row and the user row in either
-- order within one transaction.
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
