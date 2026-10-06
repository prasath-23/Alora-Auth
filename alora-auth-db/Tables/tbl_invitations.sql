/****** Object: Table [tbl_invitations] ******/
-- A pending invitation. Only the SHA-256 of the token is stored; the raw
-- value exists solely in the email that was sent. Issued by a tenant Admin
-- or by an Owner, never both.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_invitations (
    id                   TEXT                NOT NULL DEFAULT gen_random_uuid()::text,
    email                TEXT                NOT NULL,
    client_id            TEXT                NOT NULL,
    invited_by_user_id   TEXT                NULL,
    invited_by_owner_id  TEXT                NULL,
    token_hash           TEXT                NOT NULL,
    expires_at           TIMESTAMPTZ         NOT NULL,
    status               "InvitationStatus"  NOT NULL DEFAULT 'PENDING',
    accepted_at          TIMESTAMPTZ         NULL,
    accepted_by_user_id  TEXT                NULL,
    revoked_at           TIMESTAMPTZ         NULL,
    revoked_by_user_id   TEXT                NULL,
    created_at           TIMESTAMPTZ         NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ         NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_invitations PRIMARY KEY (id),
    CONSTRAINT CK_tbl_invitations_one_inviter CHECK (num_nonnulls(invited_by_user_id, invited_by_owner_id) = 1)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_invitations_tbl_clients_client_id') THEN
        ALTER TABLE tbl_invitations ADD CONSTRAINT FK_tbl_invitations_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_invitations_tbl_users_invited_by_user_id') THEN
        ALTER TABLE tbl_invitations ADD CONSTRAINT FK_tbl_invitations_tbl_users_invited_by_user_id
            FOREIGN KEY (invited_by_user_id) REFERENCES tbl_users (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_invitations_tbl_users_accepted_by_user_id') THEN
        ALTER TABLE tbl_invitations ADD CONSTRAINT FK_tbl_invitations_tbl_users_accepted_by_user_id
            FOREIGN KEY (accepted_by_user_id) REFERENCES tbl_users (id)
            ON DELETE SET NULL;
    END IF;
END $$;
--
-- TENANT ISOLATION: an Admin inviter must belong to the invited tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_invitations_tbl_users_invited_by_user_id_client_id') THEN
        ALTER TABLE tbl_invitations ADD CONSTRAINT FK_tbl_invitations_tbl_users_invited_by_user_id_client_id
            FOREIGN KEY (invited_by_user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- An Owner may invite into any tenant, which is how a new tenant gets its
-- first Admin.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_invitations_tbl_platform_owners_invited_by_owner_id') THEN
        ALTER TABLE tbl_invitations ADD CONSTRAINT FK_tbl_invitations_tbl_platform_owners_invited_by_owner_id
            FOREIGN KEY (invited_by_owner_id) REFERENCES tbl_platform_owners (user_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_invitations_token_hash
    ON tbl_invitations (token_hash);
--
-- The target of tbl_invitation_groups' composite key.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_invitations_id_client_id
    ON tbl_invitations (id, client_id);
--
-- One live invitation per address per company, whatever arrives at once: a
-- re-invite can never leave two independently redeemable tokens, so revoking
-- an invitation revokes the address's only one. stp_CreateInvitation expires
-- a pending invitation past its expiry first, so it never blocks a new one.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_invitations_client_email_pending
    ON tbl_invitations (client_id, lower(email)) WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS IX_tbl_invitations_email_client_status
    ON tbl_invitations (email, client_id, status);
--
-- Serves the admin pending-invitations list.
CREATE INDEX IF NOT EXISTS IX_tbl_invitations_client_status_created
    ON tbl_invitations (client_id, status, created_at);
--
-- Serves the six-hourly expiry sweep.
CREATE INDEX IF NOT EXISTS IX_tbl_invitations_expires_status
    ON tbl_invitations (expires_at, status);
--
-- Child side of a RESTRICT foreign key, probed on every user delete.
CREATE INDEX IF NOT EXISTS IX_tbl_invitations_invited_by
    ON tbl_invitations (invited_by_user_id);
CREATE INDEX IF NOT EXISTS IX_tbl_invitations_accepted_by
    ON tbl_invitations (accepted_by_user_id);
