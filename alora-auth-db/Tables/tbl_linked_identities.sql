/****** Object: Table [tbl_linked_identities] ******/
-- An external identity (e.g. a Google account) bound to a local user.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_linked_identities (
    id              TEXT           NOT NULL DEFAULT gen_random_uuid()::text,
    user_id         TEXT           NOT NULL,
    provider        "IdpProvider"  NOT NULL,
    provider_id     TEXT           NOT NULL,
    email_verified  BOOLEAN        NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ    NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_linked_identities PRIMARY KEY (id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_linked_identities_tbl_users_user_id') THEN
        ALTER TABLE tbl_linked_identities ADD CONSTRAINT FK_tbl_linked_identities_tbl_users_user_id
            FOREIGN KEY (user_id) REFERENCES tbl_users (id)
            ON DELETE CASCADE;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- provider_id is the provider's STABLE subject id, never the email: a user
-- who changes their Google address keeps their account, and someone who
-- acquires a recycled address does not inherit one.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_linked_identities_provider_provider_id
    ON tbl_linked_identities (provider, provider_id);
CREATE INDEX IF NOT EXISTS IX_tbl_linked_identities_user_id
    ON tbl_linked_identities (user_id);
