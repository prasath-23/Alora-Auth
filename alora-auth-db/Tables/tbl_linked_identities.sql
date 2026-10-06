/****** Object: Table [tbl_linked_identities] ******/
-- An external identity (Google, or a tenant's own OIDC provider) bound to a
-- local user. A Google account is linked at most once per tenant; an SSO
-- subject once per connection.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_linked_identities (
    id              TEXT           NOT NULL DEFAULT gen_random_uuid()::text,
    user_id         TEXT           NOT NULL,
    client_id       TEXT           NOT NULL,
    provider        "IdpProvider"  NOT NULL,
    connection_id   TEXT           NULL,
    provider_id     TEXT           NOT NULL,
    email_verified  BOOLEAN        NOT NULL DEFAULT false,
    email_at_link   TEXT           NULL,
    created_at      TIMESTAMPTZ    NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_linked_identities PRIMARY KEY (id),
    CONSTRAINT CK_tbl_linked_identities_provider CHECK (provider IN ('GOOGLE', 'OIDC')),
    CONSTRAINT CK_tbl_linked_identities_connection CHECK ((provider = 'OIDC') = (connection_id IS NOT NULL)),
    CONSTRAINT CK_tbl_linked_identities_provider_id_length CHECK (length(provider_id) BETWEEN 1 AND 255)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_linked_identities_tbl_users_user_id_client_id') THEN
        ALTER TABLE tbl_linked_identities ADD CONSTRAINT FK_tbl_linked_identities_tbl_users_user_id_client_id
            FOREIGN KEY (user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_linked_identities_connection') THEN
        ALTER TABLE tbl_linked_identities ADD CONSTRAINT FK_tbl_linked_identities_connection
            FOREIGN KEY (connection_id, client_id) REFERENCES tbl_sso_connections (id, client_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- provider_id is the provider's STABLE subject id, never the email: a user
-- who changes their Google address keeps their account, and someone who
-- acquires a recycled address does not inherit one. One Google account may
-- serve accounts in several tenants, but only one per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_linked_identities_google_subject_client
    ON tbl_linked_identities (provider_id, client_id) WHERE provider = 'GOOGLE';
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_linked_identities_google_user
    ON tbl_linked_identities (user_id) WHERE provider = 'GOOGLE';
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_linked_identities_oidc_subject
    ON tbl_linked_identities (connection_id, provider_id) WHERE provider = 'OIDC';
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_linked_identities_oidc_user
    ON tbl_linked_identities (user_id, connection_id) WHERE provider = 'OIDC';
CREATE INDEX IF NOT EXISTS IX_tbl_linked_identities_user_id
    ON tbl_linked_identities (user_id);
