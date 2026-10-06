/****** Object: Table [tbl_sso_connections] ******/
-- A tenant's own OIDC identity provider (Okta, Entra ID, Google Workspace).
-- The client secret is stored only as ciphertext, encrypted with a key held
-- outside the database.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_sso_connections (
    id                        TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    client_id                 TEXT         NOT NULL,
    name                      TEXT         NOT NULL,
    issuer                    TEXT         NOT NULL,
    oidc_client_id            TEXT         NOT NULL,
    client_secret_ciphertext  BYTEA        NULL,
    secret_key_id             TEXT         NULL,
    scopes                    TEXT         NOT NULL DEFAULT 'openid email profile',
    trust_unverified_email    BOOLEAN      NOT NULL DEFAULT false,
    is_active                 BOOLEAN      NOT NULL DEFAULT true,
    created_at                TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_sso_connections PRIMARY KEY (id),
    CONSTRAINT CK_tbl_sso_connections_issuer CHECK (issuer ~ '^https?://')
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_sso_connections_tbl_clients_client_id') THEN
        ALTER TABLE tbl_sso_connections ADD CONSTRAINT FK_tbl_sso_connections_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- The target of the composite keys that pin policies, identities and
-- sessions to the connection's own tenant.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_sso_connections_id_client_id
    ON tbl_sso_connections (id, client_id);
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_sso_connections_client_name
    ON tbl_sso_connections (client_id, lower(name));
--
-- One registration at an identity provider serves one connection.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_sso_connections_issuer_client
    ON tbl_sso_connections (issuer, oidc_client_id);
