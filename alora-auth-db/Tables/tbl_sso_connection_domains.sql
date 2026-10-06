/****** Object: Table [tbl_sso_connection_domains] ******/
-- The email domains an Owner attested for an SSO connection. Globally
-- unique, so one domain routes to one connection.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_sso_connection_domains (
    domain         TEXT  NOT NULL,
    connection_id  TEXT  NOT NULL,
    client_id      TEXT  NOT NULL,
    CONSTRAINT PK_tbl_sso_connection_domains PRIMARY KEY (domain),
    CONSTRAINT CK_tbl_sso_connection_domains_lower CHECK (domain = lower(domain)),
    CONSTRAINT CK_tbl_sso_connection_domains_length CHECK (length(domain) BETWEEN 1 AND 253)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_sso_connection_domains_connection') THEN
        ALTER TABLE tbl_sso_connection_domains ADD CONSTRAINT FK_tbl_sso_connection_domains_connection
            FOREIGN KEY (connection_id, client_id) REFERENCES tbl_sso_connections (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
