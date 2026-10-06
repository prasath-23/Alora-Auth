/****** Object: Table [tbl_api_client_scopes] ******/
-- Where an API client's credential may be used: CLIENT scopes from the
-- catalogue (a product's REST API, its gRPC services, its MCP tools). A
-- product token issued to the client carries these, or fewer.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_api_client_scopes (
    api_client_id  TEXT  NOT NULL,
    client_id      TEXT  NOT NULL,
    scope          TEXT  NOT NULL,
    kind           TEXT  NOT NULL DEFAULT 'CLIENT',
    CONSTRAINT PK_tbl_api_client_scopes PRIMARY KEY (api_client_id, scope),
    CONSTRAINT CK_tbl_api_client_scopes_kind CHECK (kind = 'CLIENT')
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
--
-- TENANT ISOLATION: the scope lives in the API client's tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_api_client_scopes_api_client') THEN
        ALTER TABLE tbl_api_client_scopes ADD CONSTRAINT FK_tbl_api_client_scopes_api_client
            FOREIGN KEY (api_client_id, client_id) REFERENCES tbl_api_clients (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- Only an application scope from the catalogue can be given.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_api_client_scopes_tbl_scopes_scope_kind') THEN
        ALTER TABLE tbl_api_client_scopes ADD CONSTRAINT FK_tbl_api_client_scopes_tbl_scopes_scope_kind
            FOREIGN KEY (scope, kind) REFERENCES tbl_scopes (scope, kind)
            ON DELETE RESTRICT;
    END IF;
END $$;
