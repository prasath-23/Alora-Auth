/****** Object: Table [tbl_scopes] ******/
-- The closed catalogue of scopes. PERSON scopes are what a person may do in
-- App Central (each feature has a read scope and, where it can be changed,
-- an edit scope); CLIENT scopes are where an API client's credential may be
-- used. Every grant of a scope references this table, so an unknown scope
-- cannot be stored, and the ADMINS group's 'every scope' is this table's
-- PERSON rows.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_scopes (
    scope        TEXT     NOT NULL,
    kind         TEXT     NOT NULL,
    feature      TEXT     NOT NULL,
    level        TEXT     NOT NULL,
    description  TEXT     NOT NULL,
    sort_order   INTEGER  NOT NULL,
    CONSTRAINT PK_tbl_scopes PRIMARY KEY (scope),
    CONSTRAINT CK_tbl_scopes_kind CHECK (kind IN ('PERSON', 'CLIENT')),
    CONSTRAINT CK_tbl_scopes_scope CHECK (scope ~ '^[a-z][a-z-]*:[a-z]+$'),
    CONSTRAINT CK_tbl_scopes_level CHECK (level IN ('read', 'edit', 'tools'))
);

-- Unique constraints and indexes.
--
-- The target of the grant tables' composite keys, which pin each grant to a
-- scope of the right kind.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_scopes_scope_kind
    ON tbl_scopes (scope, kind);

-- Reference rows: upserted on every build, never deleted here (a grant may
-- still name one).
INSERT INTO tbl_scopes (scope, kind, feature, level, description, sort_order) VALUES
    ('users:read', 'PERSON', 'users', 'read', 'See the company''s users', 10),
    ('users:edit', 'PERSON', 'users', 'edit', 'Activate and deactivate users, send password resets, give extra scopes', 11),
    ('groups:read', 'PERSON', 'groups', 'read', 'See groups and their members', 20),
    ('groups:edit', 'PERSON', 'groups', 'edit', 'Create, rename and delete groups, choose their scopes, add and remove members', 21),
    ('invitations:read', 'PERSON', 'invitations', 'read', 'See invitations', 30),
    ('invitations:edit', 'PERSON', 'invitations', 'edit', 'Invite people into groups, revoke invitations', 31),
    ('sessions:read', 'PERSON', 'sessions', 'read', 'See who is signed in', 40),
    ('sessions:edit', 'PERSON', 'sessions', 'edit', 'Revoke sessions', 41),
    ('products:read', 'PERSON', 'products', 'read', 'See the company''s subscriptions', 50),
    ('company:read', 'PERSON', 'company', 'read', 'See the company''s settings', 60),
    ('company:edit', 'PERSON', 'company', 'edit', 'Rename the company', 61),
    ('api-clients:read', 'PERSON', 'api-clients', 'read', 'See API clients', 70),
    ('api-clients:edit', 'PERSON', 'api-clients', 'edit', 'Create API clients, rotate their secrets, choose their products and scope', 71),
    ('api:read', 'CLIENT', 'api', 'read', 'Read through the product''s REST API', 110),
    ('api:edit', 'CLIENT', 'api', 'edit', 'Change data through the product''s REST API', 111),
    ('grpc:read', 'CLIENT', 'grpc', 'read', 'Read through the product''s gRPC services', 120),
    ('grpc:edit', 'CLIENT', 'grpc', 'edit', 'Change data through the product''s gRPC services', 121),
    ('mcp:tools', 'CLIENT', 'mcp', 'tools', 'Use the product''s MCP tools', 130)
ON CONFLICT (scope) DO UPDATE
SET    kind = EXCLUDED.kind,
       feature = EXCLUDED.feature,
       level = EXCLUDED.level,
       description = EXCLUDED.description,
       sort_order = EXCLUDED.sort_order;
