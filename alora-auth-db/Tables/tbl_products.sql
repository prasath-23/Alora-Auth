/****** Object: Table [tbl_products] ******/
-- The global product catalogue, and each product's registration as a
-- CONFIDENTIAL OAuth client. NOT tenant-scoped: products are platform-wide,
-- and a tenant's access is expressed by tbl_client_products. A product
-- receives application tokens (API clients) only once the Owner switches
-- accepts_api_clients on.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_products (
    id                   TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    key                  TEXT         NOT NULL,
    name                 TEXT         NOT NULL,
    description          TEXT         NULL,
    base_url             TEXT         NULL,
    initiate_login_uri   TEXT         NULL,
    client_secret_hash   TEXT         NULL,
    secret_rotated_at    TIMESTAMPTZ  NULL,
    is_active            BOOLEAN      NOT NULL DEFAULT true,
    accepts_api_clients  BOOLEAN      NOT NULL DEFAULT false,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_products PRIMARY KEY (id),
    CONSTRAINT CK_tbl_products_initiate_login_uri CHECK (initiate_login_uri IS NULL OR initiate_login_uri ~ '^https?://[^#]+$')
);

-- Unique constraints and indexes.
--
-- The key is embedded in the token audience as product:<key>, so it must
-- identify exactly one product.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_products_key
    ON tbl_products (key);
