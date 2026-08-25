/****** Object: Table [tbl_products] ******/
-- The global product catalogue. NOT tenant-scoped: products are
-- platform-wide, and a tenant's access is expressed by tbl_client_products.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_products (
    id           TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    key          TEXT         NOT NULL,
    name         TEXT         NOT NULL,
    description  TEXT         NULL,
    base_url     TEXT         NULL,
    is_active    BOOLEAN      NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_products PRIMARY KEY (id)
);

-- Unique constraints and indexes.
--
-- The key is embedded in the JWT audience as product:<key>, so it must
-- identify exactly one product.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_products_key
    ON tbl_products (key);
