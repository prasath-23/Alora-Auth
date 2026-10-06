/****** Object: Table [tbl_client_products] ******/
-- A tenant's subscription to a product.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_client_products (
    id          TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    client_id   TEXT         NOT NULL,
    product_id  TEXT         NOT NULL,
    is_active   BOOLEAN      NOT NULL DEFAULT true,
    seat_limit  INTEGER      NULL,
    starts_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    ends_at     TIMESTAMPTZ  NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_client_products PRIMARY KEY (id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_client_products_tbl_clients_client_id') THEN
        ALTER TABLE tbl_client_products ADD CONSTRAINT FK_tbl_client_products_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE CASCADE;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_client_products_tbl_products_product_id') THEN
        ALTER TABLE tbl_client_products ADD CONSTRAINT FK_tbl_client_products_tbl_products_product_id
            FOREIGN KEY (product_id) REFERENCES tbl_products (id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- Also the target of the composite keys that tie grants and product sessions
-- to a subscription.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_client_products_client_product
    ON tbl_client_products (client_id, product_id);
--
-- Serves the entitlement check on every launch.
CREATE INDEX IF NOT EXISTS IX_tbl_client_products_client_active
    ON tbl_client_products (client_id, is_active);
