/****** Object: Table [tbl_api_client_products] ******/
-- The products an API client may get a token for, each one its tenant
-- subscribes to. Whether the product accepts API clients is checked when it
-- is put on the list and again at every token.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_api_client_products (
    api_client_id  TEXT         NOT NULL,
    client_id      TEXT         NOT NULL,
    product_id     TEXT         NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_api_client_products PRIMARY KEY (api_client_id, product_id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
--
-- TENANT ISOLATION: the entry lives in the API client's tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_api_client_products_api_client') THEN
        ALTER TABLE tbl_api_client_products ADD CONSTRAINT FK_tbl_api_client_products_api_client
            FOREIGN KEY (api_client_id, client_id) REFERENCES tbl_api_clients (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- Only a product the tenant subscribes to can be listed.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_api_client_products_subscription') THEN
        ALTER TABLE tbl_api_client_products ADD CONSTRAINT FK_tbl_api_client_products_subscription
            FOREIGN KEY (client_id, product_id) REFERENCES tbl_client_products (client_id, product_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- Child side of the subscription key.
CREATE INDEX IF NOT EXISTS IX_tbl_api_client_products_client_product
    ON tbl_api_client_products (client_id, product_id);
