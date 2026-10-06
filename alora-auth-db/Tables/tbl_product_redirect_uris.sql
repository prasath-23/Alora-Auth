/****** Object: Table [tbl_product_redirect_uris] ******/
-- The exact redirect URIs a product may receive codes at. Matched
-- byte-for-byte, never by prefix or origin.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_product_redirect_uris (
    product_id    TEXT         NOT NULL,
    redirect_uri  TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_product_redirect_uris PRIMARY KEY (product_id, redirect_uri),
    CONSTRAINT CK_tbl_product_redirect_uris_redirect_uri CHECK (redirect_uri ~ '^https?://[^#]+$')
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_product_redirect_uris_tbl_products_product_id') THEN
        ALTER TABLE tbl_product_redirect_uris ADD CONSTRAINT FK_tbl_product_redirect_uris_tbl_products_product_id
            FOREIGN KEY (product_id) REFERENCES tbl_products (id)
            ON DELETE CASCADE;
    END IF;
END $$;
