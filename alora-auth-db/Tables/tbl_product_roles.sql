/****** Object: Table [tbl_product_roles] ******/
-- The role catalogue of a product. Role names become token claims, so they
-- are validated against this list rather than free text: a typo would
-- otherwise grant nothing, silently.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_product_roles (
    product_id   TEXT         NOT NULL,
    role_name    TEXT         NOT NULL,
    description  TEXT         NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_product_roles PRIMARY KEY (product_id, role_name),
    CONSTRAINT CK_tbl_product_roles_role_name CHECK (role_name ~ '^[A-Za-z][A-Za-z0-9 _-]{0,63}$')
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_product_roles_tbl_products_product_id') THEN
        ALTER TABLE tbl_product_roles ADD CONSTRAINT FK_tbl_product_roles_tbl_products_product_id
            FOREIGN KEY (product_id) REFERENCES tbl_products (id)
            ON DELETE CASCADE;
    END IF;
END $$;
