/****** Object: Table [tbl_invitation_products] ******/
-- The products and roles an invitation grants on acceptance.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_invitation_products (
    id             TEXT  NOT NULL DEFAULT gen_random_uuid()::text,
    invitation_id  TEXT  NOT NULL,
    product_id     TEXT  NOT NULL,
    role_name      TEXT  NOT NULL,
    CONSTRAINT PK_tbl_invitation_products PRIMARY KEY (id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_invitation_products_tbl_invitations_invitation_id') THEN
        ALTER TABLE tbl_invitation_products ADD CONSTRAINT FK_tbl_invitation_products_tbl_invitations_invitation_id
            FOREIGN KEY (invitation_id) REFERENCES tbl_invitations (id)
            ON DELETE CASCADE;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_invitation_products_tbl_products_product_id') THEN
        ALTER TABLE tbl_invitation_products ADD CONSTRAINT FK_tbl_invitation_products_tbl_products_product_id
            FOREIGN KEY (product_id) REFERENCES tbl_products (id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_invitation_products_invitation_product
    ON tbl_invitation_products (invitation_id, product_id);
