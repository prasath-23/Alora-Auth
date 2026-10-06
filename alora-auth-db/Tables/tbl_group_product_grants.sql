/****** Object: Table [tbl_group_product_grants] ******/
-- A product role a group confers on every member.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_group_product_grants (
    group_id    TEXT         NOT NULL,
    client_id   TEXT         NOT NULL,
    product_id  TEXT         NOT NULL,
    role_name   TEXT         NOT NULL,
    granted_by  TEXT         NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_group_product_grants PRIMARY KEY (group_id, product_id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
--
-- TENANT ISOLATION: the grant lives in the group's tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_group_product_grants_tbl_groups_group_id_client_id') THEN
        ALTER TABLE tbl_group_product_grants ADD CONSTRAINT FK_tbl_group_product_grants_tbl_groups_group_id_client_id
            FOREIGN KEY (group_id, client_id) REFERENCES tbl_groups (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- A group can only grant a product its tenant subscribes to.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_group_product_grants_subscription') THEN
        ALTER TABLE tbl_group_product_grants ADD CONSTRAINT FK_tbl_group_product_grants_subscription
            FOREIGN KEY (client_id, product_id) REFERENCES tbl_client_products (client_id, product_id)
            ON DELETE RESTRICT;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_group_product_grants_role') THEN
        ALTER TABLE tbl_group_product_grants ADD CONSTRAINT FK_tbl_group_product_grants_role
            FOREIGN KEY (product_id, role_name) REFERENCES tbl_product_roles (product_id, role_name)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE INDEX IF NOT EXISTS IX_tbl_group_product_grants_client_product
    ON tbl_group_product_grants (client_id, product_id);
