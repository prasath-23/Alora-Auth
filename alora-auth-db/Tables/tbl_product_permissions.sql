/****** Object: Table [tbl_product_permissions] ******/
-- A user's DIRECT role within one product, granted by an Owner. Effective
-- access adds the roles the user's groups grant.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_product_permissions (
    id           TEXT         NOT NULL DEFAULT gen_random_uuid()::text,
    user_id      TEXT         NOT NULL,
    client_id    TEXT         NOT NULL,
    product_id   TEXT         NOT NULL,
    role_name    TEXT         NOT NULL,
    granted_by   TEXT         NULL,
    valid_from   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    valid_until  TIMESTAMPTZ  NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_product_permissions PRIMARY KEY (id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_product_permissions_tbl_users_user_id') THEN
        ALTER TABLE tbl_product_permissions ADD CONSTRAINT FK_tbl_product_permissions_tbl_users_user_id
            FOREIGN KEY (user_id) REFERENCES tbl_users (id)
            ON DELETE CASCADE;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_product_permissions_tbl_clients_client_id') THEN
        ALTER TABLE tbl_product_permissions ADD CONSTRAINT FK_tbl_product_permissions_tbl_clients_client_id
            FOREIGN KEY (client_id) REFERENCES tbl_clients (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_product_permissions_tbl_products_product_id') THEN
        ALTER TABLE tbl_product_permissions ADD CONSTRAINT FK_tbl_product_permissions_tbl_products_product_id
            FOREIGN KEY (product_id) REFERENCES tbl_products (id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- TENANT ISOLATION: a grant cannot reference a user from another tenant.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_product_permissions_tbl_users_user_id_client_id') THEN
        ALTER TABLE tbl_product_permissions ADD CONSTRAINT FK_tbl_product_permissions_tbl_users_user_id_client_id
            FOREIGN KEY (user_id, client_id) REFERENCES tbl_users (id, client_id)
            ON DELETE CASCADE;
    END IF;
END $$;
--
-- A role can only be granted in a product the tenant subscribes to.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_product_permissions_subscription') THEN
        ALTER TABLE tbl_product_permissions ADD CONSTRAINT FK_tbl_product_permissions_subscription
            FOREIGN KEY (client_id, product_id) REFERENCES tbl_client_products (client_id, product_id)
            ON DELETE RESTRICT;
    END IF;
END $$;
--
-- The role must be in the product's catalogue; a role still granted cannot
-- be removed from it.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_product_permissions_role') THEN
        ALTER TABLE tbl_product_permissions ADD CONSTRAINT FK_tbl_product_permissions_role
            FOREIGN KEY (product_id, role_name) REFERENCES tbl_product_roles (product_id, role_name)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- Unique constraints and indexes.
--
-- One role per user per product; a regrant is an upsert on this key.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_product_permissions_user_client_product
    ON tbl_product_permissions (user_id, client_id, product_id);
--
-- Child side of the tenant foreign key, probed on tenant delete.
CREATE INDEX IF NOT EXISTS IX_tbl_product_permissions_client_id
    ON tbl_product_permissions (client_id);
