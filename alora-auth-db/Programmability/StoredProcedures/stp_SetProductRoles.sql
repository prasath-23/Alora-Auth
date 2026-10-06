/****** Object: Stored Procedure [stp_SetProductRoles] ******/
-- Replaces a product's role catalogue with the complete desired set.
-- Removing a role that is still granted fails on its foreign key (23503),
-- which the caller reports as a conflict instead of silently revoking
-- access.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetProductRoles(p_productId TEXT, p_roleNames TEXT[])
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    DELETE FROM tbl_product_roles
    WHERE  product_id = p_productId
      AND  role_name <> ALL (p_roleNames);
    INSERT INTO tbl_product_roles (product_id, role_name)
    SELECT DISTINCT p_productId, r FROM unnest(p_roleNames) AS r
    ON CONFLICT (product_id, role_name) DO NOTHING;
    SELECT count(*)::int FROM tbl_product_roles WHERE product_id = p_productId;
$$;
