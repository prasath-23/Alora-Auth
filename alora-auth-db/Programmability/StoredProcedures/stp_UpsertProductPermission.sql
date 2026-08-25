/****** Object: Stored Procedure [stp_UpsertProductPermission] ******/
-- Grants or re-grants a product role. ON CONFLICT on the natural key makes a
-- regrant idempotent instead of raising a duplicate-key error.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_UpsertProductPermission(p_userId TEXT, p_clientId TEXT, p_productId TEXT, p_roleName TEXT, p_grantedBy TEXT)
LANGUAGE sql
AS $$
    INSERT INTO tbl_product_permissions (user_id, client_id, product_id, role_name, granted_by)
    VALUES (p_userId, p_clientId, p_productId, p_roleName, p_grantedBy)
    ON CONFLICT (user_id, client_id, product_id)
    DO UPDATE SET role_name  = EXCLUDED.role_name,
                  granted_by = EXCLUDED.granted_by;
$$;
