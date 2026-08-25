/****** Object: Stored Procedure [stp_DeleteProductPermission] ******/
-- Revokes a product role, tenant-scoped. The count lets the caller answer
-- 404 rather than reporting success for a grant that never existed.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_DeleteProductPermission(p_userId TEXT, p_clientId TEXT, p_productId TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH del AS (
        DELETE FROM tbl_product_permissions
        WHERE  user_id    = p_userId
          AND  client_id  = p_clientId
          AND  product_id = p_productId
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
