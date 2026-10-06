/****** Object: Stored Procedure [stp_UpsertProductPermission] ******/
-- Grants or re-grants a DIRECT product role, and bumps the user's
-- permissions_version in the same statement. ON CONFLICT on the natural key makes
-- a regrant idempotent instead of raising a duplicate-key error; the composite
-- keys refuse an unsubscribed product and an unknown role.
--
-- SEAT LIMIT: after the grant, the product's seat_limit is enforced
-- (stp_AssertProductSeat) in the same transaction, so a grant that would let one
-- person too many open the product is rolled back as 409.
--
-- Implemented as a PROCEDURE: nothing is returned, so the caller invokes it with
-- CALL. plpgsql (not plain SQL) because of the seat guard.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_UpsertProductPermission(p_userId TEXT, p_clientId TEXT, p_productId TEXT, p_roleName TEXT, p_grantedBy TEXT)
LANGUAGE plpgsql
AS $$
BEGIN
    WITH up AS (
        INSERT INTO tbl_product_permissions (user_id, client_id, product_id, role_name, granted_by)
        VALUES (p_userId, p_clientId, p_productId, p_roleName, p_grantedBy)
        ON CONFLICT (user_id, client_id, product_id)
        DO UPDATE SET role_name  = EXCLUDED.role_name,
                      granted_by = EXCLUDED.granted_by
        RETURNING user_id, client_id
    )
    UPDATE tbl_users u
    SET    permissions_version = u.permissions_version + 1
    FROM   up
    WHERE  u.id = up.user_id AND u.client_id = up.client_id;

    PERFORM stp_AssertProductSeat(p_clientId, p_productId);
END;
$$;
