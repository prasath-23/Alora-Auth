/****** Object: Stored Procedure [stp_SetGroupProductGrants] ******/
-- Replaces the product roles a group confers, wholesale. Tenant ownership is
-- re-derived through tbl_groups (-1 when the group is not in this tenant), and
-- the composite keys refuse a product the tenant does not subscribe to or a role
-- outside the product's catalogue.
--
-- Every member's permissions_version is bumped: their tokens carry roles, so
-- they must be re-minted before a revoked role stops applying.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetGroupProductGrants(
    p_groupId    TEXT,
    p_clientId   TEXT,
    p_productIds TEXT[],
    p_roleNames  TEXT[],
    p_grantedBy  TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_inserted INTEGER := 0;
    v_pid      TEXT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM tbl_groups g
                   WHERE  g.id = p_groupId AND g.client_id = p_clientId) THEN
        RETURN -1;
    END IF;
    IF coalesce(array_length(p_productIds, 1), 0) <> coalesce(array_length(p_roleNames, 1), 0) THEN
        RAISE EXCEPTION 'product and role lists differ in length' USING ERRCODE = '22023';
    END IF;

    DELETE FROM tbl_group_product_grants
    WHERE  group_id = p_groupId AND client_id = p_clientId;

    IF coalesce(array_length(p_productIds, 1), 0) > 0 THEN
        INSERT INTO tbl_group_product_grants (group_id, client_id, product_id, role_name, granted_by)
        SELECT p_groupId, p_clientId, g.product_id, g.role_name, p_grantedBy
        FROM   unnest(p_productIds, p_roleNames) AS g(product_id, role_name);
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
    END IF;

    UPDATE tbl_users u
    SET    permissions_version = u.permissions_version + 1,
           updated_at          = now()
    FROM   tbl_user_groups ug
    WHERE  ug.group_id  = p_groupId
      AND  ug.client_id = p_clientId
      AND  u.id         = ug.user_id
      AND  u.client_id  = ug.client_id;

    -- Attaching a product to the group grants it to every member at once, so
    -- hold each newly-granted product's seat_limit (product-id order, so
    -- concurrent grants take the subscription locks consistently).
    FOR v_pid IN
        SELECT product_id FROM tbl_group_product_grants
        WHERE  group_id = p_groupId AND client_id = p_clientId
        ORDER  BY product_id
    LOOP
        PERFORM stp_AssertProductSeat(p_clientId, v_pid);
    END LOOP;

    RETURN v_inserted;
END;
$$;
