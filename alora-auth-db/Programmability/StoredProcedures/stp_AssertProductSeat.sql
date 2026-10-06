/****** Object: Stored Procedure [stp_AssertProductSeat] ******/
-- Enforces a product subscription's seat_limit: the number of DISTINCT people who
-- may currently open the product (vw_EffectiveProductRole) must not exceed it.
-- Called by every mutation that can widen product access, AFTER it has made its
-- change, so it checks the resulting state directly. The subscription row is
-- locked FOR UPDATE first, so concurrent seat-consuming changes to the same
-- product serialise here and cannot both slip under the cap. A NULL seat_limit,
-- or no subscription row, is unlimited. Over the limit raises SQLSTATE AL001,
-- which the API maps to 409.
--
-- Implemented as a FUNCTION returning void: callers PERFORM it for its effect.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_AssertProductSeat(p_clientId TEXT, p_productId TEXT)
RETURNS void
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_limit INTEGER;
    v_count INTEGER;
BEGIN
    SELECT seat_limit INTO v_limit
    FROM   tbl_client_products
    WHERE  client_id = p_clientId AND product_id = p_productId
    FOR    UPDATE;

    IF v_limit IS NULL THEN
        RETURN;  -- no subscription row, or an unlimited one
    END IF;

    SELECT count(DISTINCT user_id) INTO v_count
    FROM   vw_EffectiveProductRole
    WHERE  client_id = p_clientId AND product_id = p_productId;

    IF v_count > v_limit THEN
        RAISE EXCEPTION 'product % in company % is at its seat limit of %', p_productId, p_clientId, v_limit
            USING ERRCODE = 'AL001';
    END IF;
END;
$$;
