/****** Object: Stored Procedure [stp_UpsertSubscription] ******/
-- Subscribes a tenant to a product, or changes the subscription.
-- Deactivating a subscription stops every launch and refresh of that product
-- for the tenant, because effective access requires a live subscription.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_UpsertSubscription(p_clientId TEXT, p_productId TEXT, p_isActive BOOLEAN, p_seatLimit INTEGER, p_endsAt TIMESTAMPTZ)
RETURNS SETOF tbl_client_products
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_client_products (client_id, product_id, is_active, seat_limit, ends_at)
    VALUES (p_clientId, p_productId, p_isActive, p_seatLimit, p_endsAt)
    ON CONFLICT (client_id, product_id)
    DO UPDATE SET is_active  = EXCLUDED.is_active,
                  seat_limit = EXCLUDED.seat_limit,
                  ends_at    = EXCLUDED.ends_at
    RETURNING *;
$$;
