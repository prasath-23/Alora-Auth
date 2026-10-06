/****** Object: Stored Procedure [stp_SetApiClientProducts] ******/
-- Replaces the products an API client may get a token for, wholesale. A product
-- ADDED to the list must be a live subscription of the tenant (switched on,
-- started, not ended) to an active product that accepts API clients; if one is
-- not, nothing changes (-2). A
-- product already on the list may stay whatever has changed since: it is inert
-- until it is usable again, since every token is checked against the same
-- conditions. Another tenant's API client changes nothing (-1).
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetApiClientProducts(
    p_apiClientId TEXT,
    p_clientId    TEXT,
    p_productIds  TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_wanted TEXT[] := coalesce(p_productIds, '{}'::text[]);
    v_bad    INTEGER;
    v_held   INTEGER;
BEGIN
    PERFORM 1
    FROM   tbl_api_clients a
    WHERE  a.id = p_apiClientId AND a.client_id = p_clientId
    FOR    UPDATE;

    IF NOT FOUND THEN
        RETURN -1;  -- -1 = no such API client in this tenant
    END IF;

    SELECT count(*) INTO v_bad
    FROM   (SELECT DISTINCT w FROM unnest(v_wanted) AS w) wanted
    WHERE  NOT EXISTS (SELECT 1 FROM tbl_api_client_products ap
                       WHERE  ap.api_client_id = p_apiClientId
                         AND  ap.client_id     = p_clientId
                         AND  ap.product_id    = wanted.w)
      AND  NOT EXISTS (SELECT 1
                       FROM   tbl_client_products cp
                       JOIN   tbl_products p ON p.id = cp.product_id
                       WHERE  cp.client_id  = p_clientId
                         AND  cp.product_id = wanted.w
                         AND  cp.is_active
                         AND  cp.starts_at <= now()
                         AND  (cp.ends_at IS NULL OR cp.ends_at > now())
                         AND  p.is_active
                         AND  p.accepts_api_clients);

    IF v_bad > 0 THEN
        RETURN -2;  -- -2 = a product that cannot be added to an API client's list
    END IF;

    DELETE FROM tbl_api_client_products
    WHERE  api_client_id = p_apiClientId
      AND  client_id     = p_clientId
      AND  NOT (product_id = ANY (v_wanted));

    INSERT INTO tbl_api_client_products (api_client_id, client_id, product_id)
    SELECT DISTINCT p_apiClientId, p_clientId, w
    FROM   unnest(v_wanted) AS w
    ON CONFLICT (api_client_id, product_id) DO NOTHING;

    SELECT count(*)::int INTO v_held
    FROM   tbl_api_client_products
    WHERE  api_client_id = p_apiClientId AND client_id = p_clientId;

    UPDATE tbl_api_clients
    SET    updated_at = now()
    WHERE  id = p_apiClientId AND client_id = p_clientId;

    RETURN v_held;  -- >= 0 = number of products on the list
END;
$$;
