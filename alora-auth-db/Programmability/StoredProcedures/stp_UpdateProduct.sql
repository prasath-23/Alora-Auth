/****** Object: Stored Procedure [stp_UpdateProduct] ******/
-- Updates a catalogue entry. The key is immutable: it is embedded in
-- already-issued token audiences, so changing it would invalidate live
-- tokens. A NULL p_acceptsApiClients keeps whether the product accepts API
-- clients.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_UpdateProduct(p_productId TEXT, p_name TEXT, p_description TEXT, p_baseUrl TEXT, p_initiateLoginUri TEXT, p_isActive BOOLEAN, p_acceptsApiClients BOOLEAN)
RETURNS SETOF tbl_products
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_products
    SET    name                = p_name,
           description         = p_description,
           base_url            = p_baseUrl,
           initiate_login_uri  = p_initiateLoginUri,
           is_active           = p_isActive,
           accepts_api_clients = COALESCE(p_acceptsApiClients, accepts_api_clients),
           updated_at          = now()
    WHERE  id = p_productId
    RETURNING *;
$$;
