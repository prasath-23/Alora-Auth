/****** Object: Stored Procedure [stp_CreateProduct] ******/
-- Adds a product to the global catalogue. A duplicate key raises 23505. Its
-- client secret, redirect URIs and roles are set separately.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateProduct(p_key TEXT, p_name TEXT, p_description TEXT, p_baseUrl TEXT, p_initiateLoginUri TEXT, p_isActive BOOLEAN, p_acceptsApiClients BOOLEAN)
RETURNS SETOF tbl_products
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_products (key, name, description, base_url, initiate_login_uri, is_active,
                             accepts_api_clients)
    VALUES (p_key, p_name, p_description, p_baseUrl, p_initiateLoginUri, p_isActive,
            p_acceptsApiClients)
    RETURNING *;
$$;
