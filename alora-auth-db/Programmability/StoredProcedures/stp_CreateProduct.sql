/****** Object: Stored Procedure [stp_CreateProduct] ******/
-- Adds a product to the global catalogue. A duplicate key raises 23505.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateProduct(p_key TEXT, p_name TEXT, p_description TEXT, p_baseUrl TEXT, p_isActive BOOLEAN)
RETURNS SETOF tbl_products
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_products (key, name, description, base_url, is_active)
    VALUES (p_key, p_name, p_description, p_baseUrl, p_isActive)
    RETURNING *;
$$;
