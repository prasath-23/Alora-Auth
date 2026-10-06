/****** Object: Stored Procedure [stp_SetProductClientSecret] ******/
-- Rotates a product's client secret. Only the hash is stored; the plaintext
-- is shown to the Owner once and never again.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetProductClientSecret(p_productId TEXT, p_secretHash TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH upd AS (
        UPDATE tbl_products
        SET    client_secret_hash = p_secretHash,
               secret_rotated_at  = now(),
               updated_at         = now()
        WHERE  id = p_productId
        RETURNING 1
    )
    SELECT count(*)::int FROM upd;
$$;
