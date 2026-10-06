/****** Object: Stored Procedure [stp_UpdateApiClient] ******/
-- Renames, re-describes, or switches an API client on or off, tenant-scoped:
-- another tenant's id yields no rows. A switched-off client gets no token,
-- whatever its secrets.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_UpdateApiClient(p_apiClientId TEXT, p_clientId TEXT, p_name TEXT, p_description TEXT, p_isActive BOOLEAN)
RETURNS SETOF tbl_api_clients
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_api_clients
    SET    name        = p_name,
           description = p_description,
           is_active   = p_isActive,
           updated_at  = now()
    WHERE  id        = p_apiClientId
      AND  client_id = p_clientId
    RETURNING *;
$$;
