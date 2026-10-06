/****** Object: Stored Procedure [stp_CreateApiClient] ******/
-- Creates an API client in a tenant, by a user of that tenant or by an
-- Owner. It starts with no scopes, no products and no secret, so it can do
-- nothing until each is chosen. A name already used in the tenant raises
-- 23505.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateApiClient(p_clientId TEXT, p_name TEXT, p_description TEXT, p_createdByUserId TEXT, p_createdByOwnerId TEXT)
RETURNS SETOF tbl_api_clients
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_api_clients (client_id, name, description, created_by_user_id, created_by_owner_id)
    VALUES (p_clientId, p_name, p_description, p_createdByUserId, p_createdByOwnerId)
    RETURNING *;
$$;
