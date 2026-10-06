/****** Object: Stored Procedure [stp_SetApiClientScopes] ******/
-- Replaces where an API client's credential may be used -- its CLIENT scopes --
-- wholesale, so the caller submits the complete desired state.
--
-- The API client is looked up by (id, tenant) and locked: another tenant's
-- changes nothing (-1). An unknown scope, or a person's scope, fails the
-- foreign key into tbl_scopes.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetApiClientScopes(
    p_apiClientId TEXT,
    p_clientId    TEXT,
    p_scopes      TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_inserted INTEGER := 0;
BEGIN
    PERFORM 1
    FROM   tbl_api_clients a
    WHERE  a.id = p_apiClientId AND a.client_id = p_clientId
    FOR    UPDATE;

    IF NOT FOUND THEN
        RETURN -1;  -- -1 = no such API client in this tenant
    END IF;

    DELETE FROM tbl_api_client_scopes
    WHERE  api_client_id = p_apiClientId AND client_id = p_clientId;

    IF p_scopes IS NOT NULL AND cardinality(p_scopes) > 0 THEN
        INSERT INTO tbl_api_client_scopes (api_client_id, client_id, scope)
        SELECT DISTINCT p_apiClientId, p_clientId, s
        FROM   unnest(p_scopes) AS s;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
    END IF;

    UPDATE tbl_api_clients
    SET    updated_at = now()
    WHERE  id = p_apiClientId AND client_id = p_clientId;

    RETURN v_inserted;  -- >= 0 = number of scopes the client now holds
END;
$$;
