/****** Object: Table-valued Function [udf_GetOAuthClientCredentials] ******/
-- The credentials to check a client id's secret against at the token
-- endpoint: a product's one secret, or an API client's live secrets (at most
-- two).
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetOAuthClientCredentials(p_oauthClientId TEXT)
RETURNS SETOF vw_OAuthClientCredential
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_OAuthClientCredential v WHERE v.oauth_client_id = p_oauthClientId;
$$;
