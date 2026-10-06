/****** Object: Scalar-valued Function [udf_IsApiClientSecretLive] ******/
-- TRUE while the secret an application token was issued under is live: not
-- revoked, not expired. Introspection checks it, so revoking a secret ends
-- the tokens issued under it at once.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_IsApiClientSecretLive(p_secretId TEXT, p_apiClientId TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM tbl_api_client_secrets x
        WHERE  x.id            = p_secretId
          AND  x.api_client_id = p_apiClientId
          AND  x.revoked_at   IS NULL
          AND  (x.expires_at IS NULL OR x.expires_at > now())
    );
$$;
