/****** Object: Stored Procedure [stp_TouchApiClientSecret] ******/
-- Stamps when a secret, and its API client, last earned a token -- at most
-- once a minute each, so a busy client does not turn every token into a
-- write.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_TouchApiClientSecret(p_secretId TEXT, p_apiClientId TEXT)
LANGUAGE sql
AS $$
    UPDATE tbl_api_client_secrets
    SET    last_used_at = now()
    WHERE  id            = p_secretId
      AND  api_client_id = p_apiClientId
      AND  (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');
    UPDATE tbl_api_clients
    SET    last_used_at = now()
    WHERE  id = p_apiClientId
      AND  (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');
$$;
