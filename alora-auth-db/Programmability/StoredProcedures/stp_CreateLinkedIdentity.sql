/****** Object: Stored Procedure [stp_CreateLinkedIdentity] ******/
-- Binds an external identity to a local account on its first federated
-- sign-in. The partial unique indexes allow one Google account per tenant
-- and one subject per SSO connection.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateLinkedIdentity(p_userId TEXT, p_clientId TEXT, p_provider "IdpProvider", p_connectionId TEXT, p_providerId TEXT, p_emailVerified BOOLEAN, p_emailAtLink TEXT)
RETURNS SETOF tbl_linked_identities
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_linked_identities (user_id, client_id, provider, connection_id,
                                       provider_id, email_verified, email_at_link)
    VALUES (p_userId, p_clientId, p_provider, p_connectionId,
            p_providerId, p_emailVerified, lower(p_emailAtLink))
    RETURNING *;
$$;
