/****** Object: Stored Procedure [stp_CreateLinkedIdentity] ******/
-- Binds an external identity to a local account on first federated sign-in.
-- The unique constraint on (provider, provider_id) means one provider
-- account can never be linked to two local users.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateLinkedIdentity(p_userId TEXT, p_provider "IdpProvider", p_providerId TEXT, p_emailVerified BOOLEAN)
RETURNS SETOF tbl_linked_identities
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_linked_identities (user_id, provider, provider_id, email_verified)
    VALUES (p_userId, p_provider, p_providerId, p_emailVerified)
    RETURNING *;
$$;
