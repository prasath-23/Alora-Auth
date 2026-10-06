/****** Object: Table-valued Function [udf_ListUserIdentitiesByEmail] ******/
-- Every live account that holds this address, across tenants, whether or not
-- it has a password: the accounts a first federated sign-in with a verified
-- address may link to. Capped and deterministically ordered like the
-- password lookup.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListUserIdentitiesByEmail(p_email TEXT)
RETURNS SETOF vw_UserIdentity
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserIdentity v
    WHERE  lower(v.email) = lower(p_email)
    ORDER  BY v.client_id, v.id
    LIMIT  10;
$$;
