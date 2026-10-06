/****** Object: Stored Procedure [stp_SetUserScopes] ******/
-- Replaces the EXTRA App Central scopes given to one person -- what they hold on
-- top of their groups -- wholesale. Scopes kept from the previous set keep their
-- original attribution; scopes dropped are removed; new ones are recorded as
-- given by p_grantedByUserId (a user of the same tenant) or p_grantedByOwnerId
-- (an Owner), at most one of which is set.
--
-- The user is looked up by (id, tenant) and must be live: another tenant's user
-- or a deleted one changes nothing (-1). An unknown scope, or an API client's
-- scope, fails the foreign key into tbl_scopes.
--
-- The user's admin_version is bumped in this same transaction.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetUserScopes(
    p_userId           TEXT,
    p_clientId         TEXT,
    p_scopes           TEXT[],
    p_grantedByUserId  TEXT,
    p_grantedByOwnerId TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_held INTEGER := 0;
BEGIN
    PERFORM 1
    FROM   tbl_users u
    WHERE  u.id = p_userId AND u.client_id = p_clientId AND u.deleted_at IS NULL
    FOR    UPDATE;

    IF NOT FOUND THEN
        RETURN -1;  -- -1 = no such live user in this tenant
    END IF;

    DELETE FROM tbl_user_scopes
    WHERE  user_id   = p_userId
      AND  client_id = p_clientId
      AND  (p_scopes IS NULL OR NOT (scope = ANY (p_scopes)));

    IF p_scopes IS NOT NULL AND cardinality(p_scopes) > 0 THEN
        INSERT INTO tbl_user_scopes (user_id, client_id, scope, granted_by_user_id, granted_by_owner_id)
        SELECT DISTINCT p_userId, p_clientId, s, p_grantedByUserId, p_grantedByOwnerId
        FROM   unnest(p_scopes) AS s
        ON CONFLICT (user_id, scope) DO NOTHING;
    END IF;

    SELECT count(*)::int INTO v_held
    FROM   tbl_user_scopes
    WHERE  user_id = p_userId AND client_id = p_clientId;

    UPDATE tbl_users
    SET    admin_version = admin_version + 1
    WHERE  id = p_userId AND client_id = p_clientId;

    RETURN v_held;  -- >= 0 = number of extra scopes now held
END;
$$;
