/****** Object: Stored Procedure [stp_CreateProductFamily] ******/
-- Opens a PRODUCT login under a live central login of the SAME user and tenant,
-- inheriting how the user authenticated and the parent's absolute cap: a product
-- can never stay signed in longer than the App Central login it came from.
--
-- Returns ZERO rows when the parent is not a live central login, which the
-- caller treats as "sign in again". The parent row is share-locked while the
-- child is attached, so a concurrent logout cannot slip between the check and
-- the insert.
--
-- Implemented as a FUNCTION: the caller needs the session row.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateProductFamily(
    p_parentFamilyId   TEXT,
    p_userId           TEXT,
    p_clientId         TEXT,
    p_productId        TEXT,
    p_sessionUuid      TEXT,
    p_refreshTokenHash TEXT,
    p_expiresAt        TIMESTAMPTZ,
    p_ipAddress        TEXT,
    p_deviceLabel      TEXT,
    p_userAgent        TEXT
)
RETURNS SETOF tbl_user_sessions
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_parent   tbl_session_families;
    v_familyId TEXT;
BEGIN
    SELECT * INTO v_parent
    FROM   tbl_session_families f
    WHERE  f.id          = p_parentFamilyId
      AND  f.user_id     = p_userId
      AND  f.client_id   = p_clientId
      AND  f.kind        = 'CENTRAL'
      AND  f.revoked_at IS NULL
      AND  f.absolute_expires_at > now()
    FOR    SHARE;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    INSERT INTO tbl_session_families (user_id, client_id, kind, product_id, parent_family_id,
                                      auth_method, auth_connection_id, authenticated_at,
                                      absolute_expires_at)
    VALUES (p_userId, p_clientId, 'PRODUCT', p_productId, p_parentFamilyId,
            v_parent.auth_method, v_parent.auth_connection_id, v_parent.authenticated_at,
            v_parent.absolute_expires_at)
    RETURNING id INTO v_familyId;

    RETURN QUERY
    INSERT INTO tbl_user_sessions (user_id, client_id, session_uuid, family_id,
                                   refresh_token_hash, expires_at,
                                   ip_address, device_label, user_agent)
    VALUES (p_userId, p_clientId, p_sessionUuid, v_familyId,
            p_refreshTokenHash, LEAST(p_expiresAt, v_parent.absolute_expires_at),
            p_ipAddress, p_deviceLabel, p_userAgent)
    RETURNING *;
END;
$$;
