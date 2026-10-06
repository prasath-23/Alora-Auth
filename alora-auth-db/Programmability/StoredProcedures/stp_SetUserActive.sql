/****** Object: Stored Procedure [stp_SetUserActive] ******/
-- Enables or disables a member, tenant-scoped. Returns the affected-row count so
-- the caller can answer 404 for an unknown or another tenant's user rather than
-- silently reporting success.
--
-- SEAT LIMIT: reactivating a member consumes a seat, so enabling one is capped by
-- the company's max_seats exactly as creation is. The OTHER active members are
-- counted (id <> p_userId) under the company row lock, so re-enabling an already
-- active member is never refused and concurrent re-activations cannot overshoot.
-- Over the limit raises SQLSTATE AL001 (409); a NULL max_seats is unlimited.
-- plpgsql because of the guard.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetUserActive(p_userId TEXT, p_clientId TEXT, p_isActive BOOLEAN)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_max   INTEGER;
    v_count INTEGER;
    v_n     INTEGER;
BEGIN
    IF p_isActive THEN
        SELECT max_seats INTO v_max FROM tbl_clients WHERE id = p_clientId FOR UPDATE;
        IF v_max IS NOT NULL THEN
            SELECT count(*) INTO v_count
            FROM   tbl_users
            WHERE  client_id  = p_clientId
              AND  deleted_at IS NULL
              AND  is_active
              AND  id <> p_userId;
            IF v_count >= v_max THEN
                RAISE EXCEPTION 'company % is at its seat limit of %', p_clientId, v_max
                    USING ERRCODE = 'AL001';
            END IF;
        END IF;
    END IF;

    WITH upd AS (
        UPDATE tbl_users
        SET    is_active  = p_isActive,
               updated_at = now()
        WHERE  id        = p_userId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int INTO v_n FROM upd;
    RETURN v_n;
END;
$$;
