/****** Object: Stored Procedure [stp_CreateUser] ******/
-- Creates a member. The address is stored lower-cased so it is aligned with the
-- case-insensitive unique index; inserting mixed case would let two rows differ
-- only by case and defeat that index. A duplicate live address raises 23505,
-- which the caller maps to 409.
--
-- SEAT LIMIT: a company's max_seats caps its ACTIVE members (is_active AND not
-- deleted). The company row is locked FOR UPDATE first, so two concurrent
-- invitation accepts serialise here and cannot both slip under the cap; over the
-- limit raises SQLSTATE AL001, which the API maps to 409. A NULL max_seats is
-- unlimited. plpgsql (not plain SQL) because the guard needs the lock and a
-- conditional RAISE.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateUser(p_clientId TEXT, p_email TEXT, p_passwordHash TEXT, p_accountType "AccountType")
RETURNS SETOF tbl_users
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_max   INTEGER;
    v_count INTEGER;
BEGIN
    SELECT max_seats INTO v_max FROM tbl_clients WHERE id = p_clientId FOR UPDATE;

    IF v_max IS NOT NULL THEN
        SELECT count(*) INTO v_count
        FROM   tbl_users
        WHERE  client_id  = p_clientId
          AND  deleted_at IS NULL
          AND  is_active;
        IF v_count >= v_max THEN
            RAISE EXCEPTION 'company % is at its seat limit of %', p_clientId, v_max
                USING ERRCODE = 'AL001';
        END IF;
    END IF;

    RETURN QUERY
    INSERT INTO tbl_users (client_id, email, password_hash, account_type)
    VALUES (p_clientId, lower(p_email), p_passwordHash, p_accountType)
    RETURNING *;
END;
$$;
