/****** Object: Stored Procedure [stp_CreateUser] ******/
-- Creates a member. The address is stored lower-cased so it is aligned with
-- the case-insensitive unique index; inserting mixed case would let two rows
-- differ only by case and defeat that index. A duplicate live address raises
-- 23505, which the caller maps to 409.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateUser(p_clientId TEXT, p_email TEXT, p_passwordHash TEXT, p_accountType "AccountType")
RETURNS SETOF tbl_users
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_users (client_id, email, password_hash, account_type)
    VALUES (p_clientId, lower(p_email), p_passwordHash, p_accountType)
    RETURNING *;
$$;
