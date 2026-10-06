/****** Object: Table-valued Function [udf_GetSessionFamilyGate] ******/
-- Everything the service must check about one login, in one read.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetSessionFamilyGate(p_familyId TEXT)
RETURNS SETOF vw_SessionFamilyGate
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_SessionFamilyGate v WHERE v.family_id = p_familyId;
$$;
