/****** Object: Table-valued Function [udf_ListCompanies] ******/
-- Every tenant, for the Owner console: the platform company first.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListCompanies()
RETURNS SETOF vw_CompanyListItem
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_CompanyListItem v ORDER BY v.is_platform DESC, v.name;
$$;
