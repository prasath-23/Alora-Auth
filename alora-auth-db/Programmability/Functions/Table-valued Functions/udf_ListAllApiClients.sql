/****** Object: Table-valued Function [udf_ListAllApiClients] ******/
-- Every tenant's API clients, for the Owner console: by company, then by
-- name.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListAllApiClients()
RETURNS SETOF vw_ApiClientSummary
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ApiClientSummary v ORDER BY lower(v.company_name), lower(v.name);
$$;
