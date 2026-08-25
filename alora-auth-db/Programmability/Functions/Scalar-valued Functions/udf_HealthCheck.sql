/****** Object: Scalar-valued Function [udf_HealthCheck] ******/
-- Readiness probe. Round-trips a constant so the caller only has to check
-- for an error; it touches no table, so a slow query cannot make the service
-- look unhealthy.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_HealthCheck()
RETURNS INTEGER
LANGUAGE sql
STABLE
AS $$
    SELECT 1;
$$;
