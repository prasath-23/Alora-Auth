/****** Object: View [vw_UserFreshness] ******/
-- The per-request staleness probe. Deliberately UNFILTERED: the caller must
-- be able to tell 'inactive' and 'soft-deleted' apart from 'no such user',
-- so the predicates stay in the application rather than the view.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserFreshness AS
SELECT u.id,
       u.permissions_version,
       u.is_active,
       u.deleted_at
FROM   tbl_users u;
