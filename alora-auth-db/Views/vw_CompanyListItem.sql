/****** Object: View [vw_CompanyListItem] ******/
-- The Owner's company list, with each tenant's live member count.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_CompanyListItem AS
SELECT c.id,
       c.name,
       c.domain,
       c.domain_verified_at,
       c.subscription_status,
       c.max_seats,
       c.is_active,
       c.is_platform,
       c.created_at,
       c.updated_at,
       (SELECT count(*) FROM tbl_users u
        WHERE  u.client_id = c.id
          AND  u.deleted_at IS NULL)::bigint AS user_count
FROM   tbl_clients c;
