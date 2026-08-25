/****** Object: View [vw_LinkedIdentityOwner] ******/
-- An external identity with its owning user. The soft-delete predicate is
-- critical: the OAuth callback is a PUBLIC route that the freshness
-- middleware never guards, so without it a deprovisioned user could sign
-- back in through the provider and receive a fresh refresh token.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_LinkedIdentityOwner AS
SELECT li.provider,
       li.provider_id,
       u.id        AS user_id,
       u.client_id,
       u.is_active
FROM   tbl_linked_identities li
JOIN   tbl_users u ON u.id = li.user_id
                  AND u.deleted_at IS NULL;
