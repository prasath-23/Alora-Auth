/****** Object: View [vw_LinkedIdentityOwner] ******/
-- An external identity with its owning user. The soft-delete predicate is
-- critical: a federated callback is a PUBLIC route, so without it a
-- deprovisioned user could sign back in through the provider. is_active also
-- covers the tenant, so a suspended organisation stays shut.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_LinkedIdentityOwner AS
SELECT li.provider,
       li.connection_id,
       li.provider_id,
       u.id          AS user_id,
       u.client_id,
       u.email,
       u.account_type,
       (u.is_active AND c.is_active)::boolean AS is_active
FROM   tbl_linked_identities li
JOIN   tbl_users   u ON u.id = li.user_id
                    AND u.client_id  = li.client_id
                    AND u.deleted_at IS NULL
JOIN   tbl_clients c ON c.id = u.client_id;
