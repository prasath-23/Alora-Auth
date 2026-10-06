-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: effective product access
--
-- vw_EffectiveProductRole is the single definition of "may use this product":
-- direct grants plus group grants, only for live users, active tenants and
-- products, and live subscriptions.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: ListEffectiveRoles :many
SELECT * FROM udf_ListEffectiveRoles($1, $2, $3);

-- name: ListUserEffectiveAccess :many
SELECT * FROM udf_ListUserEffectiveAccess($1, $2);

-- name: ListUserApps :many
SELECT * FROM udf_ListUserApps($1, $2);
