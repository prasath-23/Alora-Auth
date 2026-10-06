"""Generates db/Views/vw_*.sql — one file per view.

Views exist for two reasons in this schema:

 1. They are the PROJECTION mechanism. A read function declares
    `RETURNS SETOF vw_Something`, which is what lets it return a narrow,
    secret-minimised row shape instead of a whole table. Without a view the
    function would have to return SETOF tbl_x and expose every column.

 2. They carry the STANDING predicates (a session is "alive", an invitation is
    "pending", a grant is "effective"), so each function only adds its
    parameters. The definition then lives in exactly one place.

Views are built in alphabetical order, so a view that reads another view must
sort after it. Computed columns carry explicit casts: sqlc derives the Go type
from them, and an uncast EXISTS or aggregate would surface as interface{}.

Run:  python db/gen_views.py
"""
import os

OUT = os.path.join(os.path.dirname(__file__), "Views")

VIEWS = [
    # ---- users -------------------------------------------------------------
    ("vw_UserCredential",
     "The login projection. This is the ONLY view that exposes password_hash, and "
     "it is consumed by exactly one function (the candidate lookup). Restricted to "
     "live, password-capable accounts in ACTIVE tenants, so a deleted, disabled or "
     "OAuth-only user -- or anyone in a suspended organisation -- can never be "
     "authenticated by password.",
     """SELECT u.id,
       u.client_id,
       u.email,
       u.password_hash,
       u.account_type,
       u.created_at
FROM   tbl_users u
JOIN   tbl_clients c ON c.id = u.client_id
                    AND c.is_active = true
WHERE  u.deleted_at    IS NULL
  AND  u.is_active      = true
  AND  u.account_type  IN ('EMAIL', 'HYBRID')
  AND  u.password_hash IS NOT NULL"""),

    ("vw_UserIdentity",
     "The token-minting projection: everything a token payload needs and nothing "
     "more. The liveness predicate -- the user AND their tenant -- is part of the "
     "view, so an account or organisation disabled mid-flow cannot be minted a "
     "token. Deliberately excludes password_hash.",
     """SELECT u.id,
       u.client_id,
       u.email,
       u.permissions_version
FROM   tbl_users u
JOIN   tbl_clients c ON c.id = u.client_id
                    AND c.is_active = true
WHERE  u.deleted_at IS NULL
  AND  u.is_active   = true"""),

    ("vw_UserTenantScoped",
     "A single live member of a tenant, as the admin surface sees them. is_admin is "
     "membership of the tenant's ADMINS system group, evaluated live. Omits "
     "password_hash and deleted_at (the latter is implied by the predicate).",
     """SELECT u.id,
       u.client_id,
       u.email,
       u.account_type,
       u.is_active,
       u.permissions_version,
       u.login_policy_id,
       EXISTS (SELECT 1
               FROM   tbl_user_groups ug
               JOIN   tbl_groups g ON g.id = ug.group_id
                                  AND g.client_id = ug.client_id
               WHERE  ug.user_id    = u.id
                 AND  ug.client_id  = u.client_id
                 AND  g.system_key  = 'ADMINS')::boolean AS is_admin,
       u.created_at,
       u.updated_at,
       EXISTS (SELECT 1 FROM tbl_platform_owners po
               WHERE  po.user_id   = u.id
                 AND  po.client_id = u.client_id)::boolean AS is_owner
FROM   tbl_users u
WHERE  u.deleted_at IS NULL"""),

    ("vw_UserListItem",
     "The admin user-list row. Same shape as vw_UserTenantScoped but kept separate "
     "because the two are consumed by different endpoints and will diverge: a "
     "change to the list must not silently alter the detail lookup.",
     """SELECT u.id,
       u.client_id,
       u.email,
       u.account_type,
       u.is_active,
       u.permissions_version,
       u.login_policy_id,
       EXISTS (SELECT 1
               FROM   tbl_user_groups ug
               JOIN   tbl_groups g ON g.id = ug.group_id
                                  AND g.client_id = ug.client_id
               WHERE  ug.user_id    = u.id
                 AND  ug.client_id  = u.client_id
                 AND  g.system_key  = 'ADMINS')::boolean AS is_admin,
       u.created_at,
       u.updated_at,
       EXISTS (SELECT 1 FROM tbl_platform_owners po
               WHERE  po.user_id   = u.id
                 AND  po.client_id = u.client_id)::boolean AS is_owner
FROM   tbl_users u
WHERE  u.deleted_at IS NULL"""),

    ("vw_UserGroupMembership",
     "A user's group memberships, with the group's name resolved. Joined on the "
     "group's OWN client_id so a membership can never surface a group from another "
     "tenant, and soft-deleted users are excluded so they do not appear as members.",
     """SELECT ug.user_id,
       ug.client_id,
       ug.group_id,
       g.name        AS group_name,
       g.system_key,
       ug.assigned_at
FROM   tbl_user_groups ug
JOIN   tbl_groups g ON g.id = ug.group_id
                   AND g.client_id = ug.client_id
JOIN   tbl_users  u ON u.id = ug.user_id
                   AND u.deleted_at IS NULL"""),

    ("vw_UserLoginPolicy",
     "The login policy that applies to each live user: their own assignment, else "
     "the highest-priority policy among their groups, else the tenant default. "
     "Every sign-in path and every refresh enforces this row, never only the UI.",
     """SELECT u.id                                  AS user_id,
       u.client_id,
       p.id                                  AS policy_id,
       p.name                                AS policy_name,
       p.allow_password,
       p.allow_google,
       p.sso_connection_id,
       (CASE WHEN u.login_policy_id IS NOT NULL THEN 'USER'
             WHEN gp.policy_id      IS NOT NULL THEN 'GROUP'
             ELSE 'DEFAULT' END)::text        AS source
FROM   tbl_users u
LEFT   JOIN LATERAL (
       SELECT lp.id AS policy_id
       FROM   tbl_user_groups    ug
       JOIN   tbl_groups         g  ON g.id  = ug.group_id
                                   AND g.client_id = ug.client_id
       JOIN   tbl_login_policies lp ON lp.id = g.login_policy_id
                                   AND lp.client_id = g.client_id
       WHERE  ug.user_id   = u.id
         AND  ug.client_id = u.client_id
       ORDER  BY lp.priority DESC
       LIMIT  1) gp ON true
JOIN   tbl_login_policies p ON p.client_id = u.client_id
                           AND p.id = COALESCE(u.login_policy_id, gp.policy_id,
                                               (SELECT d.id FROM tbl_login_policies d
                                                WHERE  d.client_id = u.client_id
                                                  AND  d.is_default))
WHERE  u.deleted_at IS NULL"""),

    # ---- access ------------------------------------------------------------
    ("vw_UserProductRole",
     "A user's DIRECT product-role grants inside their validity window, with the "
     "product resolved. Effective access, which also counts group grants, is "
     "vw_EffectiveProductRole.",
     """SELECT pp.user_id,
       pp.client_id,
       pp.product_id,
       p.key        AS product_key,
       p.name       AS product_name,
       pp.role_name,
       pp.valid_until
FROM   tbl_product_permissions pp
JOIN   tbl_products p ON p.id = pp.product_id
WHERE  pp.valid_from <= now()
  AND  (pp.valid_until IS NULL OR pp.valid_until > now())"""),

    ("vw_EffectiveProductRole",
     "EVERY role a user holds in a product: direct grants inside their validity "
     "window, plus the roles of the groups they belong to -- and only where the "
     "user, their tenant and the product are active and the tenant's subscription "
     "is live. This is the single definition of 'may use this product'; the launch "
     "check, the token's roles claim and the app list all read it.",
     """SELECT r.user_id,
       r.client_id,
       r.product_id,
       p.key        AS product_key,
       p.name       AS product_name,
       r.role_name,
       r.source,
       r.group_id
FROM   (SELECT pp.user_id, pp.client_id, pp.product_id, pp.role_name,
               'DIRECT'::text AS source, NULL::text AS group_id
        FROM   tbl_product_permissions pp
        WHERE  pp.valid_from <= now()
          AND  (pp.valid_until IS NULL OR pp.valid_until > now())
        UNION ALL
        SELECT ug.user_id, g.client_id, gpg.product_id, gpg.role_name,
               'GROUP'::text AS source, g.id AS group_id
        FROM   tbl_group_product_grants gpg
        JOIN   tbl_groups      g  ON g.id  = gpg.group_id
                                 AND g.client_id = gpg.client_id
        JOIN   tbl_user_groups ug ON ug.group_id  = g.id
                                 AND ug.client_id = g.client_id) r
JOIN   tbl_users           u  ON u.id = r.user_id
                             AND u.client_id  = r.client_id
                             AND u.deleted_at IS NULL
                             AND u.is_active  = true
JOIN   tbl_clients         c  ON c.id = r.client_id
                             AND c.is_active  = true
JOIN   tbl_products        p  ON p.id = r.product_id
                             AND p.is_active  = true
JOIN   tbl_client_products cp ON cp.client_id  = r.client_id
                             AND cp.product_id = r.product_id
                             AND cp.is_active  = true
                             AND cp.starts_at <= now()
                             AND (cp.ends_at IS NULL OR cp.ends_at > now())"""),

    ("vw_EffectiveScope",
     "Every App Central scope a person holds, one row per (scope, source): from each "
     "group they belong to (the ADMINS group gives every person scope in the "
     "catalogue), and their own extras. A scope held twice appears twice, once per "
     "source; the effective set is the distinct scopes. Groups are joined on their "
     "OWN client_id, so another tenant's group can never give anything here. (The "
     "extras branch comes first so the group columns are typed as nullable.)",
     """SELECT us.user_id,
       us.client_id,
       us.scope,
       'EXTRA'::text AS source,
       NULL::text    AS group_id,
       NULL::text    AS group_name
FROM   tbl_user_scopes us
UNION ALL
SELECT ug.user_id,
       ug.client_id,
       s.scope,
       'GROUP'::text,
       g.id,
       g.name
FROM   tbl_user_groups ug
JOIN   tbl_groups g ON g.id         = ug.group_id
                   AND g.client_id  = ug.client_id
                   AND g.system_key = 'ADMINS'
JOIN   tbl_scopes s ON s.kind = 'PERSON'
UNION ALL
SELECT ug.user_id,
       ug.client_id,
       gs.scope,
       'GROUP'::text,
       g.id,
       g.name
FROM   tbl_user_groups ug
JOIN   tbl_groups g        ON g.id        = ug.group_id
                          AND g.client_id = ug.client_id
JOIN   tbl_group_scopes gs ON gs.group_id  = g.id
                          AND gs.client_id = g.client_id"""),

    ("vw_ScopeReach",
     "Rule 2's measure of a person: every App Central scope they hold "
     "(vw_EffectiveScope), plus the scopes of each group they manage, since a manager "
     "can hand those out. It GRANTS nothing -- the session gate reads "
     "vw_EffectiveScope, never this -- it only decides who may act on whom. One row "
     "per (scope, source); the reach is the distinct scopes. (A system group never "
     "has managers, so the Admins group's implicit scopes need no branch here.)",
     """SELECT es.user_id,
       es.client_id,
       es.scope,
       'HELD'::text AS via,
       es.group_id
FROM   vw_EffectiveScope es
UNION ALL
SELECT gm.user_id,
       gm.client_id,
       gs.scope,
       'MANAGES'::text,
       gm.group_id
FROM   tbl_group_managers gm
JOIN   tbl_group_scopes gs ON gs.group_id  = gm.group_id
                          AND gs.client_id = gm.client_id"""),

    ("vw_UserApp",
     "One row per product a user may open, with every role they hold in it: what "
     "App Central's launcher shows.",
     """SELECT e.user_id,
       e.client_id,
       e.product_id,
       p.key                AS product_key,
       p.name               AS product_name,
       p.description        AS product_description,
       p.base_url,
       p.initiate_login_uri,
       array_agg(DISTINCT e.role_name ORDER BY e.role_name)::text[] AS roles
FROM   vw_EffectiveProductRole e
JOIN   tbl_products p ON p.id = e.product_id
GROUP  BY e.user_id, e.client_id, e.product_id, p.key, p.name, p.description,
          p.base_url, p.initiate_login_uri"""),

    # ---- sessions ----------------------------------------------------------
    ("vw_SessionFamilyGate",
     "Everything a refresh, a launch or an authenticated request must know about "
     "one login, in one row. A family is alive only while it is unrevoked, inside "
     "its absolute cap AND has a live generation; a product family additionally "
     "needs a live parent and effective access to its product. scopes is the "
     "person's effective App Central scope set, read fresh on every request.",
     """SELECT f.id                       AS family_id,
       f.user_id,
       f.client_id,
       f.kind,
       f.product_id,
       f.parent_family_id,
       f.auth_method,
       f.auth_connection_id,
       f.authenticated_at,
       f.absolute_expires_at,
       (f.revoked_at IS NULL
        AND f.absolute_expires_at > now()
        AND EXISTS (SELECT 1 FROM tbl_user_sessions s
                    WHERE  s.family_id  = f.id
                      AND  s.revoked_at IS NULL
                      AND  s.expires_at > now()))::boolean AS family_alive,
       (f.parent_family_id IS NULL
        OR (pf.revoked_at IS NULL
            AND pf.absolute_expires_at > now()
            AND EXISTS (SELECT 1 FROM tbl_user_sessions ps
                        WHERE  ps.family_id  = pf.id
                          AND  ps.revoked_at IS NULL
                          AND  ps.expires_at > now())))::boolean AS parent_alive,
       (u.is_active AND u.deleted_at IS NULL)::boolean AS user_active,
       c.is_active                                     AS client_active,
       u.email,
       u.permissions_version,
       EXISTS (SELECT 1
               FROM   tbl_user_groups ug
               JOIN   tbl_groups g ON g.id = ug.group_id
                                  AND g.client_id = ug.client_id
               WHERE  ug.user_id   = f.user_id
                 AND  ug.client_id = f.client_id
                 AND  g.system_key = 'ADMINS')::boolean AS is_tenant_admin,
       EXISTS (SELECT 1 FROM tbl_platform_owners po
               WHERE  po.user_id   = f.user_id
                 AND  po.client_id = f.client_id)::boolean AS is_platform_owner,
       (f.product_id IS NULL
        OR EXISTS (SELECT 1 FROM vw_EffectiveProductRole e
                   WHERE  e.user_id    = f.user_id
                     AND  e.client_id  = f.client_id
                     AND  e.product_id = f.product_id))::boolean AS has_access,
       u.admin_version,
       ARRAY(SELECT DISTINCT es.scope
             FROM   vw_EffectiveScope es
             WHERE  es.user_id   = f.user_id
               AND  es.client_id = f.client_id
             ORDER  BY es.scope)::text[] AS scopes
FROM   tbl_session_families f
JOIN   tbl_users   u  ON u.id = f.user_id
                     AND u.client_id = f.client_id
JOIN   tbl_clients c  ON c.id = f.client_id
LEFT   JOIN tbl_session_families pf ON pf.id = f.parent_family_id"""),

    ("vw_SessionFamilySummary",
     "The admin session list: one row per live login, with whose it is (by "
     "address) and its latest generation's device details. Deliberately omits "
     "every token hash and the user id -- the columns the response contract bans.",
     """SELECT f.id,
       f.client_id,
       f.kind,
       p.key                        AS product_key,
       f.auth_method,
       f.authenticated_at,
       f.created_at,
       COALESCE(s.device_label, '')::text AS device_label,
       COALESCE(s.ip_address, '')::text   AS ip_address,
       s.last_seen_at::timestamptz  AS last_seen_at,
       u.email
FROM   tbl_session_families f
JOIN   tbl_users u ON u.id = f.user_id
                  AND u.client_id = f.client_id
LEFT   JOIN tbl_products p ON p.id = f.product_id
JOIN   LATERAL (SELECT ls.device_label, ls.ip_address, ls.last_seen_at
                FROM   tbl_user_sessions ls
                WHERE  ls.family_id  = f.id
                  AND  ls.revoked_at IS NULL
                  AND  ls.expires_at > now()
                ORDER  BY ls.generation DESC
                LIMIT  1) s ON true
WHERE  f.revoked_at IS NULL
  AND  f.absolute_expires_at > now()"""),

    ("vw_SessionOwner",
     "Minimal session identity for the logout paths: enough to find the family to "
     "revoke, with no token material beyond the hash already presented.",
     """SELECT s.id,
       s.family_id,
       s.user_id,
       s.client_id,
       s.revoked_at,
       s.refresh_token_hash
FROM   tbl_user_sessions s"""),

    # ---- tenants / products --------------------------------------------------
    ("vw_ClientProductDetail",
     "A tenant's subscriptions with the product resolved. Shaped to match the "
     "response contract exactly: id is the SUBSCRIPTION id, not the product id.",
     """SELECT cp.id,
       cp.client_id,
       cp.product_id,
       cp.is_active,
       cp.seat_limit,
       cp.starts_at,
       cp.ends_at,
       cp.created_at,
       p.key         AS product_key,
       p.name        AS product_name,
       p.description AS product_description,
       p.base_url    AS product_base_url,
       p.is_active   AS product_is_active,
       p.accepts_api_clients AS product_accepts_api_clients
FROM   tbl_client_products cp
JOIN   tbl_products p ON p.id = cp.product_id"""),

    ("vw_CompanyListItem",
     "The Owner's company list, with each tenant's live member count.",
     """SELECT c.id,
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
FROM   tbl_clients c"""),

    ("vw_ProductClient",
     "A product's registration as an OAuth client, WITHOUT its secret hash: only "
     "whether one is set.",
     """SELECT p.id,
       p.key,
       p.name,
       p.description,
       p.base_url,
       p.initiate_login_uri,
       p.is_active,
       p.accepts_api_clients,
       (p.client_secret_hash IS NOT NULL)::boolean AS has_secret,
       p.secret_rotated_at,
       p.created_at,
       p.updated_at
FROM   tbl_products p"""),

    ("vw_OAuthClientCredential",
     "The ONE client-authentication projection for the token endpoint, carrying secret "
     "hashes: a product's secret, or each live secret of an API client (so 0-2 rows "
     "for one client id). Columns that do not apply to a kind are empty strings, "
     "never NULL, so every column has one type. is_active folds in what makes a "
     "client unusable outright: a product switched off, or an API client -- or its "
     "company -- switched off.",
     """SELECT 'PRODUCT'::text      AS kind,
       p.id                 AS oauth_client_id,
       p.key                AS product_key,
       ''::text             AS company_id,
       ''::text             AS secret_id,
       p.client_secret_hash AS secret_hash,
       p.is_active          AS is_active
FROM   tbl_products p
WHERE  p.client_secret_hash IS NOT NULL
UNION  ALL
SELECT 'API_CLIENT'::text,
       a.id,
       ''::text,
       a.client_id,
       x.id,
       x.secret_hash,
       (a.is_active AND c.is_active)::boolean
FROM   tbl_api_clients a
JOIN   tbl_clients            c ON c.id = a.client_id
JOIN   tbl_api_client_secrets x ON x.api_client_id = a.id
                               AND x.client_id     = a.client_id
WHERE  x.revoked_at IS NULL
  AND  (x.expires_at IS NULL OR x.expires_at > now())"""),

    ("vw_ProductClientCredential",
     "The one projection that carries a product's secret hash, consumed only by "
     "client authentication at the token endpoint.",
     """SELECT p.id,
       p.key,
       p.is_active,
       p.client_secret_hash
FROM   tbl_products p
WHERE  p.client_secret_hash IS NOT NULL"""),

    # ---- API clients ---------------------------------------------------------
    ("vw_ApiClientSummary",
     "An API client with its company's name, its scopes (sorted by name, as a token "
     "lists them), the products on its list -- each marked usable while its "
     "subscription is live, the product is active and it accepts API clients -- and "
     "how many live secrets it has. Never a secret hash.",
     """SELECT a.id,
       a.client_id,
       c.name AS company_name,
       a.name,
       a.description,
       a.is_active,
       a.created_by_user_id,
       a.created_by_owner_id,
       a.last_used_at,
       a.created_at,
       a.updated_at,
       COALESCE((SELECT jsonb_agg(s.scope ORDER BY s.scope)
                 FROM   tbl_api_client_scopes s
                 WHERE  s.api_client_id = a.id
                   AND  s.client_id     = a.client_id), '[]'::jsonb) AS scopes,
       COALESCE((SELECT jsonb_agg(jsonb_build_object(
                            'product_id',   p.id,
                            'product_key',  p.key,
                            'product_name', p.name,
                            'usable',       cp.is_active AND cp.starts_at <= now()
                                            AND (cp.ends_at IS NULL OR cp.ends_at > now())
                                            AND p.is_active AND p.accepts_api_clients)
                        ORDER BY p.key)
                 FROM   tbl_api_client_products ap
                 JOIN   tbl_products        p  ON p.id = ap.product_id
                 JOIN   tbl_client_products cp ON cp.client_id  = ap.client_id
                                              AND cp.product_id = ap.product_id
                 WHERE  ap.api_client_id = a.id
                   AND  ap.client_id     = a.client_id), '[]'::jsonb) AS products,
       (SELECT count(*)
        FROM   tbl_api_client_secrets x
        WHERE  x.api_client_id = a.id
          AND  x.client_id     = a.client_id
          AND  x.revoked_at IS NULL
          AND  (x.expires_at IS NULL OR x.expires_at > now()))::int AS live_secrets
FROM   tbl_api_clients a
JOIN   tbl_clients     c ON c.id = a.client_id"""),

    ("vw_ApiClientGrant",
     "What the client-credentials grant checks for one API client and one product on "
     "its list: whether a token may be issued right now -- the client and its company "
     "active, the subscription live, the product active and accepting API clients -- "
     "and the scopes the client holds. A product not on the list has no row.",
     """SELECT a.id      AS api_client_id,
       a.client_id,
       p.id      AS product_id,
       p.key     AS product_key,
       (a.is_active AND c.is_active
        AND cp.is_active AND cp.starts_at <= now() AND (cp.ends_at IS NULL OR cp.ends_at > now())
        AND p.is_active AND p.accepts_api_clients)::boolean AS usable,
       ARRAY(SELECT s.scope
             FROM   tbl_api_client_scopes s
             WHERE  s.api_client_id = a.id
               AND  s.client_id     = a.client_id
             ORDER  BY s.scope)::text[] AS scopes
FROM   tbl_api_client_products ap
JOIN   tbl_api_clients     a  ON a.id = ap.api_client_id
                             AND a.client_id = ap.client_id
JOIN   tbl_clients         c  ON c.id = a.client_id
JOIN   tbl_products        p  ON p.id = ap.product_id
JOIN   tbl_client_products cp ON cp.client_id  = ap.client_id
                             AND cp.product_id = ap.product_id"""),

    ("vw_ApiClientSecret",
     "An API client's secrets WITHOUT their hashes: enough to tell them apart and to "
     "see which are live. A secret is live until it is revoked or expires.",
     """SELECT x.id,
       x.api_client_id,
       x.client_id,
       x.prefix,
       x.expires_at,
       x.revoked_at,
       x.last_used_at,
       x.created_by_user_id,
       x.created_by_owner_id,
       x.created_at,
       (x.revoked_at IS NULL AND (x.expires_at IS NULL OR x.expires_at > now()))::boolean AS is_live
FROM   tbl_api_client_secrets x"""),

    # ---- groups ------------------------------------------------------------
    ("vw_GroupListItem",
     "Group list with its scopes (sorted by name, as a token lists them), product "
     "grants and live member count. The count joins tbl_users so soft-deleted "
     "members are excluded -- otherwise the group list would report a total that "
     "contradicts the user list.",
     """SELECT g.id,
       g.client_id,
       g.name,
       g.description,
       g.system_key,
       g.login_policy_id,
       g.created_at,
       g.updated_at,
       CASE WHEN g.system_key = 'ADMINS'
            THEN (SELECT jsonb_agg(s.scope ORDER BY s.scope)
                  FROM   tbl_scopes s
                  WHERE  s.kind = 'PERSON')
            ELSE COALESCE((SELECT jsonb_agg(gs.scope ORDER BY gs.scope)
                           FROM   tbl_group_scopes gs
                           WHERE  gs.group_id  = g.id
                             AND  gs.client_id = g.client_id), '[]'::jsonb)
       END AS scopes,
       COALESCE((SELECT jsonb_agg(jsonb_build_object('product_id', gpg.product_id,
                                                     'product_key', pr.key,
                                                     'role_name', gpg.role_name)
                                  ORDER BY pr.key)
                 FROM   tbl_group_product_grants gpg
                 JOIN   tbl_products pr ON pr.id = gpg.product_id
                 WHERE  gpg.group_id  = g.id
                   AND  gpg.client_id = g.client_id), '[]'::jsonb) AS product_grants,
       (SELECT count(*)
        FROM   tbl_user_groups ug
        JOIN   tbl_users mu ON mu.id = ug.user_id
                           AND mu.deleted_at IS NULL
        WHERE  ug.group_id  = g.id
          AND  ug.client_id = g.client_id)::bigint        AS member_count
FROM   tbl_groups g"""),

    ("vw_GroupDetailRow",
     "One row per group member, or a single row with NULL member columns for an "
     "empty group (LEFT JOIN). The group's own columns repeat on every row; the "
     "caller takes them from the first. Soft-deleted users are excluded, so their "
     "addresses are never disclosed through the group detail endpoint.",
     """SELECT g.id,
       g.client_id,
       g.name,
       g.description,
       g.system_key,
       g.login_policy_id,
       g.created_at,
       CASE WHEN g.system_key = 'ADMINS'
            THEN (SELECT jsonb_agg(s.scope ORDER BY s.scope)
                  FROM   tbl_scopes s
                  WHERE  s.kind = 'PERSON')
            ELSE COALESCE((SELECT jsonb_agg(gs.scope ORDER BY gs.scope)
                           FROM   tbl_group_scopes gs
                           WHERE  gs.group_id  = g.id
                             AND  gs.client_id = g.client_id), '[]'::jsonb)
       END AS scopes,
       COALESCE((SELECT jsonb_agg(jsonb_build_object('product_id', gpg.product_id,
                                                     'product_key', pr.key,
                                                     'role_name', gpg.role_name)
                                  ORDER BY pr.key)
                 FROM   tbl_group_product_grants gpg
                 JOIN   tbl_products pr ON pr.id = gpg.product_id
                 WHERE  gpg.group_id  = g.id
                   AND  gpg.client_id = g.client_id), '[]'::jsonb) AS product_grants,
       ug.user_id,
       u.email       AS user_email,
       ug.assigned_at
FROM   tbl_groups g
LEFT   JOIN tbl_user_groups ug ON ug.group_id  = g.id
                              AND ug.client_id = g.client_id
LEFT   JOIN tbl_users u        ON u.id         = ug.user_id
                              AND u.client_id  = g.client_id
                              AND u.deleted_at IS NULL"""),

    ("vw_GroupManager",
     "A group's managers, each with their address and who appointed them (a user of "
     "the tenant, or an Owner). Soft-deleted people are left out in the WHERE, so a "
     "deleted manager's id is never disclosed either.",
     """SELECT gm.group_id,
       gm.client_id,
       gm.user_id,
       u.email,
       gm.appointed_at,
       COALESCE(au.email, ao.email, '')               AS appointed_by_email,
       (gm.appointed_by_owner_id IS NOT NULL)::boolean AS appointed_by_owner
FROM   tbl_group_managers gm
JOIN   tbl_users u        ON u.id         = gm.user_id
                         AND u.client_id  = gm.client_id
LEFT   JOIN tbl_users au  ON au.id        = gm.appointed_by_user_id
                         AND au.client_id = gm.client_id
LEFT   JOIN tbl_users ao  ON ao.id        = gm.appointed_by_owner_id
WHERE  u.deleted_at IS NULL"""),

    # ---- invitations -------------------------------------------------------
    ("vw_InvitationListItem",
     "The admin invitation-list row. token_hash is never projected: it is a "
     "credential at rest and useless to any caller.",
     """SELECT i.id,
       i.client_id,
       i.email,
       i.status,
       i.expires_at,
       i.created_at
FROM   tbl_invitations i"""),

    ("vw_PendingInvitation",
     "A redeemable invitation: PENDING, unexpired, and belonging to an ACTIVE "
     "tenant. The tenant check is the kill switch -- a suspended organisation must "
     "not keep onboarding members through invitations issued before suspension.",
     """SELECT i.id,
       i.email,
       i.client_id,
       i.invited_by_user_id,
       i.invited_by_owner_id,
       i.token_hash,
       i.expires_at,
       c.name AS client_name
FROM   tbl_invitations i
JOIN   tbl_clients c ON c.id = i.client_id
                    AND c.is_active = true
WHERE  i.status      = 'PENDING'
  AND  i.expires_at  > now()"""),

    ("vw_InvitationGroup",
     "The groups an invitation adds its user to, with the group's name resolved.",
     """SELECT ig.invitation_id,
       ig.client_id,
       ig.group_id,
       g.name AS group_name
FROM   tbl_invitation_groups ig
JOIN   tbl_groups g ON g.id = ig.group_id
                   AND g.client_id = ig.client_id"""),

    # ---- federation / reset ------------------------------------------------
    ("vw_ValidResetToken",
     "A redeemable password-reset token joined to its owner. Carries the unused and "
     "unexpired predicates so no caller can accidentally honour a spent link, and "
     "surfaces the owner's state so a reset cannot revive a disabled account.",
     """SELECT t.id,
       t.user_id,
       t.client_id,
       t.token_hash,
       u.email,
       u.is_active,
       u.deleted_at
FROM   tbl_password_reset_tokens t
JOIN   tbl_users u ON u.id = t.user_id
WHERE  t.used_at    IS NULL
  AND  t.expires_at  > now()"""),

    ("vw_LinkedIdentityOwner",
     "An external identity with its owning user. The soft-delete predicate is "
     "critical: a federated callback is a PUBLIC route, so without it a "
     "deprovisioned user could sign back in through the provider. is_active also "
     "covers the tenant, so a suspended organisation stays shut.",
     """SELECT li.provider,
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
JOIN   tbl_clients c ON c.id = u.client_id"""),

    ("vw_SsoConnectionSummary",
     "An SSO connection as the Owner console shows it: never the secret, only "
     "whether one is set.",
     """SELECT sc.id,
       sc.client_id,
       sc.name,
       sc.issuer,
       sc.oidc_client_id,
       sc.scopes,
       sc.trust_unverified_email,
       sc.is_active,
       (sc.client_secret_ciphertext IS NOT NULL)::boolean AS has_secret,
       COALESCE((SELECT array_agg(d.domain ORDER BY d.domain)
                 FROM   tbl_sso_connection_domains d
                 WHERE  d.connection_id = sc.id), '{}')::text[] AS domains,
       sc.created_at,
       sc.updated_at
FROM   tbl_sso_connections sc"""),

    ("vw_SsoConnectionRuntime",
     "What the SSO login path needs, including the encrypted secret. is_active also "
     "covers the tenant, so a suspended organisation's connection cannot be used.",
     """SELECT sc.id,
       sc.client_id,
       sc.name,
       sc.issuer,
       sc.oidc_client_id,
       sc.client_secret_ciphertext,
       sc.secret_key_id,
       sc.scopes,
       sc.trust_unverified_email,
       (sc.is_active AND c.is_active)::boolean AS is_active,
       COALESCE((SELECT array_agg(d.domain ORDER BY d.domain)
                 FROM   tbl_sso_connection_domains d
                 WHERE  d.connection_id = sc.id), '{}')::text[] AS domains
FROM   tbl_sso_connections sc
JOIN   tbl_clients c ON c.id = sc.client_id"""),

    ("vw_DomainLoginHint",
     "Login discovery by email DOMAIN, never by account: a domain attested for an "
     "active SSO connection routes to it; a tenant's verified domain offers that "
     "tenant's default methods. Answers depend on the domain alone, so discovery "
     "cannot reveal whether an account exists.",
     """SELECT lower(c.domain)       AS domain,
       c.id                  AS client_id,
       NULL::text            AS connection_id,
       dp.allow_password,
       dp.allow_google
FROM   tbl_clients c
JOIN   tbl_login_policies dp ON dp.client_id = c.id
                            AND dp.is_default
WHERE  c.domain IS NOT NULL
  AND  c.domain_verified_at IS NOT NULL
  AND  c.is_active = true
  AND  NOT EXISTS (SELECT 1 FROM tbl_sso_connection_domains x
                   WHERE  x.domain = lower(c.domain))
UNION  ALL
SELECT d.domain,
       d.client_id,
       d.connection_id,
       dp.allow_password,
       dp.allow_google
FROM   tbl_sso_connection_domains d
JOIN   tbl_sso_connections sc ON sc.id = d.connection_id
                             AND sc.client_id = d.client_id
                             AND sc.is_active = true
JOIN   tbl_clients         c  ON c.id = d.client_id
                             AND c.is_active  = true
JOIN   tbl_login_policies  dp ON dp.client_id = d.client_id
                             AND dp.is_default"""),
]


def wrap(text, width=74, indent="-- "):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(indent + cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(indent + cur)
    return "\n".join(lines)


os.makedirs(OUT, exist_ok=True)
for name, purpose, body in VIEWS:
    content = (
        f"/****** Object: View [{name}] ******/\n"
        f"{wrap(purpose)}\n"
        f"--\n"
        f"-- CREATE OR REPLACE so the build is idempotent.\n\n"
        f"CREATE OR REPLACE VIEW {name} AS\n{body};\n"
    )
    with open(os.path.join(OUT, name + ".sql"), "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
print(f"wrote {len(VIEWS)} view files to {OUT}")
