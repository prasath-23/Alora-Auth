"""Generates db/Views/vw_*.sql — one file per view.

Views exist for two reasons in this schema:

 1. They are the PROJECTION mechanism. A read function declares
    `RETURNS SETOF vw_Something`, which is what lets it return a narrow,
    secret-minimised row shape instead of a whole table. Without a view the
    function would have to return SETOF tbl_x and expose every column.

 2. They carry the STANDING predicates (a session is "active", an invitation is
    "pending"), so each function only adds its parameters. The definition of
    "active" then lives in exactly one place.

Run:  python db/gen_views.py
"""
import os

OUT = os.path.join(os.path.dirname(__file__), "Views")

VIEWS = [
    ("vw_UserCredential",
     "The login projection. This is the ONLY view that exposes password_hash, and "
     "it is consumed by exactly one function (the credential check). Restricted to "
     "live, password-capable accounts, so a deleted, disabled or OAuth-only user "
     "can never be authenticated by password.",
     """SELECT u.id,
       u.client_id,
       u.email,
       u.password_hash,
       u.account_type,
       u.is_global_admin,
       u.permissions_version
FROM   tbl_users u
WHERE  u.deleted_at   IS NULL
  AND  u.is_active     = true
  AND  u.account_type IN ('EMAIL', 'HYBRID')"""),

    ("vw_UserIdentity",
     "The token-minting projection: everything a JWT payload needs and nothing "
     "more. The liveness predicate is part of the view, so an account deactivated "
     "between issuing an authorization code and redeeming it cannot be minted a "
     "token. Deliberately excludes password_hash.",
     """SELECT u.id,
       u.client_id,
       u.email,
       u.is_global_admin,
       u.permissions_version
FROM   tbl_users u
WHERE  u.deleted_at IS NULL
  AND  u.is_active   = true"""),

    ("vw_UserFreshness",
     "The per-request staleness probe. Deliberately UNFILTERED: the caller must be "
     "able to tell 'inactive' and 'soft-deleted' apart from 'no such user', so the "
     "predicates stay in the application rather than the view.",
     """SELECT u.id,
       u.permissions_version,
       u.is_active,
       u.deleted_at
FROM   tbl_users u"""),

    ("vw_UserTenantScoped",
     "A single live member of a tenant, as the admin surface sees them. Omits "
     "password_hash and deleted_at (the latter is implied by the predicate).",
     """SELECT u.id,
       u.client_id,
       u.email,
       u.account_type,
       u.is_active,
       u.is_global_admin,
       u.permissions_version,
       u.created_at,
       u.updated_at
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
       u.is_global_admin,
       u.permissions_version,
       u.created_at,
       u.updated_at
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
       ug.assigned_at
FROM   tbl_user_groups ug
JOIN   tbl_groups g ON g.id = ug.group_id
                   AND g.client_id = ug.client_id
JOIN   tbl_users  u ON u.id = ug.user_id
                   AND u.deleted_at IS NULL"""),

    ("vw_UserProductRole",
     "Active product-role grants. The validity window is part of the view, so an "
     "expired grant cannot leak into a JWT roles claim from any caller. Inner join "
     "to products is loss-free because the product FK is RESTRICT.",
     """SELECT pp.user_id,
       pp.client_id,
       pp.product_id,
       p.key        AS product_key,
       p.name       AS product_name,
       pp.role_name,
       pp.valid_until
FROM   tbl_product_permissions pp
JOIN   tbl_products p ON p.id = pp.product_id
WHERE  pp.valid_until IS NULL
   OR  pp.valid_until  > now()"""),

    ("vw_SessionSummary",
     "The admin session-list row. Carries the 'active' predicate, and deliberately "
     "omits refresh_token_hash, prev_token_hash, revoked_reason and user_id — the "
     "columns the response contract bans. A leak here would hand an admin (or an "
     "XSS payload reading the page) material capable of impersonation.",
     """SELECT s.id,
       s.client_id,
       s.device_label,
       s.ip_address,
       s.last_seen_at,
       s.created_at
FROM   tbl_user_sessions s
WHERE  s.revoked_at IS NULL
  AND  s.expires_at  > now()"""),

    ("vw_SessionOwner",
     "Minimal session identity for the logout and admin-revoke paths: enough to "
     "decide whether to act, with no token material.",
     """SELECT s.id,
       s.user_id,
       s.client_id,
       s.revoked_at,
       s.refresh_token_hash
FROM   tbl_user_sessions s"""),

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
       p.is_active   AS product_is_active
FROM   tbl_client_products cp
JOIN   tbl_products p ON p.id = cp.product_id"""),

    ("vw_GroupListItem",
     "Group list with its feature keys aggregated and its live member count. The "
     "count joins tbl_users so soft-deleted members are excluded — otherwise the "
     "group list would report a total that contradicts the user list.",
     """SELECT g.id,
       g.client_id,
       g.name,
       g.description,
       g.created_at,
       g.updated_at,
       COALESCE((SELECT jsonb_agg(gf.feature_key ORDER BY gf.feature_key)
                 FROM   tbl_group_features gf
                 WHERE  gf.group_id = g.id), '[]'::jsonb) AS features,
       (SELECT count(*)
        FROM   tbl_user_groups ug
        JOIN   tbl_users mu ON mu.id = ug.user_id
                           AND mu.deleted_at IS NULL
        WHERE  ug.group_id  = g.id
          AND  ug.client_id = g.client_id)::bigint        AS member_count
FROM   tbl_groups g"""),

    ("vw_GroupDetailRow",
     "One row per group member, or a single row with NULL member columns for an "
     "empty group (LEFT JOIN). The feature list repeats on every row; the caller "
     "takes it from the first. Soft-deleted users are excluded, so their addresses "
     "are never disclosed through the group detail endpoint.",
     """SELECT g.id,
       g.client_id,
       g.name,
       g.description,
       g.created_at,
       COALESCE((SELECT jsonb_agg(gf.feature_key ORDER BY gf.feature_key)
                 FROM   tbl_group_features gf
                 WHERE  gf.group_id = g.id), '[]'::jsonb) AS features,
       ug.user_id,
       u.email       AS user_email,
       ug.assigned_at
FROM   tbl_groups g
LEFT   JOIN tbl_user_groups ug ON ug.group_id  = g.id
                              AND ug.client_id = g.client_id
LEFT   JOIN tbl_users u        ON u.id         = ug.user_id
                              AND u.client_id  = g.client_id
                              AND u.deleted_at IS NULL"""),

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
     "tenant. The tenant check is the kill switch — a suspended organisation must "
     "not keep onboarding members through invitations issued before suspension.",
     """SELECT i.id,
       i.email,
       i.client_id,
       i.invited_by_user_id,
       i.token_hash,
       i.expires_at,
       c.allowed_idp_providers,
       c.name AS client_name
FROM   tbl_invitations i
JOIN   tbl_clients c ON c.id = i.client_id
                    AND c.is_active = true
WHERE  i.status      = 'PENDING'
  AND  i.expires_at  > now()"""),

    ("vw_InvitationProductRole",
     "The products and roles an invitation confers, with the product resolved.",
     """SELECT ip.invitation_id,
       ip.product_id,
       p.key  AS product_key,
       p.name AS product_name,
       ip.role_name
FROM   tbl_invitation_products ip
JOIN   tbl_products p ON p.id = ip.product_id"""),

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
     "critical: the OAuth callback is a PUBLIC route that the freshness middleware "
     "never guards, so without it a deprovisioned user could sign back in through "
     "the provider and receive a fresh refresh token.",
     """SELECT li.provider,
       li.provider_id,
       u.id        AS user_id,
       u.client_id,
       u.is_active
FROM   tbl_linked_identities li
JOIN   tbl_users u ON u.id = li.user_id
                  AND u.deleted_at IS NULL"""),

    ("vw_ClientOAuthGate",
     "The per-tenant identity-provider policy, used to decide whether a federated "
     "login may proceed at all.",
     """SELECT c.id,
       c.allowed_idp_providers,
       c.is_active
FROM   tbl_clients c"""),
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
