"""Generates db/Programmability/Functions/** — one file per read function.

CONVENTION
  udf_*  = a READ. Declared STABLE so the planner may cache it within a
           statement, except where a row lock is taken (FOR UPDATE requires
           VOLATILE).

  Table-valued functions return `SETOF vw_*` or `SETOF tbl_*`. Returning SETOF a
  VIEW is what gives a narrow, secret-minimised row shape while still being a
  concrete type the caller can bind to.

  Parameters are camelCase with a p_ prefix, so a parameter can never be
  confused with a column of the same name inside the body.

Run:  python db/gen_functions.py
"""
import os

HERE = os.path.dirname(__file__)
SCALAR = os.path.join(HERE, "Programmability", "Functions", "Scalar-valued Functions")
TVF = os.path.join(HERE, "Programmability", "Functions", "Table-valued Functions")

# (name, params, returns, volatility, purpose, body)
SCALARS = [
    ("udf_ActiveEmailExists", "p_clientId TEXT, p_email TEXT", "BOOLEAN", "STABLE",
     "TRUE when a live user already holds this address in the tenant. Used as a "
     "pre-insert check so the caller can return a clean 409 instead of surfacing a "
     "unique-violation as a 500. Case-insensitive, matching the unique index.",
     """SELECT EXISTS (
        SELECT 1 FROM tbl_users u
        WHERE  u.client_id    = p_clientId
          AND  lower(u.email) = lower(p_email)
          AND  u.deleted_at  IS NULL
    )"""),

    ("udf_ClientIdByVerifiedDomain", "p_domain TEXT", "TEXT", "STABLE",
     "Resolves a hostname to its tenant, but ONLY for a verified domain on an "
     "active tenant. This backs the CORS decision and the federated-login tenant "
     "lookup, so requiring verification is what stops someone claiming an "
     "unowned domain and being admitted to another organisation.",
     """SELECT c.id
    FROM   tbl_clients c
    WHERE  lower(c.domain)      = lower(p_domain)
      AND  c.domain_verified_at IS NOT NULL
      AND  c.is_active           = true
    LIMIT  1"""),

    ("udf_ProductKeyById", "p_productId TEXT", "TEXT", "STABLE",
     "The product's audience key, used to scope a minted token to one product.",
     """SELECT p.key FROM tbl_products p WHERE p.id = p_productId"""),

    ("udf_ClientNameById", "p_clientId TEXT", "TEXT", "STABLE",
     "The tenant's display name, for invitation emails.",
     """SELECT c.name FROM tbl_clients c WHERE c.id = p_clientId"""),

    ("udf_ActiveSubscriptionId", "p_clientId TEXT, p_productId TEXT", "TEXT", "STABLE",
     "The tenant's live subscription to a product, or NULL. Both the login path and "
     "the permission-grant path gate on this, so a tenant cannot be signed into (or "
     "granted a role in) a product it does not pay for.",
     """SELECT cp.id
    FROM   tbl_client_products cp
    WHERE  cp.client_id  = p_clientId
      AND  cp.product_id = p_productId
      AND  cp.is_active   = true
      AND  (cp.ends_at   IS NULL OR cp.ends_at > now())
    LIMIT  1"""),

    ("udf_UserIdByEmail", "p_clientId TEXT, p_email TEXT", "TEXT", "STABLE",
     "Resolves an address to a live user id WITHIN a tenant. Backs adding a group "
     "member by email, which exists because managing groups does not imply "
     "permission to list users.",
     """SELECT u.id
    FROM   tbl_users u
    WHERE  u.client_id    = p_clientId
      AND  lower(u.email) = lower(p_email)
      AND  u.deleted_at  IS NULL"""),

    ("udf_HasGroupFeature", "p_featureKey TEXT, p_clientId TEXT, p_userId TEXT", "BOOLEAN", "STABLE",
     "TRUE when the user belongs to a group IN THIS TENANT that grants the feature. "
     "The group's OWN client_id is checked, not just the membership row: matching "
     "only the membership would let a group belonging to another organisation "
     "confer permission here.",
     """SELECT EXISTS (
        SELECT 1
        FROM   tbl_group_features gf
        JOIN   tbl_groups        g  ON g.id  = gf.group_id
        JOIN   tbl_user_groups   ug ON ug.group_id = g.id
        WHERE  gf.feature_key = p_featureKey
          AND  g.client_id    = p_clientId
          AND  ug.user_id     = p_userId
    )"""),

    ("udf_UserCursorPosition", "p_userId TEXT, p_clientId TEXT", "TIMESTAMPTZ", "STABLE",
     "Translates an opaque page cursor (a user id) into its keyset position. "
     "Tenant-scoped, so a cursor forged from another tenant's id resolves to NULL "
     "rather than revealing a position in their list.",
     """SELECT u.created_at
    FROM   tbl_users u
    WHERE  u.id        = p_userId
      AND  u.client_id = p_clientId
      AND  u.deleted_at IS NULL"""),

    ("udf_HealthCheck", "", "INTEGER", "STABLE",
     "Readiness probe. Round-trips a constant so the caller only has to check for "
     "an error; it touches no table, so a slow query cannot make the service look "
     "unhealthy.",
     """SELECT 1"""),
]

# (name, params, returns, volatility, purpose, body)
TVFS = [
    # ---- users -------------------------------------------------------------
    ("udf_GetUserById", "p_userId TEXT", "SETOF tbl_users", "STABLE",
     "Full row by primary key. NOT tenant-scoped and NOT soft-delete filtered "
     "because the id comes from a verified JWT subject, making this a trusted "
     "self-load. It is the only read that exposes password_hash outside the login "
     "path, and it exists for the self-service change-password flow.",
     "SELECT * FROM tbl_users u WHERE u.id = p_userId"),

    ("udf_GetUserFreshness", "p_userId TEXT", "SETOF vw_UserFreshness", "STABLE",
     "One row per request for the staleness check. Unfiltered by design so the "
     "caller can distinguish inactive from deleted from missing.",
     "SELECT * FROM vw_UserFreshness v WHERE v.id = p_userId"),

    ("udf_GetUserCredentialByEmail", "p_email TEXT", "SETOF vw_UserCredential", "STABLE",
     "The login lookup. Cross-tenant on purpose: an address identifies at most one "
     "live password account, so the tenant is derived FROM the user rather than "
     "supplied by the caller.",
     "SELECT * FROM vw_UserCredential v WHERE lower(v.email) = lower(p_email) LIMIT 1"),

    ("udf_GetUserIdentityForToken", "p_userId TEXT", "SETOF vw_UserIdentity", "STABLE",
     "The token-minting identity. Returns zero rows for a deprovisioned account, "
     "which the caller maps to 403 — this is what stops a token being issued to a "
     "user disabled during the authorization-code window.",
     "SELECT * FROM vw_UserIdentity v WHERE v.id = p_userId"),

    ("udf_GetUserTenantScoped", "p_userId TEXT, p_clientId TEXT", "SETOF vw_UserTenantScoped", "STABLE",
     "Ownership check for any admin operation on a member. Zero rows means either "
     "no such user or another tenant's user, and the caller cannot tell which.",
     "SELECT * FROM vw_UserTenantScoped v WHERE v.id = p_userId AND v.client_id = p_clientId"),

    ("udf_GetOAuthLinkableUser", "p_clientId TEXT, p_email TEXT", "SETOF vw_UserTenantScoped", "STABLE",
     "The federated-login link target: an existing OAUTH_ONLY account in this "
     "tenant. Restricted to OAUTH_ONLY so a Google sign-in can never take over an "
     "account that has its own password.",
     """SELECT * FROM vw_UserTenantScoped v
    WHERE  v.client_id     = p_clientId
      AND  lower(v.email)  = lower(p_email)
      AND  v.is_active      = true
      AND  v.account_type   = 'OAUTH_ONLY'
    LIMIT  1"""),

    ("udf_ListUsers",
     "p_clientId TEXT, p_search TEXT DEFAULT NULL, p_cursorCreated TIMESTAMPTZ DEFAULT NULL, "
     "p_cursorId TEXT DEFAULT NULL, p_take INTEGER DEFAULT 26",
     "SETOF vw_UserListItem", "STABLE",
     "Keyset-paginated user list. Keyset rather than OFFSET because OFFSET degrades "
     "linearly and can skip or repeat rows when the set changes between pages. The "
     "search term has backslash, percent and underscore escaped, so a caller cannot "
     "inject LIKE wildcards to widen the match.",
     """SELECT * FROM vw_UserListItem v
    WHERE  v.client_id = p_clientId
      AND  (p_search IS NULL
            OR v.email ILIKE '%' || replace(replace(replace(p_search, '\\\\', '\\\\\\\\'),
                                                    '%', '\\\\%'), '_', '\\\\_') || '%' ESCAPE '\\\\')
      AND  (p_cursorCreated IS NULL
            OR (v.created_at, v.id) < (p_cursorCreated, p_cursorId))
    ORDER  BY v.created_at DESC, v.id DESC
    LIMIT  p_take"""),

    ("udf_ListUserGroups", "p_clientId TEXT, p_userIds TEXT[]", "SETOF vw_UserGroupMembership", "STABLE",
     "Group memberships for a PAGE of users in one round trip, avoiding a query per "
     "row when rendering the user list.",
     """SELECT * FROM vw_UserGroupMembership v
    WHERE  v.client_id = p_clientId
      AND  v.user_id   = ANY(p_userIds)
    ORDER  BY v.group_name"""),

    ("udf_ListUserProductRoles", "p_userId TEXT, p_clientId TEXT", "SETOF vw_UserProductRole", "STABLE",
     "The user's active product roles. These become the JWT roles claim, so the "
     "tenant predicate here is what keeps another organisation's grant out of a "
     "token.",
     """SELECT * FROM vw_UserProductRole v
    WHERE  v.user_id   = p_userId
      AND  v.client_id = p_clientId"""),

    ("udf_ListUserFeatures", "p_clientId TEXT, p_userId TEXT", "SETOF TEXT", "STABLE",
     "Distinct feature keys the user holds through group membership, for the UI to "
     "decide what to render.",
     """SELECT DISTINCT gf.feature_key
    FROM   tbl_group_features gf
    JOIN   tbl_groups      g  ON g.id = gf.group_id
    JOIN   tbl_user_groups ug ON ug.group_id = g.id AND ug.client_id = g.client_id
    WHERE  g.client_id = p_clientId
      AND  ug.user_id  = p_userId
    ORDER  BY gf.feature_key"""),

    ("udf_GetUserDetail", "p_userId TEXT, p_clientId TEXT", "SETOF vw_GroupDetailRow", "STABLE",
     "PLACEHOLDER — replaced below; see udf_GetUserPermissionRows.",
     "SELECT * FROM vw_GroupDetailRow v WHERE false"),

    # ---- sessions ----------------------------------------------------------
    ("udf_GetSessionByRefreshHashForUpdate", "p_tokenHash TEXT", "SETOF tbl_user_sessions", "VOLATILE",
     "THE rotation lookup. Two deliberate properties:\n"
     "--   * FOR UPDATE locks the row for the caller's transaction, so two "
     "concurrent rotations of the same token serialise instead of both minting a "
     "successor.\n"
     "--   * There is NO revoked_at filter. A revoked match is precisely the signal "
     "that distinguishes a replayed token from an unknown one, and filtering it out "
     "would make reuse detection impossible.\n"
     "-- VOLATILE because a STABLE function may not take row locks.",
     "SELECT * FROM tbl_user_sessions s WHERE s.refresh_token_hash = p_tokenHash FOR UPDATE"),

    ("udf_GetSessionById", "p_sessionId TEXT", "SETOF tbl_user_sessions", "STABLE",
     "Internal lookup used while walking the rotation chain. Deliberately ignores "
     "revocation: the caller needs to inspect a revoked successor to tell a benign "
     "concurrent refresh from a genuine replay.",
     "SELECT * FROM tbl_user_sessions s WHERE s.id = p_sessionId"),

    ("udf_GetGraceSuccessor", "p_prevTokenHash TEXT, p_createdAfter TIMESTAMPTZ", "SETOF tbl_user_sessions", "STABLE",
     "Finds a still-live successor whose predecessor was the presented token, "
     "created inside the grace window. Existence means the legitimate client simply "
     "refreshed twice at once, so the caller answers 409 and leaves the family "
     "intact rather than burning it.",
     """SELECT * FROM tbl_user_sessions s
    WHERE  s.prev_token_hash = p_prevTokenHash
      AND  s.revoked_at     IS NULL
      AND  s.created_at      > p_createdAfter
    ORDER  BY s.created_at DESC
    LIMIT  1"""),

    ("udf_GetSessionForLogout", "p_tokenHash TEXT", "SETOF vw_SessionOwner", "STABLE",
     "Minimal identity for logout. No lock is taken: logout is idempotent, so a "
     "concurrent revoke is harmless.",
     "SELECT * FROM vw_SessionOwner v WHERE v.refresh_token_hash = p_tokenHash"),

    ("udf_GetClientSessionById", "p_sessionId TEXT, p_clientId TEXT", "SETOF vw_SessionOwner", "STABLE",
     "Tenant-scoped session lookup for the admin revoke path.",
     "SELECT * FROM vw_SessionOwner v WHERE v.id = p_sessionId AND v.client_id = p_clientId"),

    ("udf_ListActiveSessions", "p_clientId TEXT", "SETOF vw_SessionSummary", "STABLE",
     "The admin session list, capped so one tenant cannot request an unbounded "
     "result set. The view already excludes token material.",
     """SELECT * FROM vw_SessionSummary v
    WHERE  v.client_id = p_clientId
    ORDER  BY v.last_seen_at DESC
    LIMIT  200"""),

    # ---- clients / products ------------------------------------------------
    ("udf_GetClientById", "p_clientId TEXT", "SETOF tbl_clients", "STABLE",
     "The tenant record. tbl_clients holds no credential, so the full row is safe "
     "to return.",
     "SELECT * FROM tbl_clients c WHERE c.id = p_clientId"),

    ("udf_GetClientOAuthGate", "p_clientId TEXT", "SETOF vw_ClientOAuthGate", "STABLE",
     "The tenant's identity-provider policy, checked before a federated login is "
     "allowed to proceed.",
     "SELECT * FROM vw_ClientOAuthGate v WHERE v.id = p_clientId"),

    ("udf_GetProductById", "p_productId TEXT, p_activeOnly BOOLEAN DEFAULT false", "SETOF tbl_products", "STABLE",
     "A product, optionally restricted to active ones. The login path passes TRUE, "
     "so a retired product cannot be signed into.",
     """SELECT * FROM tbl_products p
    WHERE  p.id = p_productId
      AND  (p_activeOnly = false OR p.is_active = true)"""),

    ("udf_ListActiveProducts", "", "SETOF tbl_products", "STABLE",
     "The active product catalogue. Global, not tenant-scoped: the catalogue is "
     "platform-wide and carries no tenant data.",
     "SELECT * FROM tbl_products p WHERE p.is_active = true ORDER BY p.name"),

    ("udf_ListClientProducts", "p_clientId TEXT", "SETOF vw_ClientProductDetail", "STABLE",
     "A tenant's subscriptions, shaped for the admin products page.",
     "SELECT * FROM vw_ClientProductDetail v WHERE v.client_id = p_clientId ORDER BY v.product_name"),

    ("udf_GetProductPermission", "p_userId TEXT, p_clientId TEXT, p_productId TEXT", "SETOF vw_UserProductRole", "STABLE",
     "A single grant, for existence checks.",
     """SELECT * FROM vw_UserProductRole v
    WHERE  v.user_id    = p_userId
      AND  v.client_id  = p_clientId
      AND  v.product_id = p_productId"""),

    # ---- invitations -------------------------------------------------------
    ("udf_GetPendingInviteByEmail", "p_clientId TEXT, p_email TEXT", "SETOF vw_PendingInvitation", "STABLE",
     "Duplicate-invite guard: is an invitation already outstanding for this address "
     "in this tenant? Prevents two independently redeemable tokens existing at once.",
     """SELECT * FROM vw_PendingInvitation v
    WHERE  v.client_id    = p_clientId
      AND  lower(v.email) = lower(p_email)"""),

    ("udf_GetPendingInvitation", "p_tokenHash TEXT", "SETOF vw_PendingInvitation", "STABLE",
     "Looks a redeemable invitation up by its at-rest hash. The view supplies the "
     "pending, unexpired and active-tenant predicates, so every caller inherits "
     "them and none can accidentally honour a dead invitation.",
     "SELECT * FROM vw_PendingInvitation v WHERE v.token_hash = p_tokenHash"),

    ("udf_ListInvitations", "p_clientId TEXT", "SETOF vw_InvitationListItem", "STABLE",
     "The admin invitation list, newest first and capped.",
     """SELECT * FROM vw_InvitationListItem v
    WHERE  v.client_id = p_clientId
    ORDER  BY v.created_at DESC
    LIMIT  100"""),

    ("udf_ListInvitationProducts", "p_invitationId TEXT", "SETOF vw_InvitationProductRole", "STABLE",
     "The products an invitation confers, applied on acceptance.",
     """SELECT * FROM vw_InvitationProductRole v
    WHERE  v.invitation_id = p_invitationId
    ORDER  BY v.product_name"""),

    # ---- rbac --------------------------------------------------------------
    ("udf_ListGroups", "p_clientId TEXT", "SETOF vw_GroupListItem", "STABLE",
     "The tenant's groups with features and live member counts.",
     "SELECT * FROM vw_GroupListItem v WHERE v.client_id = p_clientId ORDER BY v.name"),

    ("udf_GetGroupDetail", "p_groupId TEXT, p_clientId TEXT", "SETOF vw_GroupDetailRow", "STABLE",
     "One row per member of a group, tenant-scoped.",
     """SELECT * FROM vw_GroupDetailRow v
    WHERE  v.id        = p_groupId
      AND  v.client_id = p_clientId
    ORDER  BY v.user_email NULLS LAST"""),

    ("udf_GetGroupTenantScoped", "p_groupId TEXT, p_clientId TEXT", "SETOF tbl_groups", "STABLE",
     "Ownership check before any group mutation.",
     "SELECT * FROM tbl_groups g WHERE g.id = p_groupId AND g.client_id = p_clientId"),

    # ---- oauth / reset -----------------------------------------------------
    ("udf_GetLinkedIdentity", "p_provider \"IdpProvider\", p_providerId TEXT", "SETOF vw_LinkedIdentityOwner", "STABLE",
     "Resolves an external identity to its local user. Matching on the provider's "
     "stable subject id rather than the email means a user who changes their "
     "provider address keeps their account, and whoever later acquires that address "
     "does not inherit it.",
     """SELECT * FROM vw_LinkedIdentityOwner v
    WHERE  v.provider    = p_provider
      AND  v.provider_id = p_providerId"""),

    ("udf_GetValidResetToken", "p_tokenHash TEXT", "SETOF vw_ValidResetToken", "STABLE",
     "A redeemable reset token with its owner's state. The view carries the unused "
     "and unexpired predicates; the owner's flags let the caller refuse to revive a "
     "disabled account.",
     "SELECT * FROM vw_ValidResetToken v WHERE v.token_hash = p_tokenHash"),
]


def wrap(text, width=74, indent="-- "):
    out = []
    for para in text.split("\n"):
        if para.startswith("--"):
            out.append(para)
            continue
        words, cur = para.split(), ""
        for w in words:
            if len(cur) + len(w) + 1 > width:
                out.append(indent + cur)
                cur = w
            else:
                cur = (cur + " " + w).strip()
        if cur:
            out.append(indent + cur)
    return "\n".join(out)


def emit(kind, name, params, returns, vol, purpose, body):
    sig = f"{name}({params})" if params else f"{name}()"
    return (
        f"/****** Object: {kind} [{name}] ******/\n"
        f"{wrap(purpose)}\n"
        f"--\n"
        f"-- CREATE OR REPLACE so the build is idempotent.\n\n"
        f"CREATE OR REPLACE FUNCTION {sig}\n"
        f"RETURNS {returns}\n"
        f"LANGUAGE sql\n"
        f"{vol}\n"
        f"AS $$\n    {body.strip()};\n$$;\n"
    )


os.makedirs(SCALAR, exist_ok=True)
os.makedirs(TVF, exist_ok=True)

n = 0
for spec in SCALARS:
    name = spec[0]
    with open(os.path.join(SCALAR, name + ".sql"), "w", encoding="utf-8", newline="\n") as f:
        f.write(emit("Scalar-valued Function", *spec))
    n += 1

for spec in TVFS:
    name = spec[0]
    if name == "udf_GetUserDetail":
        continue  # superseded: user detail is assembled from two focused reads
    with open(os.path.join(TVF, name + ".sql"), "w", encoding="utf-8", newline="\n") as f:
        f.write(emit("Table-valued Function", *spec))
    n += 1

print(f"wrote {n} function files")
