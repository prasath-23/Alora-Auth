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
    ("udf_RateLimitPeek", "p_key TEXT, p_max INTEGER", "TIMESTAMPTZ", "STABLE",
     "The reset time of a shared fixed-window counter that has ALREADY reached "
     "p_max, or NULL when the key is still within budget or its window has passed. "
     "Read-only -- it spends nothing: the failure-budget check consults it before "
     "running a request and spends a unit only when the request then fails.",
     """SELECT c.reset_at
    FROM   tbl_rate_limit_counters c
    WHERE  c.bucket_key = p_key
      AND  c.reset_at   > now()
      AND  c.hits      >= p_max"""),

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
     "active tenant. This backs federated-login tenant resolution, so requiring "
     "verification is what stops someone claiming an unowned domain and being "
     "admitted to another organisation.",
     """SELECT c.id
    FROM   tbl_clients c
    WHERE  lower(c.domain)      = lower(p_domain)
      AND  c.domain_verified_at IS NOT NULL
      AND  c.is_active           = true
    LIMIT  1"""),

    ("udf_ProductKeyById", "p_productId TEXT", "TEXT", "STABLE",
     "The product's audience key, used to scope a minted token to one product.",
     """SELECT p.key FROM tbl_products p WHERE p.id = p_productId"""),

    ("udf_IsGroupManager", "p_groupId TEXT, p_clientId TEXT, p_userId TEXT", "BOOLEAN", "STABLE",
     "TRUE when the user manages the group, in that tenant. The manager door asks it "
     "on every request; its writes ask again inside the procedure, at the moment of "
     "the change.",
     """SELECT EXISTS (
        SELECT 1 FROM tbl_group_managers gm
        WHERE  gm.group_id  = p_groupId
          AND  gm.client_id = p_clientId
          AND  gm.user_id   = p_userId
    )"""),

    ("udf_ClientNameById", "p_clientId TEXT", "TEXT", "STABLE",
     "The tenant's display name, for invitation emails.",
     """SELECT c.name FROM tbl_clients c WHERE c.id = p_clientId"""),

    ("udf_ActiveSubscriptionId", "p_clientId TEXT, p_productId TEXT", "TEXT", "STABLE",
     "The tenant's live subscription to a product, or NULL. The grant paths gate on "
     "this, so a tenant cannot be granted a role in a product it does not pay for.",
     """SELECT cp.id
    FROM   tbl_client_products cp
    WHERE  cp.client_id  = p_clientId
      AND  cp.product_id = p_productId
      AND  cp.is_active   = true
      AND  cp.starts_at  <= now()
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

    ("udf_UserCursorPosition", "p_userId TEXT, p_clientId TEXT", "TIMESTAMPTZ", "STABLE",
     "Translates an opaque page cursor (a user id) into its keyset position. "
     "Tenant-scoped, so a cursor forged from another tenant's id resolves to NULL "
     "rather than revealing a position in their list.",
     """SELECT u.created_at
    FROM   tbl_users u
    WHERE  u.id        = p_userId
      AND  u.client_id = p_clientId
      AND  u.deleted_at IS NULL"""),

    ("udf_IsApiClientSecretLive", "p_secretId TEXT, p_apiClientId TEXT", "BOOLEAN", "STABLE",
     "TRUE while the secret an application token was issued under is live: not "
     "revoked, not expired. Introspection checks it, so revoking a secret ends the "
     "tokens issued under it at once.",
     """SELECT EXISTS (
        SELECT 1 FROM tbl_api_client_secrets x
        WHERE  x.id            = p_secretId
          AND  x.api_client_id = p_apiClientId
          AND  x.revoked_at   IS NULL
          AND  (x.expires_at IS NULL OR x.expires_at > now())
    )"""),

    ("udf_HealthCheck", "", "INTEGER", "STABLE",
     "Readiness probe. Round-trips a constant so the caller only has to check for "
     "an error; it touches no table, so a slow query cannot make the service look "
     "unhealthy.",
     """SELECT 1"""),

    ("udf_GetSystemGroupId", "p_clientId TEXT, p_systemKey TEXT", "TEXT", "STABLE",
     "The id of one of a tenant's system groups (ADMINS), created with the tenant.",
     """SELECT g.id
    FROM   tbl_groups g
    WHERE  g.client_id  = p_clientId
      AND  g.system_key = p_systemKey"""),

    ("udf_IsRedirectUriRegistered", "p_productId TEXT, p_redirectUri TEXT", "BOOLEAN", "STABLE",
     "TRUE only for an EXACT match against an active product's registered redirect "
     "URIs. No prefix, origin or wildcard matching: any of those is an open "
     "redirect waiting to happen.",
     """SELECT EXISTS (
        SELECT 1
        FROM   tbl_product_redirect_uris r
        JOIN   tbl_products p ON p.id = r.product_id
                             AND p.is_active = true
        WHERE  r.product_id   = p_productId
          AND  r.redirect_uri = p_redirectUri
    )"""),
]

# (name, params, returns, volatility, purpose, body)
TVFS = [
    # ---- users -------------------------------------------------------------
    ("udf_GetUserById", "p_userId TEXT", "SETOF tbl_users", "STABLE",
     "Full row by primary key. NOT tenant-scoped and NOT soft-delete filtered "
     "because the id comes from a verified token subject, making this a trusted "
     "self-load. It is the only read that exposes password_hash outside the login "
     "path, and it exists for the self-service change-password flow.",
     "SELECT * FROM tbl_users u WHERE u.id = p_userId"),

    ("udf_ListLoginCandidates", "p_email TEXT", "SETOF vw_UserCredential", "STABLE",
     "Every live password account that holds this address, across tenants: one "
     "person may belong to several organisations. Capped and deterministically "
     "ordered, so the work a login does is bounded and repeatable.",
     """SELECT * FROM vw_UserCredential v
    WHERE  lower(v.email) = lower(p_email)
    ORDER  BY v.created_at, v.id
    LIMIT  10"""),

    ("udf_ListUserIdentitiesByEmail", "p_email TEXT", "SETOF vw_UserIdentity", "STABLE",
     "Every live account that holds this address, across tenants, whether or not it "
     "has a password: the accounts a first federated sign-in with a verified address "
     "may link to. Capped and deterministically ordered like the password lookup.",
     """SELECT * FROM vw_UserIdentity v
    WHERE  lower(v.email) = lower(p_email)
    ORDER  BY v.client_id, v.id
    LIMIT  10"""),

    ("udf_GetUserIdentityForToken", "p_userId TEXT", "SETOF vw_UserIdentity", "STABLE",
     "The token-minting identity. Returns zero rows for a deprovisioned account or a "
     "suspended tenant, which the caller maps to a refusal.",
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

    ("udf_GetUserForSsoLink", "p_clientId TEXT, p_email TEXT", "SETOF vw_UserTenantScoped", "STABLE",
     "The account a first SSO sign-in may link to: a live, active member of the "
     "connection's OWN tenant with this address. SSO never creates accounts.",
     """SELECT * FROM vw_UserTenantScoped v
    WHERE  v.client_id     = p_clientId
      AND  lower(v.email)  = lower(p_email)
      AND  v.is_active      = true
    LIMIT  1"""),

    ("udf_ListUsers",
     "p_clientId TEXT, p_search TEXT DEFAULT NULL, p_cursorCreated TIMESTAMPTZ DEFAULT NULL, "
     "p_cursorId TEXT DEFAULT NULL, p_take INTEGER DEFAULT 26",
     "SETOF vw_UserListItem", "STABLE",
     "Keyset-paginated user list. Keyset rather than OFFSET because OFFSET degrades "
     "linearly and can skip or repeat rows when the set changes between pages. The "
     "search term has backslash, percent and underscore escaped, so a caller cannot "
     "inject LIKE wildcards to widen the match. The escapes are E'' strings on "
     "purpose: with standard_conforming_strings on, a plain '\\\\' is TWO characters, "
     "which ESCAPE rejects (\"invalid escape string\") on every search.",
     """SELECT * FROM vw_UserListItem v
    WHERE  v.client_id = p_clientId
      AND  (p_search IS NULL
            OR v.email ILIKE '%' || replace(replace(replace(p_search, E'\\\\', E'\\\\\\\\'),
                                                    '%', E'\\\\%'), '_', E'\\\\_') || '%' ESCAPE E'\\\\')
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
     "The user's DIRECT product roles, tenant-scoped.",
     """SELECT * FROM vw_UserProductRole v
    WHERE  v.user_id   = p_userId
      AND  v.client_id = p_clientId"""),

    ("udf_ListUserScopes", "p_clientId TEXT, p_userId TEXT", "SETOF vw_EffectiveScope", "STABLE",
     "Every App Central scope the user holds, one row per source (each group, and "
     "their extras), tenant-scoped. What the rules compare, and what the UI shows "
     "under 'where it comes from'.",
     """SELECT * FROM vw_EffectiveScope v
    WHERE  v.client_id = p_clientId
      AND  v.user_id   = p_userId
    ORDER  BY v.scope, v.source, v.group_name"""),

    ("udf_ListScopeReach", "p_clientId TEXT, p_userId TEXT", "SETOF vw_ScopeReach", "STABLE",
     "The user's reach, tenant-scoped: the scopes they hold plus those of the groups "
     "they manage, one row per source. What rule 2 compares -- never what grants.",
     """SELECT * FROM vw_ScopeReach v
    WHERE  v.client_id = p_clientId
      AND  v.user_id   = p_userId
    ORDER  BY v.scope, v.via"""),

    ("udf_ListScopes", "", "SETOF tbl_scopes", "STABLE",
     "The scope catalogue, in display order.",
     "SELECT * FROM tbl_scopes s ORDER BY s.sort_order"),

    ("udf_GetUserLoginPolicy", "p_userId TEXT, p_clientId TEXT", "SETOF vw_UserLoginPolicy", "STABLE",
     "The login policy that applies to one user, already resolved.",
     """SELECT * FROM vw_UserLoginPolicy v
    WHERE  v.user_id   = p_userId
      AND  v.client_id = p_clientId"""),

    # ---- access ------------------------------------------------------------
    ("udf_ListEffectiveRoles", "p_userId TEXT, p_clientId TEXT, p_productId TEXT", "SETOF TEXT", "STABLE",
     "The distinct roles a user effectively holds in ONE product. Empty means no "
     "access; this is what a product token's roles claim is built from.",
     """SELECT DISTINCT v.role_name
    FROM   vw_EffectiveProductRole v
    WHERE  v.user_id    = p_userId
      AND  v.client_id  = p_clientId
      AND  v.product_id = p_productId
    ORDER  BY v.role_name"""),

    ("udf_ListUserEffectiveAccess", "p_userId TEXT, p_clientId TEXT", "SETOF vw_EffectiveProductRole", "STABLE",
     "Every effective role of one user, with where it comes from.",
     """SELECT * FROM vw_EffectiveProductRole v
    WHERE  v.user_id   = p_userId
      AND  v.client_id = p_clientId
    ORDER  BY v.product_name, v.role_name"""),

    ("udf_ListUserApps", "p_userId TEXT, p_clientId TEXT", "SETOF vw_UserApp", "STABLE",
     "The products a user may open from App Central.",
     """SELECT * FROM vw_UserApp v
    WHERE  v.user_id   = p_userId
      AND  v.client_id = p_clientId
    ORDER  BY v.product_name"""),

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

    ("udf_GetSessionFamilyGate", "p_familyId TEXT", "SETOF vw_SessionFamilyGate", "STABLE",
     "Everything the service must check about one login, in one read.",
     "SELECT * FROM vw_SessionFamilyGate v WHERE v.family_id = p_familyId"),

    ("udf_ListSessionFamilies", "p_clientId TEXT", "SETOF vw_SessionFamilySummary", "STABLE",
     "The admin session list, capped so one tenant cannot request an unbounded "
     "result set. The view already excludes token material.",
     """SELECT * FROM vw_SessionFamilySummary v
    WHERE  v.client_id = p_clientId
    ORDER  BY v.last_seen_at DESC
    LIMIT  200"""),

    # ---- clients / products ------------------------------------------------
    ("udf_GetClientById", "p_clientId TEXT", "SETOF tbl_clients", "STABLE",
     "The tenant record. tbl_clients holds no credential, so the full row is safe "
     "to return.",
     "SELECT * FROM tbl_clients c WHERE c.id = p_clientId"),

    ("udf_ListCompanies", "", "SETOF vw_CompanyListItem", "STABLE",
     "Every tenant, for the Owner console: the platform company first.",
     "SELECT * FROM vw_CompanyListItem v ORDER BY v.is_platform DESC, v.name"),

    ("udf_GetProductById", "p_productId TEXT, p_activeOnly BOOLEAN DEFAULT false", "SETOF tbl_products", "STABLE",
     "A product, optionally restricted to active ones.",
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
     "A single direct grant, for existence checks.",
     """SELECT * FROM vw_UserProductRole v
    WHERE  v.user_id    = p_userId
      AND  v.client_id  = p_clientId
      AND  v.product_id = p_productId"""),

    ("udf_GetProductClient", "p_productId TEXT", "SETOF vw_ProductClient", "STABLE",
     "A product's client registration, without its secret.",
     "SELECT * FROM vw_ProductClient v WHERE v.id = p_productId"),

    ("udf_GetProductClientCredential", "p_productId TEXT", "SETOF vw_ProductClientCredential", "STABLE",
     "The secret hash of a product, for client authentication only.",
     "SELECT * FROM vw_ProductClientCredential v WHERE v.id = p_productId"),

    ("udf_ListProducts", "", "SETOF vw_ProductClient", "STABLE",
     "The whole catalogue with registration details, for the Owner console.",
     "SELECT * FROM vw_ProductClient v ORDER BY v.name"),

    ("udf_ListProductRoles", "p_productId TEXT", "SETOF tbl_product_roles", "STABLE",
     "A product's role catalogue.",
     "SELECT * FROM tbl_product_roles r WHERE r.product_id = p_productId ORDER BY r.role_name"),

    ("udf_ListProductRedirectUris", "p_productId TEXT", "SETOF tbl_product_redirect_uris", "STABLE",
     "A product's registered redirect URIs.",
     "SELECT * FROM tbl_product_redirect_uris r WHERE r.product_id = p_productId ORDER BY r.redirect_uri"),

    # ---- API clients -------------------------------------------------------
    ("udf_ListApiClients", "p_clientId TEXT", "SETOF vw_ApiClientSummary", "STABLE",
     "A tenant's API clients, by name.",
     "SELECT * FROM vw_ApiClientSummary v WHERE v.client_id = p_clientId ORDER BY lower(v.name)"),

    ("udf_ListAllApiClients", "", "SETOF vw_ApiClientSummary", "STABLE",
     "Every tenant's API clients, for the Owner console: by company, then by name.",
     "SELECT * FROM vw_ApiClientSummary v ORDER BY lower(v.company_name), lower(v.name)"),

    ("udf_GetApiClient", "p_apiClientId TEXT, p_clientId TEXT", "SETOF vw_ApiClientSummary", "STABLE",
     "One API client of a tenant; another tenant's id yields no rows.",
     "SELECT * FROM vw_ApiClientSummary v WHERE v.id = p_apiClientId AND v.client_id = p_clientId"),

    ("udf_ListApiClientSecrets", "p_apiClientId TEXT, p_clientId TEXT", "SETOF vw_ApiClientSecret", "STABLE",
     "An API client's secrets, newest first, without their hashes.",
     """SELECT * FROM vw_ApiClientSecret v
    WHERE  v.api_client_id = p_apiClientId
      AND  v.client_id     = p_clientId
    ORDER  BY v.created_at DESC"""),

    ("udf_ListApiClientProductChoices", "p_clientId TEXT", "SETOF vw_ClientProductDetail", "STABLE",
     "The products a tenant may put on an API client's list: live subscriptions to "
     "active products that accept API clients.",
     """SELECT * FROM vw_ClientProductDetail v
    WHERE  v.client_id = p_clientId
      AND  v.is_active
      AND  v.starts_at <= now()
      AND  (v.ends_at IS NULL OR v.ends_at > now())
      AND  v.product_is_active
      AND  v.product_accepts_api_clients
    ORDER  BY v.product_name"""),

    ("udf_GetOAuthClientCredentials", "p_oauthClientId TEXT", "SETOF vw_OAuthClientCredential", "STABLE",
     "The credentials to check a client id's secret against at the token endpoint: a "
     "product's one secret, or an API client's live secrets (at most two).",
     "SELECT * FROM vw_OAuthClientCredential v WHERE v.oauth_client_id = p_oauthClientId"),

    ("udf_GetApiClientGrant", "p_apiClientId TEXT, p_productKey TEXT", "SETOF vw_ApiClientGrant", "STABLE",
     "Whether an API client may have a token for a product on its list right now, and "
     "with which scopes. No row: the product is unknown, or not on the list.",
     """SELECT * FROM vw_ApiClientGrant v
    WHERE  v.api_client_id = p_apiClientId
      AND  v.product_key   = p_productKey"""),

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

    ("udf_ListInvitationGroups", "p_invitationId TEXT", "SETOF vw_InvitationGroup", "STABLE",
     "The groups an invitation adds its user to, applied on acceptance.",
     """SELECT * FROM vw_InvitationGroup v
    WHERE  v.invitation_id = p_invitationId
    ORDER  BY v.group_name"""),

    ("udf_GetInvitationLoginPolicy", "p_invitationId TEXT, p_clientId TEXT", "SETOF tbl_login_policies", "STABLE",
     "The login policy an invited user will be under: the highest-priority policy "
     "among the invited groups, else the tenant default. Lets the acceptance page "
     "offer only the methods the user will actually be allowed.",
     """SELECT lp.* FROM tbl_login_policies lp
    WHERE  lp.client_id = p_clientId
      AND  lp.id = COALESCE(
             (SELECT gp.id
              FROM   tbl_invitation_groups ig
              JOIN   tbl_groups         g  ON g.id  = ig.group_id
                                          AND g.client_id = ig.client_id
              JOIN   tbl_login_policies gp ON gp.id = g.login_policy_id
                                          AND gp.client_id = g.client_id
              WHERE  ig.invitation_id = p_invitationId
                AND  ig.client_id     = p_clientId
              ORDER  BY gp.priority DESC
              LIMIT  1),
             (SELECT d.id FROM tbl_login_policies d
              WHERE  d.client_id = p_clientId
                AND  d.is_default))"""),

    # ---- rbac --------------------------------------------------------------
    ("udf_ListGroups", "p_clientId TEXT", "SETOF vw_GroupListItem", "STABLE",
     "The tenant's groups with their scopes, product grants and live member counts.",
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

    ("udf_ListGroupManagers", "p_groupId TEXT, p_clientId TEXT", "SETOF vw_GroupManager", "STABLE",
     "A group's managers, tenant-scoped, by address.",
     """SELECT * FROM vw_GroupManager v
    WHERE  v.group_id  = p_groupId
      AND  v.client_id = p_clientId
    ORDER  BY v.email"""),

    ("udf_ListManagedGroups", "p_userId TEXT, p_clientId TEXT", "SETOF vw_GroupListItem", "STABLE",
     "The groups a person manages in their tenant, as the group list shows them.",
     """SELECT * FROM vw_GroupListItem v
    WHERE  v.client_id = p_clientId
      AND  EXISTS (SELECT 1 FROM tbl_group_managers gm
                   WHERE  gm.group_id  = v.id
                     AND  gm.client_id = v.client_id
                     AND  gm.user_id   = p_userId)
    ORDER  BY v.name"""),

    # ---- oauth / federation / reset ----------------------------------------
    ("udf_GetAuthorizationCodeByHash", "p_codeHash TEXT", "SETOF tbl_authorization_codes", "STABLE",
     "A code by its hash, spent or not: after a failed claim, it tells a replay "
     "(whose product login must then be revoked) from an unknown code.",
     "SELECT * FROM tbl_authorization_codes a WHERE a.code_hash = p_codeHash"),

    ("udf_GetLoginState", "p_stateHash TEXT, p_kind \"LoginStateKind\"", "SETOF tbl_login_states", "STABLE",
     "A live sign-in state by its hash, WITHOUT consuming it: the account chooser "
     "reads its candidates before the choice is made. Redemption is always "
     "stp_TakeLoginState, which deletes the row in the same statement.",
     """SELECT * FROM tbl_login_states s
    WHERE  s.state_hash = p_stateHash
      AND  s.kind       = p_kind
      AND  s.expires_at > now()"""),

    ("udf_ListGoogleLinks", "p_subject TEXT", "SETOF vw_LinkedIdentityOwner", "STABLE",
     "Every live account a Google subject is linked to, one per tenant at most.",
     """SELECT * FROM vw_LinkedIdentityOwner v
    WHERE  v.provider    = 'GOOGLE'
      AND  v.provider_id = p_subject"""),

    ("udf_GetLinkedIdentityByConnection", "p_connectionId TEXT, p_subject TEXT", "SETOF vw_LinkedIdentityOwner", "STABLE",
     "The live account an SSO subject is linked to at one connection. Matching on "
     "the provider's stable subject, never the email, is what stops an address "
     "change at the provider from moving someone into another account.",
     """SELECT * FROM vw_LinkedIdentityOwner v
    WHERE  v.provider      = 'OIDC'
      AND  v.connection_id = p_connectionId
      AND  v.provider_id   = p_subject"""),

    # The lock below is what makes a reset token single-use; see the header. The
    # header is verbatim "--" lines, which wrap() passes through unchanged.
    ("udf_GetValidResetToken", "p_tokenHash TEXT", "SETOF vw_ValidResetToken", "VOLATILE",
     "-- A redeemable password-reset token with its owner's state. The unused and\n"
     "-- unexpired predicates come from vw_ValidResetToken; the owner's flags let the\n"
     "-- caller refuse to revive a disabled account.\n"
     "--\n"
     "-- FOR UPDATE OF t is ESSENTIAL and is why this function reads the base tables\n"
     "-- rather than simply selecting from the view: it locks the token row for the\n"
     "-- caller's transaction, so two concurrent redemptions of the same (possibly\n"
     "-- stolen) token serialise. The second waits, re-evaluates `used_at IS NULL`\n"
     "-- under the lock, and finds nothing — which is what makes single-use real. A\n"
     "-- lock-free read would let an attacker racing the legitimate user set the\n"
     "-- password to a value of their choosing.\n"
     "--\n"
     "-- VOLATILE because a STABLE function may not take row locks.\n"
     "--\n"
     "-- The result type stays SETOF vw_ValidResetToken so the row shape is declared in\n"
     "-- exactly one place.",
     """SELECT t.id,
           t.user_id,
           t.client_id,
           t.token_hash,
           u.email,
           u.is_active,
           u.deleted_at
    FROM   tbl_password_reset_tokens t
    JOIN   tbl_users u ON u.id = t.user_id
    WHERE  t.token_hash  = p_tokenHash
      AND  t.used_at    IS NULL
      AND  t.expires_at  > now()
    FOR    UPDATE OF t"""),

    # ---- login policies / sso ----------------------------------------------
    ("udf_ListLoginPolicies", "p_clientId TEXT", "SETOF tbl_login_policies", "STABLE",
     "A tenant's login policies, highest priority first.",
     "SELECT * FROM tbl_login_policies lp WHERE lp.client_id = p_clientId ORDER BY lp.priority DESC"),

    ("udf_GetLoginPolicy", "p_policyId TEXT, p_clientId TEXT", "SETOF tbl_login_policies", "STABLE",
     "One policy, tenant-scoped.",
     "SELECT * FROM tbl_login_policies lp WHERE lp.id = p_policyId AND lp.client_id = p_clientId"),

    ("udf_GetSsoConnection", "p_connectionId TEXT", "SETOF vw_SsoConnectionRuntime", "STABLE",
     "What the SSO login path needs about one connection, secret ciphertext "
     "included. Never returned by any API.",
     "SELECT * FROM vw_SsoConnectionRuntime v WHERE v.id = p_connectionId"),

    ("udf_ListSsoConnections", "p_clientId TEXT", "SETOF vw_SsoConnectionSummary", "STABLE",
     "A tenant's SSO connections, without secrets.",
     "SELECT * FROM vw_SsoConnectionSummary v WHERE v.client_id = p_clientId ORDER BY v.name"),

    ("udf_GetDomainLoginHint", "p_domain TEXT", "SETOF vw_DomainLoginHint", "STABLE",
     "The sign-in methods to OFFER for an email domain. A hint for the login page "
     "only: every login path enforces the user's own policy regardless.",
     "SELECT * FROM vw_DomainLoginHint v WHERE v.domain = lower(p_domain) LIMIT 1"),
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
    with open(os.path.join(TVF, name + ".sql"), "w", encoding="utf-8", newline="\n") as f:
        f.write(emit("Table-valued Function", *spec))
    n += 1

print(f"wrote {n} function files")
