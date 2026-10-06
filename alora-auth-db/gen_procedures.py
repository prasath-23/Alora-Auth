"""Generates db/Programmability/StoredProcedures/stp_*.sql — one file per write.

CONVENTION AND A POSTGRESQL CONSTRAINT

  stp_* denotes a WRITE entry point. It is implemented as:

    * CREATE PROCEDURE  when nothing needs to be returned. Called with CALL.

    * CREATE FUNCTION   when the caller needs the inserted row or an affected-row
                        count. PostgreSQL procedures cannot return a result set,
                        and their INOUT parameters are not usable through the
                        query interface this API uses, so a function is the only
                        correct option. Marked VOLATILE.

  Each file states which form it uses and why, so the difference is never a
  surprise at the call site.

  Affected-row counts come from a CTE (`WITH upd AS (UPDATE ... RETURNING 1)
  SELECT count(*) FROM upd`) rather than plpgsql's ROW_COUNT, which keeps these
  as plain SQL functions the planner can inline. Writes that need a guard or
  several dependent statements are plpgsql, written out in full in EXPLICIT.

Run:  python db/gen_procedures.py
"""
import os

OUT = os.path.join(os.path.dirname(__file__), "Programmability", "StoredProcedures")

# kind: "proc" (CREATE PROCEDURE, no return) | "func" (CREATE FUNCTION + returns)
# (name, kind, params, returns_or_None, purpose, body)
WRITES = [
    # ---- users -------------------------------------------------------------
    # stp_CreateUser and stp_SetUserActive are plpgsql (see EXPLICIT): both guard
    # a company's max_seats under a row lock, which a plain SQL body cannot do.

    ("stp_SetUserPassword", "proc",
     "p_userId TEXT, p_clientId TEXT, p_passwordHash TEXT", None,
     "Sets a new password hash. Tenant-scoped so a leaked user id from another "
     "organisation cannot be used to overwrite a password. An OAUTH_ONLY account "
     "that receives a password becomes HYBRID, otherwise the password could never "
     "be used; whether it MAY be used is still the login policy's decision.",
     """UPDATE tbl_users
    SET    password_hash = p_passwordHash,
           account_type  = CASE WHEN account_type = 'OAUTH_ONLY' THEN 'HYBRID'::"AccountType"
                                ELSE account_type END,
           updated_at    = now()
    WHERE  id        = p_userId
      AND  client_id = p_clientId"""),

    ("stp_SoftDeleteUser", "proc",
     "p_userId TEXT, p_clientId TEXT", None,
     "Soft delete. Stamping deleted_at drops the row out of the partial unique index "
     "on email, which is what frees the address for re-invitation while keeping the "
     "row for the audit trail.",
     """UPDATE tbl_users
    SET    deleted_at = now(),
           updated_at = now()
    WHERE  id        = p_userId
      AND  client_id = p_clientId"""),

    ("stp_BumpPermissionsVersion", "proc",
     "p_userId TEXT, p_clientId TEXT", None,
     "Invalidates the user's outstanding access tokens. The increment is done IN SQL "
     "(pv = pv + 1) rather than read-modify-write, so concurrent grants cannot lose "
     "an increment and leave a stale token valid.",
     """UPDATE tbl_users
    SET    permissions_version = permissions_version + 1,
           updated_at          = now()
    WHERE  id        = p_userId
      AND  client_id = p_clientId"""),

    ("stp_SetUserLoginPolicy", "func",
     "p_userId TEXT, p_clientId TEXT, p_policyId TEXT", "INTEGER",
     "Assigns a user their own login policy, or clears it with NULL. The composite "
     "key refuses another tenant's policy.",
     """WITH upd AS (
        UPDATE tbl_users
        SET    login_policy_id = p_policyId,
               updated_at      = now()
        WHERE  id          = p_userId
          AND  client_id   = p_clientId
          AND  deleted_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM upd"""),

    ("stp_CreatePlatformOwner", "proc",
     "p_userId TEXT, p_clientId TEXT", None,
     "Makes a platform-company user an Owner. Runs with the CALLER's rights, and the "
     "application role holds no write on tbl_platform_owners, so only provisioning "
     "connected as the schema owner can call it successfully.",
     """INSERT INTO tbl_platform_owners (user_id, client_id)
    VALUES (p_userId, p_clientId)
    ON CONFLICT (user_id) DO NOTHING"""),

    # ---- clients / products -------------------------------------------------
    ("stp_UpdateClient", "func",
     'p_clientId TEXT, p_name TEXT, p_domainVerifiedAt TIMESTAMPTZ, '
     'p_subscriptionStatus "SubscriptionStatus", p_maxSeats INTEGER, p_isActive BOOLEAN',
     "SETOF tbl_clients",
     "Full tenant update. The domain itself changes only through "
     "stp_SetClientDomain, and is_platform never changes after creation.",
     """UPDATE tbl_clients
    SET    name                = p_name,
           domain_verified_at  = p_domainVerifiedAt,
           subscription_status = p_subscriptionStatus,
           max_seats           = p_maxSeats,
           is_active           = p_isActive,
           updated_at          = now()
    WHERE  id = p_clientId
    RETURNING *"""),

    ("stp_SetClientDomain", "func",
     "p_clientId TEXT, p_domain TEXT, p_verified BOOLEAN", "SETOF tbl_clients",
     "Sets a tenant's email domain, and whether an Owner has verified it. A verified "
     "domain already held by another tenant raises 23505.",
     """UPDATE tbl_clients
    SET    domain             = lower(p_domain),
           domain_verified_at = CASE WHEN p_verified AND p_domain IS NOT NULL THEN now() ELSE NULL END,
           updated_at         = now()
    WHERE  id = p_clientId
    RETURNING *"""),

    ("stp_CreateProduct", "func",
     "p_key TEXT, p_name TEXT, p_description TEXT, p_baseUrl TEXT, p_initiateLoginUri TEXT, p_isActive BOOLEAN, "
     "p_acceptsApiClients BOOLEAN",
     "SETOF tbl_products",
     "Adds a product to the global catalogue. A duplicate key raises 23505. Its "
     "client secret, redirect URIs and roles are set separately.",
     """INSERT INTO tbl_products (key, name, description, base_url, initiate_login_uri, is_active,
                             accepts_api_clients)
    VALUES (p_key, p_name, p_description, p_baseUrl, p_initiateLoginUri, p_isActive,
            p_acceptsApiClients)
    RETURNING *"""),

    ("stp_UpdateProduct", "func",
     "p_productId TEXT, p_name TEXT, p_description TEXT, p_baseUrl TEXT, p_initiateLoginUri TEXT, p_isActive BOOLEAN, "
     "p_acceptsApiClients BOOLEAN",
     "SETOF tbl_products",
     "Updates a catalogue entry. The key is immutable: it is embedded in already-"
     "issued token audiences, so changing it would invalidate live tokens. A NULL "
     "p_acceptsApiClients keeps whether the product accepts API clients.",
     """UPDATE tbl_products
    SET    name                = p_name,
           description         = p_description,
           base_url            = p_baseUrl,
           initiate_login_uri  = p_initiateLoginUri,
           is_active           = p_isActive,
           accepts_api_clients = COALESCE(p_acceptsApiClients, accepts_api_clients),
           updated_at          = now()
    WHERE  id = p_productId
    RETURNING *"""),

    ("stp_SetProductClientSecret", "func",
     "p_productId TEXT, p_secretHash TEXT", "INTEGER",
     "Rotates a product's client secret. Only the hash is stored; the plaintext is "
     "shown to the Owner once and never again.",
     """WITH upd AS (
        UPDATE tbl_products
        SET    client_secret_hash = p_secretHash,
               secret_rotated_at  = now(),
               updated_at         = now()
        WHERE  id = p_productId
        RETURNING 1
    )
    SELECT count(*)::int FROM upd"""),

    ("stp_SetProductRedirectUris", "func",
     "p_productId TEXT, p_redirectUris TEXT[]", "INTEGER",
     "Replaces a product's redirect URIs wholesale with the complete desired set.",
     """DELETE FROM tbl_product_redirect_uris WHERE product_id = p_productId;
    INSERT INTO tbl_product_redirect_uris (product_id, redirect_uri)
    SELECT DISTINCT p_productId, u FROM unnest(p_redirectUris) AS u;
    SELECT count(*)::int FROM tbl_product_redirect_uris WHERE product_id = p_productId"""),

    ("stp_SetProductRoles", "func",
     "p_productId TEXT, p_roleNames TEXT[]", "INTEGER",
     "Replaces a product's role catalogue with the complete desired set. Removing a "
     "role that is still granted fails on its foreign key (23503), which the caller "
     "reports as a conflict instead of silently revoking access.",
     """DELETE FROM tbl_product_roles
    WHERE  product_id = p_productId
      AND  role_name <> ALL (p_roleNames);
    INSERT INTO tbl_product_roles (product_id, role_name)
    SELECT DISTINCT p_productId, r FROM unnest(p_roleNames) AS r
    ON CONFLICT (product_id, role_name) DO NOTHING;
    SELECT count(*)::int FROM tbl_product_roles WHERE product_id = p_productId"""),

    ("stp_UpsertSubscription", "func",
     "p_clientId TEXT, p_productId TEXT, p_isActive BOOLEAN, p_seatLimit INTEGER, p_endsAt TIMESTAMPTZ",
     "SETOF tbl_client_products",
     "Subscribes a tenant to a product, or changes the subscription. Deactivating "
     "a subscription stops every launch and refresh of that product for the tenant, "
     "because effective access requires a live subscription.",
     """INSERT INTO tbl_client_products (client_id, product_id, is_active, seat_limit, ends_at)
    VALUES (p_clientId, p_productId, p_isActive, p_seatLimit, p_endsAt)
    ON CONFLICT (client_id, product_id)
    DO UPDATE SET is_active  = EXCLUDED.is_active,
                  seat_limit = EXCLUDED.seat_limit,
                  ends_at    = EXCLUDED.ends_at
    RETURNING *"""),

    # ---- sessions ----------------------------------------------------------
    ("stp_CreateSuccessorSession", "func",
     "p_userId TEXT, p_clientId TEXT, p_sessionUuid TEXT, p_familyId TEXT, "
     "p_generation INTEGER, p_refreshTokenHash TEXT, p_prevTokenHash TEXT, "
     "p_expiresAt TIMESTAMPTZ, p_ipAddress TEXT, p_deviceLabel TEXT, p_userAgent TEXT",
     "SETOF tbl_user_sessions",
     "Appends the next generation to an existing family. The family id is inherited, "
     "never regenerated -- that is what keeps a stolen token traceable to every other "
     "token derived from the same login. prev_token_hash is what makes the "
     "grace-window race detectable. A collision on (family_id, generation) means a "
     "concurrent rotation won, and the unique index turns that into 23505 rather "
     "than a forked family. The expiry never outlives the family's absolute cap.",
     """INSERT INTO tbl_user_sessions (user_id, client_id, session_uuid, family_id, generation,
                                   refresh_token_hash, prev_token_hash, expires_at,
                                   ip_address, device_label, user_agent)
    SELECT p_userId, p_clientId, p_sessionUuid, p_familyId, p_generation,
           p_refreshTokenHash, p_prevTokenHash, LEAST(p_expiresAt, f.absolute_expires_at),
           p_ipAddress, p_deviceLabel, p_userAgent
    FROM   tbl_session_families f
    WHERE  f.id = p_familyId
    RETURNING *"""),

    ("stp_MarkSessionReplaced", "proc",
     "p_sessionId TEXT, p_replacedById TEXT", None,
     "Retires a rotated session. revoked_reason is left NULL on purpose: a normal "
     "rotation is not a revocation event, and conflating the two would make a "
     "genuine security revocation indistinguishable from routine refresh traffic.",
     """UPDATE tbl_user_sessions
    SET    revoked_at     = now(),
           replaced_by_id = p_replacedById
    WHERE  id = p_sessionId"""),

    ("stp_RevokeSessionFamily", "func",
     'p_familyId TEXT, p_clientId TEXT, p_reason "SessionRevokedReason"', "INTEGER",
     "Revokes one login and every product login under it, tenant-scoped, with all "
     "their live generations. Returns the number of logins revoked, so a foreign or "
     "already-revoked id yields 0 and the caller answers 404.",
     """WITH fam AS (
        UPDATE tbl_session_families
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  (id = p_familyId OR parent_family_id = p_familyId)
          AND  client_id   = p_clientId
          AND  revoked_at IS NULL
        RETURNING id
    ), ses AS (
        UPDATE tbl_user_sessions
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  family_id  IN (SELECT id FROM fam)
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM fam"""),

    ("stp_RevokeAllUserSessions", "func",
     'p_userId TEXT, p_reason "SessionRevokedReason"', "INTEGER",
     "Revokes every live login and generation of a user -- used on password change, "
     "reset and deactivation. Scoped by user_id alone is safe because the composite "
     "tenant foreign key pins a user to exactly one tenant.",
     """WITH fam AS (
        UPDATE tbl_session_families
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  user_id     = p_userId
          AND  revoked_at IS NULL
        RETURNING 1
    ), ses AS (
        UPDATE tbl_user_sessions
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  user_id     = p_userId
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM ses"""),

    ("stp_RevokeAllClientSessions", "func",
     'p_clientId TEXT, p_reason "SessionRevokedReason"', "INTEGER",
     "Revokes every live login and generation across a whole company -- used when a "
     "company is suspended, deactivated or cancelled, so its sessions END rather than "
     "merely being gated and revived on reactivation. Mirrors stp_RevokeAllUserSessions "
     "but scoped by client_id, which every family and session row carries.",
     """WITH fam AS (
        UPDATE tbl_session_families
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  client_id   = p_clientId
          AND  revoked_at IS NULL
        RETURNING 1
    ), ses AS (
        UPDATE tbl_user_sessions
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  client_id   = p_clientId
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM ses"""),

    ("stp_RevokeTokenFamily", "proc",
     "p_familyId TEXT, p_reason TEXT DEFAULT 'REUSE_DETECTED'", None,
     "THE reuse-detection response: burns a login, every product login under it and "
     "all their live generations. Called when a spent refresh token is replayed "
     "outside the grace window. The caller must COMMIT this before returning the "
     "error -- if it is rolled back with the failing request, the family is never "
     "actually revoked and the detection is cosmetic.",
     """UPDATE tbl_session_families
    SET    revoked_at     = now(),
           revoked_reason = p_reason::"SessionRevokedReason"
    WHERE  (id = p_familyId OR parent_family_id = p_familyId)
      AND  revoked_at IS NULL;
    UPDATE tbl_user_sessions
    SET    revoked_at     = now(),
           revoked_reason = p_reason::"SessionRevokedReason"
    WHERE  family_id IN (SELECT f.id FROM tbl_session_families f
                         WHERE  f.id = p_familyId OR f.parent_family_id = p_familyId)
      AND  revoked_at IS NULL"""),

    ("stp_ExpireSessions", "proc",
     "p_batchSize INTEGER DEFAULT 500", None,
     "Scheduled sweep for timed-out generations and for logins past their absolute "
     "cap. Batched so the transaction stays short and never holds locks against "
     "live rotation traffic. Purely hygiene: every read path already checks both "
     "expiries, so a late sweep is not a security gap.",
     """UPDATE tbl_user_sessions
    SET    revoked_at     = now(),
           revoked_reason = 'EXPIRED'
    WHERE  id IN (
        SELECT s.id
        FROM   tbl_user_sessions s
        WHERE  s.expires_at  < now()
          AND  s.revoked_at IS NULL
        LIMIT  p_batchSize
    );
    UPDATE tbl_session_families
    SET    revoked_at     = now(),
           revoked_reason = 'EXPIRED'
    WHERE  id IN (
        SELECT f.id
        FROM   tbl_session_families f
        WHERE  f.absolute_expires_at < now()
          AND  f.revoked_at IS NULL
        LIMIT  p_batchSize
    )"""),

    # ---- oauth -------------------------------------------------------------
    ("stp_CreateAuthorizationCode", "func",
     "p_codeHash TEXT, p_productId TEXT, p_userId TEXT, p_clientId TEXT, p_parentFamilyId TEXT, "
     "p_redirectUri TEXT, p_codeChallenge TEXT, p_codeChallengeMethod TEXT, p_nonce TEXT, "
     "p_scope TEXT, p_expiresAt TIMESTAMPTZ",
     "SETOF tbl_authorization_codes",
     "Issues a single-use authorization code, stored as its hash. The redirect URI, "
     "PKCE challenge, nonce and the central login it was issued under are stored "
     "WITH the code, so all are re-verified at redemption and cannot be swapped "
     "between the two legs of the flow.",
     """INSERT INTO tbl_authorization_codes (code_hash, product_id, user_id, client_id, parent_family_id,
                                         redirect_uri, code_challenge, code_challenge_method,
                                         nonce, scope, expires_at)
    VALUES (p_codeHash, p_productId, p_userId, p_clientId, p_parentFamilyId,
            p_redirectUri, p_codeChallenge, p_codeChallengeMethod,
            p_nonce, p_scope, p_expiresAt)
    RETURNING *"""),

    ("stp_ClaimAuthorizationCode", "func",
     "p_codeHash TEXT", "SETOF tbl_authorization_codes",
     "Redeems a code in ONE atomic statement. The used_at IS NULL and expiry guards "
     "are part of the UPDATE, so two concurrent redemptions cannot both succeed -- "
     "the second updates zero rows. A SELECT-then-UPDATE here would be a "
     "double-spend, which is the classic authorization-code attack.",
     """UPDATE tbl_authorization_codes
    SET    used_at = now()
    WHERE  code_hash  = p_codeHash
      AND  used_at   IS NULL
      AND  expires_at > now()
    RETURNING *"""),

    ("stp_SetCodeIssuedFamily", "proc",
     "p_codeId TEXT, p_familyId TEXT", None,
     "Records the product login a code produced, so a later replay of the code can "
     "revoke it (RFC 6749 4.1.2).",
     """UPDATE tbl_authorization_codes
    SET    issued_family_id = p_familyId
    WHERE  id = p_codeId"""),

    ("stp_CleanupExpiredAuthCodes", "func", "", "INTEGER",
     "Housekeeping sweep. A code is kept for an hour past its expiry, so a replay "
     "arriving late is still recognised as one; after that it is deleted outright.",
     """WITH del AS (
        DELETE FROM tbl_authorization_codes
        WHERE  expires_at < now() - interval '1 hour'
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

    ("stp_CreateLinkedIdentity", "func",
     'p_userId TEXT, p_clientId TEXT, p_provider "IdpProvider", p_connectionId TEXT, '
     'p_providerId TEXT, p_emailVerified BOOLEAN, p_emailAtLink TEXT',
     "SETOF tbl_linked_identities",
     "Binds an external identity to a local account on its first federated sign-in. "
     "The partial unique indexes allow one Google account per tenant and one "
     "subject per SSO connection.",
     """INSERT INTO tbl_linked_identities (user_id, client_id, provider, connection_id,
                                       provider_id, email_verified, email_at_link)
    VALUES (p_userId, p_clientId, p_provider, p_connectionId,
            p_providerId, p_emailVerified, lower(p_emailAtLink))
    RETURNING *"""),

    ("stp_DeleteLinkedIdentity", "func",
     'p_userId TEXT, p_clientId TEXT, p_provider "IdpProvider", p_connectionId TEXT', "INTEGER",
     "Unlinks an external identity, tenant-scoped.",
     """WITH del AS (
        DELETE FROM tbl_linked_identities
        WHERE  user_id   = p_userId
          AND  client_id = p_clientId
          AND  provider  = p_provider
          AND  connection_id IS NOT DISTINCT FROM p_connectionId
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

    # ---- login states --------------------------------------------------------
    ("stp_CreateLoginState", "proc",
     'p_stateHash TEXT, p_kind "LoginStateKind", p_connectionId TEXT, p_nonce TEXT, '
     'p_codeVerifier TEXT, p_returnTo TEXT, p_candidateUserIds TEXT[], p_authMethod "IdpProvider", '
     'p_expiresAt TIMESTAMPTZ', None,
     "Stores the server side of a sign-in in progress under the hash of a value only "
     "the browser's cookie carries.",
     """INSERT INTO tbl_login_states (state_hash, kind, connection_id, nonce, code_verifier,
                                  return_to, candidate_user_ids, auth_method, expires_at)
    VALUES (p_stateHash, p_kind, p_connectionId, p_nonce, p_codeVerifier,
            p_returnTo, p_candidateUserIds, p_authMethod, p_expiresAt)"""),

    ("stp_TakeLoginState", "func",
     'p_stateHash TEXT, p_kind "LoginStateKind"', "SETOF tbl_login_states",
     "Consumes a sign-in state: one atomic DELETE, so a state can be used once and "
     "only before it expires.",
     """DELETE FROM tbl_login_states
    WHERE  state_hash = p_stateHash
      AND  kind       = p_kind
      AND  expires_at > now()
    RETURNING *"""),

    ("stp_CleanupLoginStates", "func", "", "INTEGER",
     "Housekeeping: removes abandoned sign-in states.",
     """WITH del AS (
        DELETE FROM tbl_login_states
        WHERE  expires_at < now()
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

    # ---- rate limiting (shared, cross-instance) ----------------------------
    ("stp_RateLimitHit", "func",
     "p_key TEXT, p_max INTEGER, p_windowSecs INTEGER",
     "TIMESTAMPTZ",
     "Spends one unit against a fixed-window counter and returns NULL when the hit is "
     "allowed, or the window's reset time when it is over p_max (so the caller can set "
     "Retry-After). One atomic upsert: the ON CONFLICT row lock serialises concurrent "
     "hits of the same key across every instance, so N processes share one budget. An "
     "expired window resets to a single hit; otherwise the count rises. Returning the "
     "reset time only on refusal keeps this a single scalar sqlc can type.",
     """INSERT INTO tbl_rate_limit_counters AS c (bucket_key, hits, reset_at)
    VALUES (p_key, 1, now() + make_interval(secs => p_windowSecs))
    ON CONFLICT (bucket_key) DO UPDATE
    SET hits     = CASE WHEN c.reset_at <= now() THEN 1 ELSE c.hits + 1 END,
        reset_at = CASE WHEN c.reset_at <= now()
                        THEN now() + make_interval(secs => p_windowSecs)
                        ELSE c.reset_at END
    RETURNING CASE WHEN c.hits <= p_max THEN NULL ELSE c.reset_at END"""),

    ("stp_CleanupRateLimitCounters", "func", "", "INTEGER",
     "Housekeeping: removes expired rate-limit counters.",
     """WITH del AS (
        DELETE FROM tbl_rate_limit_counters
        WHERE  reset_at < now()
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

    # ---- invitations -------------------------------------------------------
    ("stp_CreateInvitation", "func",
     "p_email TEXT, p_clientId TEXT, p_invitedByUserId TEXT, p_invitedByOwnerId TEXT, "
     "p_tokenHash TEXT, p_expiresAt TIMESTAMPTZ", "SETOF tbl_invitations",
     "Issues an invitation, from a tenant Admin or from an Owner. Only the token's "
     "SHA-256 is stored; the raw value exists solely in the email that was sent, so "
     "a database leak yields nothing redeemable. The address is lower-cased for "
     "index alignment. An invitation to this address still marked PENDING but past "
     "its expiry is marked EXPIRED first -- the sweep may not have reached it yet -- "
     "so that UQ_tbl_invitations_client_email_pending refuses only a live one: a "
     "second live invitation to the address raises 23505, which the caller maps "
     "to 409.",
     """UPDATE tbl_invitations
    SET    status = 'EXPIRED'
    WHERE  client_id    = p_clientId
      AND  lower(email) = lower(p_email)
      AND  status       = 'PENDING'
      AND  expires_at  <= now();

    INSERT INTO tbl_invitations (email, client_id, invited_by_user_id, invited_by_owner_id,
                                 token_hash, expires_at)
    VALUES (lower(p_email), p_clientId, p_invitedByUserId, p_invitedByOwnerId,
            p_tokenHash, p_expiresAt)
    RETURNING *"""),

    ("stp_CreateInvitationGroup", "proc",
     "p_invitationId TEXT, p_clientId TEXT, p_groupId TEXT", None,
     "Attaches one group to an invitation, inside the same transaction as the "
     "invitation itself, so a committed invitation always carries what it offered.",
     """INSERT INTO tbl_invitation_groups (invitation_id, client_id, group_id)
    VALUES (p_invitationId, p_clientId, p_groupId)"""),

    ("stp_RevokeInvitation", "func",
     "p_invitationId TEXT, p_clientId TEXT, p_revokedByUserId TEXT", "INTEGER",
     "Cancels a pending invitation. Guarded on status = 'PENDING' so an already "
     "accepted or revoked invitation is not silently re-stamped, and tenant-scoped "
     "so a foreign id affects nothing and reports 404.",
     """WITH upd AS (
        UPDATE tbl_invitations
        SET    status             = 'REVOKED',
               revoked_at         = now(),
               revoked_by_user_id = p_revokedByUserId,
               updated_at         = now()
        WHERE  id        = p_invitationId
          AND  client_id = p_clientId
          AND  status    = 'PENDING'
        RETURNING 1
    )
    SELECT count(*)::int FROM upd"""),

    ("stp_ClaimInvitation", "func",
     "p_tokenHash TEXT, p_acceptedByUserId TEXT DEFAULT NULL", "SETOF tbl_invitations",
     "Redeems an invitation in ONE atomic statement, guarded on PENDING and not "
     "expired, so two concurrent acceptances cannot both create an account. "
     "p_acceptedByUserId is NULL on the registration path, where the user does not "
     "exist yet and is linked afterwards by stp_SetInvitationAcceptedBy.",
     """UPDATE tbl_invitations
    SET    status              = 'ACCEPTED',
           accepted_at         = now(),
           accepted_by_user_id = COALESCE(p_acceptedByUserId, accepted_by_user_id),
           updated_at          = now()
    WHERE  token_hash = p_tokenHash
      AND  status     = 'PENDING'
      AND  expires_at > now()
    RETURNING *"""),

    ("stp_SetInvitationAcceptedBy", "proc",
     "p_invitationId TEXT, p_acceptedByUserId TEXT", None,
     "Links a newly created account back to the invitation it came from. The id is a "
     "trusted server value returned by the claim, never client input.",
     """UPDATE tbl_invitations
    SET    accepted_by_user_id = p_acceptedByUserId,
           updated_at          = now()
    WHERE  id = p_invitationId"""),

    ("stp_ExpireInvitations", "proc",
     "p_batchSize INTEGER DEFAULT 500", None,
     "Scheduled sweep moving lapsed invitations to EXPIRED. Batched to keep the "
     "transaction short. Hygiene only: the pending view already filters on expiry.",
     """UPDATE tbl_invitations
    SET    status = 'EXPIRED'
    WHERE  id IN (
        SELECT i.id
        FROM   tbl_invitations i
        WHERE  i.expires_at < now()
          AND  i.status     = 'PENDING'
        LIMIT  p_batchSize
    )"""),

    # ---- password reset ----------------------------------------------------
    ("stp_CreateResetToken", "func",
     "p_userId TEXT, p_clientId TEXT, p_tokenHash TEXT, p_expiresAt TIMESTAMPTZ, p_createdBy TEXT",
     "SETOF tbl_password_reset_tokens",
     "Mints a reset token, stored as its hash only. The caller deletes any "
     "outstanding token first so exactly one link is ever live -- otherwise "
     "re-issuing would leave an earlier, possibly leaked link redeemable.",
     """INSERT INTO tbl_password_reset_tokens (user_id, client_id, token_hash, expires_at, created_by)
    VALUES (p_userId, p_clientId, p_tokenHash, p_expiresAt, p_createdBy)
    RETURNING *"""),

    ("stp_DeleteUnusedResetTokens", "proc",
     "p_userId TEXT", None,
     "Invalidates every unspent reset token for a user. Used tokens are kept as an "
     "audit record of when a reset actually happened.",
     """DELETE FROM tbl_password_reset_tokens
    WHERE  user_id  = p_userId
      AND  used_at IS NULL"""),

    ("stp_MarkResetTokenUsed", "proc",
     "p_tokenId TEXT", None,
     "Burns a reset token after the password has been changed, inside the same "
     "transaction as that change so the two can never diverge.",
     """UPDATE tbl_password_reset_tokens
    SET    used_at = now()
    WHERE  id = p_tokenId"""),

    # ---- permissions -------------------------------------------------------
    # stp_UpsertProductPermission is plpgsql (see EXPLICIT): it enforces the
    # product's seat_limit after the grant.

    ("stp_DeleteProductPermission", "func",
     "p_userId TEXT, p_clientId TEXT, p_productId TEXT", "INTEGER",
     "Revokes a direct product role, tenant-scoped, and bumps the user's "
     "permissions_version in the same statement. The count lets the caller answer "
     "404 rather than reporting success for a grant that never existed.",
     """WITH del AS (
        DELETE FROM tbl_product_permissions
        WHERE  user_id    = p_userId
          AND  client_id  = p_clientId
          AND  product_id = p_productId
        RETURNING user_id, client_id
    ), bump AS (
        UPDATE tbl_users u
        SET    permissions_version = u.permissions_version + 1
        FROM   del
        WHERE  u.id = del.user_id AND u.client_id = del.client_id
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

    # ---- groups ------------------------------------------------------------
    ("stp_CreateGroup", "func",
     "p_clientId TEXT, p_name TEXT, p_description TEXT", "SETOF tbl_groups",
     "Creates a group. A duplicate name within the tenant raises 23505 via the "
     "case-insensitive unique index, which the caller maps to 409.",
     """INSERT INTO tbl_groups (client_id, name, description)
    VALUES (p_clientId, p_name, p_description)
    RETURNING *"""),

    ("stp_UpdateGroup", "func",
     "p_groupId TEXT, p_clientId TEXT, p_name TEXT, p_description TEXT", "SETOF tbl_groups",
     "Renames or re-describes a group, tenant-scoped. System groups are excluded: "
     "zero rows means unknown, another tenant's, or a system group.",
     """UPDATE tbl_groups
    SET    name        = p_name,
           description = p_description,
           updated_at  = now()
    WHERE  id          = p_groupId
      AND  client_id   = p_clientId
      AND  system_key IS NULL
    RETURNING *"""),

    ("stp_DeleteGroup", "func",
     "p_groupId TEXT, p_clientId TEXT", "INTEGER",
     "Deletes a group; its scopes, grants, memberships and managers cascade. "
     "Tenant-scoped, and never a system group. Everyone it touched is bumped ONCE, in "
     "the same statement: a former member's permissions_version and admin_version "
     "(what the group granted stops applying at their next token, not whenever the "
     "old one expires), a former manager's admin_version (they no longer run it). "
     "Members and managers are merged first, so someone who was both gets one bump "
     "of each version, not two -- and never loses one to a second UPDATE of the same "
     "row. (All the CTEs share one snapshot, so they still see the rows the delete "
     "cascades away.)",
     """WITH touched AS (
        SELECT t.user_id, t.client_id, bool_or(t.is_member) AS is_member
        FROM  (SELECT ug.user_id, ug.client_id, true AS is_member
               FROM   tbl_user_groups ug
               WHERE  ug.group_id  = p_groupId
                 AND  ug.client_id = p_clientId
               UNION ALL
               SELECT gm.user_id, gm.client_id, false
               FROM   tbl_group_managers gm
               WHERE  gm.group_id  = p_groupId
                 AND  gm.client_id = p_clientId) t
        GROUP  BY t.user_id, t.client_id
    ), del AS (
        DELETE FROM tbl_groups
        WHERE  id          = p_groupId
          AND  client_id   = p_clientId
          AND  system_key IS NULL
        RETURNING 1
    ), bump AS (
        UPDATE tbl_users u
        SET    permissions_version = u.permissions_version
                                     + CASE WHEN t.is_member THEN 1 ELSE 0 END,
               admin_version       = u.admin_version + 1
        FROM   touched t
        WHERE  u.id        = t.user_id
          AND  u.client_id = t.client_id
          AND  EXISTS (SELECT 1 FROM del)
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

    # stp_AddGroupMember is plpgsql (see EXPLICIT): joining a group grants its
    # products, so it enforces each granted product's seat_limit.

    ("stp_SetGroupLoginPolicy", "func",
     "p_groupId TEXT, p_clientId TEXT, p_policyId TEXT", "INTEGER",
     "Assigns a group a login policy, or clears it with NULL. The composite key "
     "refuses another tenant's policy.",
     """WITH upd AS (
        UPDATE tbl_groups
        SET    login_policy_id = p_policyId,
               updated_at      = now()
        WHERE  id        = p_groupId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int FROM upd"""),

    # ---- login policies ----------------------------------------------------
    ("stp_CreateLoginPolicy", "func",
     "p_clientId TEXT, p_name TEXT, p_allowPassword BOOLEAN, p_allowGoogle BOOLEAN, "
     "p_ssoConnectionId TEXT, p_priority INTEGER", "SETOF tbl_login_policies",
     "Creates a (non-default) login policy. A duplicate name or priority raises 23505; "
     "a policy allowing no method is refused by its CHECK.",
     """INSERT INTO tbl_login_policies (client_id, name, allow_password, allow_google,
                                    sso_connection_id, priority)
    VALUES (p_clientId, p_name, p_allowPassword, p_allowGoogle, p_ssoConnectionId, p_priority)
    RETURNING *"""),

    ("stp_UpdateLoginPolicy", "func",
     "p_policyId TEXT, p_clientId TEXT, p_name TEXT, p_allowPassword BOOLEAN, "
     "p_allowGoogle BOOLEAN, p_ssoConnectionId TEXT, p_priority INTEGER", "SETOF tbl_login_policies",
     "Updates a login policy, tenant-scoped.",
     """UPDATE tbl_login_policies
    SET    name              = p_name,
           allow_password    = p_allowPassword,
           allow_google      = p_allowGoogle,
           sso_connection_id = p_ssoConnectionId,
           priority          = p_priority,
           updated_at        = now()
    WHERE  id        = p_policyId
      AND  client_id = p_clientId
    RETURNING *"""),

    ("stp_DeleteLoginPolicy", "func",
     "p_policyId TEXT, p_clientId TEXT", "INTEGER",
     "Deletes a login policy. Never the default, and a policy still assigned to a "
     "user or group is refused by its foreign keys (23503).",
     """WITH del AS (
        DELETE FROM tbl_login_policies
        WHERE  id         = p_policyId
          AND  client_id  = p_clientId
          AND  is_default = false
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

    # ---- sso ---------------------------------------------------------------
    ("stp_CreateSsoConnection", "func",
     "p_connectionId TEXT, p_clientId TEXT, p_name TEXT, p_issuer TEXT, p_oidcClientId TEXT, "
     "p_secretCiphertext BYTEA, p_secretKeyId TEXT, p_scopes TEXT, p_trustUnverifiedEmail BOOLEAN, "
     "p_isActive BOOLEAN", "SETOF tbl_sso_connections",
     "Registers a tenant's OIDC identity provider. The id is chosen by the caller "
     "because the secret is encrypted with the id as associated data before it "
     "reaches the database.",
     """INSERT INTO tbl_sso_connections (id, client_id, name, issuer, oidc_client_id,
                                     client_secret_ciphertext, secret_key_id, scopes,
                                     trust_unverified_email, is_active)
    VALUES (p_connectionId, p_clientId, p_name, p_issuer, p_oidcClientId,
            p_secretCiphertext, p_secretKeyId, p_scopes, p_trustUnverifiedEmail, p_isActive)
    RETURNING *"""),

    ("stp_UpdateSsoConnection", "func",
     "p_connectionId TEXT, p_clientId TEXT, p_name TEXT, p_issuer TEXT, p_oidcClientId TEXT, "
     "p_secretCiphertext BYTEA, p_secretKeyId TEXT, p_scopes TEXT, p_trustUnverifiedEmail BOOLEAN, "
     "p_isActive BOOLEAN", "SETOF tbl_sso_connections",
     "Updates a connection, tenant-scoped. A NULL secret keeps the stored one, so "
     "editing other fields never requires re-entering it.",
     """UPDATE tbl_sso_connections
    SET    name                     = p_name,
           issuer                   = p_issuer,
           oidc_client_id           = p_oidcClientId,
           client_secret_ciphertext = COALESCE(p_secretCiphertext, client_secret_ciphertext),
           secret_key_id            = COALESCE(p_secretKeyId, secret_key_id),
           scopes                   = p_scopes,
           trust_unverified_email   = p_trustUnverifiedEmail,
           is_active                = p_isActive,
           updated_at               = now()
    WHERE  id        = p_connectionId
      AND  client_id = p_clientId
    RETURNING *"""),

    # ---- API clients -------------------------------------------------------
    ("stp_CreateApiClient", "func",
     "p_clientId TEXT, p_name TEXT, p_description TEXT, p_createdByUserId TEXT, p_createdByOwnerId TEXT",
     "SETOF tbl_api_clients",
     "Creates an API client in a tenant, by a user of that tenant or by an Owner. It "
     "starts with no scopes, no products and no secret, so it can do nothing until each "
     "is chosen. A name already used in the tenant raises 23505.",
     """INSERT INTO tbl_api_clients (client_id, name, description, created_by_user_id, created_by_owner_id)
    VALUES (p_clientId, p_name, p_description, p_createdByUserId, p_createdByOwnerId)
    RETURNING *"""),

    ("stp_UpdateApiClient", "func",
     "p_apiClientId TEXT, p_clientId TEXT, p_name TEXT, p_description TEXT, p_isActive BOOLEAN",
     "SETOF tbl_api_clients",
     "Renames, re-describes, or switches an API client on or off, tenant-scoped: another "
     "tenant's id yields no rows. A switched-off client gets no token, whatever its "
     "secrets.",
     """UPDATE tbl_api_clients
    SET    name        = p_name,
           description = p_description,
           is_active   = p_isActive,
           updated_at  = now()
    WHERE  id        = p_apiClientId
      AND  client_id = p_clientId
    RETURNING *"""),

    ("stp_DeleteApiClient", "func",
     "p_apiClientId TEXT, p_clientId TEXT", "INTEGER",
     "Deletes an API client, and with it its scopes, products and secrets, tenant-"
     "scoped. The audit trail keeps what it was: its rows name the client in their "
     "metadata, not by a key.",
     """WITH del AS (
        DELETE FROM tbl_api_clients
        WHERE  id        = p_apiClientId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

    ("stp_RevokeApiClientSecret", "func",
     "p_secretId TEXT, p_apiClientId TEXT, p_clientId TEXT", "INTEGER",
     "Revokes one secret by stamping revoked_at, tenant-scoped and guarded on not yet "
     "revoked, so an unknown, another tenant's or an already revoked secret reports 0.",
     """WITH upd AS (
        UPDATE tbl_api_client_secrets
        SET    revoked_at = now()
        WHERE  id            = p_secretId
          AND  api_client_id = p_apiClientId
          AND  client_id     = p_clientId
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM upd"""),

    ("stp_TouchApiClientSecret", "proc",
     "p_secretId TEXT, p_apiClientId TEXT", None,
     "Stamps when a secret, and its API client, last earned a token -- at most once a "
     "minute each, so a busy client does not turn every token into a write.",
     """UPDATE tbl_api_client_secrets
    SET    last_used_at = now()
    WHERE  id            = p_secretId
      AND  api_client_id = p_apiClientId
      AND  (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');
    UPDATE tbl_api_clients
    SET    last_used_at = now()
    WHERE  id = p_apiClientId
      AND  (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')"""),

    # ---- audit -------------------------------------------------------------
    ("stp_InsertAuditLog", "proc",
     "p_clientId TEXT, p_actorUserId TEXT, p_eventType TEXT, p_eventMetadata JSONB, "
     "p_ipAddress TEXT, p_userAgent TEXT, p_requestId TEXT", None,
     "Appends an audit record. INSERT-only by design: no procedure in this schema "
     "updates or deletes tbl_audit_logs, which is what makes the trail trustworthy.",
     """INSERT INTO tbl_audit_logs (client_id, actor_user_id, event_type, event_metadata,
                                ip_address, user_agent, request_id)
    VALUES (p_clientId, p_actorUserId, p_eventType, p_eventMetadata,
            p_ipAddress, p_userAgent, p_requestId)"""),
]

# Writes that need a guard or several dependent statements, written out in full.
EXPLICIT = {
    "stp_CreateUser": '''/****** Object: Stored Procedure [stp_CreateUser] ******/
-- Creates a member. The address is stored lower-cased so it is aligned with the
-- case-insensitive unique index; inserting mixed case would let two rows differ
-- only by case and defeat that index. A duplicate live address raises 23505,
-- which the caller maps to 409.
--
-- SEAT LIMIT: a company's max_seats caps its ACTIVE members (is_active AND not
-- deleted). The company row is locked FOR UPDATE first, so two concurrent
-- invitation accepts serialise here and cannot both slip under the cap; over the
-- limit raises SQLSTATE AL001, which the API maps to 409. A NULL max_seats is
-- unlimited. plpgsql (not plain SQL) because the guard needs the lock and a
-- conditional RAISE.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateUser(p_clientId TEXT, p_email TEXT, p_passwordHash TEXT, p_accountType "AccountType")
RETURNS SETOF tbl_users
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_max   INTEGER;
    v_count INTEGER;
BEGIN
    SELECT max_seats INTO v_max FROM tbl_clients WHERE id = p_clientId FOR UPDATE;

    IF v_max IS NOT NULL THEN
        SELECT count(*) INTO v_count
        FROM   tbl_users
        WHERE  client_id  = p_clientId
          AND  deleted_at IS NULL
          AND  is_active;
        IF v_count >= v_max THEN
            RAISE EXCEPTION 'company % is at its seat limit of %', p_clientId, v_max
                USING ERRCODE = 'AL001';
        END IF;
    END IF;

    RETURN QUERY
    INSERT INTO tbl_users (client_id, email, password_hash, account_type)
    VALUES (p_clientId, lower(p_email), p_passwordHash, p_accountType)
    RETURNING *;
END;
$$;
''',

    "stp_SetUserActive": '''/****** Object: Stored Procedure [stp_SetUserActive] ******/
-- Enables or disables a member, tenant-scoped. Returns the affected-row count so
-- the caller can answer 404 for an unknown or another tenant's user rather than
-- silently reporting success.
--
-- SEAT LIMIT: reactivating a member consumes a seat, so enabling one is capped by
-- the company's max_seats exactly as creation is. The OTHER active members are
-- counted (id <> p_userId) under the company row lock, so re-enabling an already
-- active member is never refused and concurrent re-activations cannot overshoot.
-- Over the limit raises SQLSTATE AL001 (409); a NULL max_seats is unlimited.
-- plpgsql because of the guard.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetUserActive(p_userId TEXT, p_clientId TEXT, p_isActive BOOLEAN)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_max   INTEGER;
    v_count INTEGER;
    v_n     INTEGER;
BEGIN
    IF p_isActive THEN
        SELECT max_seats INTO v_max FROM tbl_clients WHERE id = p_clientId FOR UPDATE;
        IF v_max IS NOT NULL THEN
            SELECT count(*) INTO v_count
            FROM   tbl_users
            WHERE  client_id  = p_clientId
              AND  deleted_at IS NULL
              AND  is_active
              AND  id <> p_userId;
            IF v_count >= v_max THEN
                RAISE EXCEPTION 'company % is at its seat limit of %', p_clientId, v_max
                    USING ERRCODE = 'AL001';
            END IF;
        END IF;
    END IF;

    WITH upd AS (
        UPDATE tbl_users
        SET    is_active  = p_isActive,
               updated_at = now()
        WHERE  id        = p_userId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int INTO v_n FROM upd;
    RETURN v_n;
END;
$$;
''',

    "stp_AssertProductSeat": '''/****** Object: Stored Procedure [stp_AssertProductSeat] ******/
-- Enforces a product subscription's seat_limit: the number of DISTINCT people who
-- may currently open the product (vw_EffectiveProductRole) must not exceed it.
-- Called by every mutation that can widen product access, AFTER it has made its
-- change, so it checks the resulting state directly. The subscription row is
-- locked FOR UPDATE first, so concurrent seat-consuming changes to the same
-- product serialise here and cannot both slip under the cap. A NULL seat_limit,
-- or no subscription row, is unlimited. Over the limit raises SQLSTATE AL001,
-- which the API maps to 409.
--
-- Implemented as a FUNCTION returning void: callers PERFORM it for its effect.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_AssertProductSeat(p_clientId TEXT, p_productId TEXT)
RETURNS void
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_limit INTEGER;
    v_count INTEGER;
BEGIN
    SELECT seat_limit INTO v_limit
    FROM   tbl_client_products
    WHERE  client_id = p_clientId AND product_id = p_productId
    FOR    UPDATE;

    IF v_limit IS NULL THEN
        RETURN;  -- no subscription row, or an unlimited one
    END IF;

    SELECT count(DISTINCT user_id) INTO v_count
    FROM   vw_EffectiveProductRole
    WHERE  client_id = p_clientId AND product_id = p_productId;

    IF v_count > v_limit THEN
        RAISE EXCEPTION 'product % in company % is at its seat limit of %', p_productId, p_clientId, v_limit
            USING ERRCODE = 'AL001';
    END IF;
END;
$$;
''',

    "stp_UpsertProductPermission": '''/****** Object: Stored Procedure [stp_UpsertProductPermission] ******/
-- Grants or re-grants a DIRECT product role, and bumps the user's
-- permissions_version in the same statement. ON CONFLICT on the natural key makes
-- a regrant idempotent instead of raising a duplicate-key error; the composite
-- keys refuse an unsubscribed product and an unknown role.
--
-- SEAT LIMIT: after the grant, the product's seat_limit is enforced
-- (stp_AssertProductSeat) in the same transaction, so a grant that would let one
-- person too many open the product is rolled back as 409.
--
-- Implemented as a PROCEDURE: nothing is returned, so the caller invokes it with
-- CALL. plpgsql (not plain SQL) because of the seat guard.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_UpsertProductPermission(p_userId TEXT, p_clientId TEXT, p_productId TEXT, p_roleName TEXT, p_grantedBy TEXT)
LANGUAGE plpgsql
AS $$
BEGIN
    WITH up AS (
        INSERT INTO tbl_product_permissions (user_id, client_id, product_id, role_name, granted_by)
        VALUES (p_userId, p_clientId, p_productId, p_roleName, p_grantedBy)
        ON CONFLICT (user_id, client_id, product_id)
        DO UPDATE SET role_name  = EXCLUDED.role_name,
                      granted_by = EXCLUDED.granted_by
        RETURNING user_id, client_id
    )
    UPDATE tbl_users u
    SET    permissions_version = u.permissions_version + 1
    FROM   up
    WHERE  u.id = up.user_id AND u.client_id = up.client_id;

    PERFORM stp_AssertProductSeat(p_clientId, p_productId);
END;
$$;
''',

    "stp_AddGroupMember": '''/****** Object: Stored Procedure [stp_AddGroupMember] ******/
-- Adds a member and bumps their permissions_version and admin_version in the same
-- statement, so the membership and the signal that their tokens are stale cannot
-- come apart. A duplicate raises 23505 on the composite primary key, and the
-- composite tenant foreign keys independently refuse a user or group from another
-- organisation even if the caller's checks were bypassed.
--
-- SEAT LIMIT: joining a group grants the member every product the group confers,
-- so after the insert each such product's seat_limit is enforced
-- (stp_AssertProductSeat), in product-id order so concurrent adds take the
-- subscription locks in a consistent order. Over a limit rolls the join back as 409.
--
-- Implemented as a PROCEDURE: nothing is returned, so the caller invokes it with
-- CALL. plpgsql (not plain SQL) because of the seat guard.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_AddGroupMember(p_userId TEXT, p_groupId TEXT, p_clientId TEXT, p_assignedBy TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_pid TEXT;
BEGIN
    WITH ins AS (
        INSERT INTO tbl_user_groups (user_id, group_id, client_id, assigned_by)
        VALUES (p_userId, p_groupId, p_clientId, p_assignedBy)
        RETURNING user_id, client_id
    )
    UPDATE tbl_users u
    SET    permissions_version = u.permissions_version + 1,
           admin_version       = u.admin_version + 1
    FROM   ins
    WHERE  u.id = ins.user_id AND u.client_id = ins.client_id;

    FOR v_pid IN
        SELECT product_id FROM tbl_group_product_grants
        WHERE  group_id = p_groupId AND client_id = p_clientId
        ORDER  BY product_id
    LOOP
        PERFORM stp_AssertProductSeat(p_clientId, v_pid);
    END LOOP;
END;
$$;
''',

    "stp_SetGroupScopes": '''/****** Object: Stored Procedure [stp_SetGroupScopes] ******/
-- Replaces the App Central scopes a group gives its members, wholesale, so the
-- caller submits the complete desired state instead of computing a diff.
--
-- Tenant scoping is ENFORCED HERE rather than assumed: the group is looked up
-- by (id, tenant), so a group of another organisation changes nothing (-1).
-- A system group is refused (-3): the Admins group holds every scope by
-- definition and has none to set. An unknown scope, or an API client's scope,
-- fails the foreign key into tbl_scopes.
--
-- Every member's admin_version is bumped, in this same transaction: their login
-- tokens describe access they no longer have (or lack access they now have).
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetGroupScopes(
    p_groupId  TEXT,
    p_clientId TEXT,
    p_scopes   TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_found    BOOLEAN;
    v_system   TEXT;
    v_inserted INTEGER := 0;
BEGIN
    SELECT true, g.system_key INTO v_found, v_system
    FROM   tbl_groups g
    WHERE  g.id = p_groupId AND g.client_id = p_clientId
    FOR    UPDATE;

    IF v_found IS NULL THEN
        RETURN -1;  -- -1 = group not found in this tenant
    END IF;
    IF v_system IS NOT NULL THEN
        RETURN -3;  -- -3 = a system group, which holds every scope already
    END IF;

    DELETE FROM tbl_group_scopes WHERE group_id = p_groupId AND client_id = p_clientId;

    IF p_scopes IS NOT NULL AND cardinality(p_scopes) > 0 THEN
        INSERT INTO tbl_group_scopes (group_id, client_id, scope)
        SELECT DISTINCT p_groupId, p_clientId, s
        FROM   unnest(p_scopes) AS s;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
    END IF;

    UPDATE tbl_users u
    SET    admin_version = u.admin_version + 1
    FROM   tbl_user_groups ug
    WHERE  ug.group_id  = p_groupId
      AND  ug.client_id = p_clientId
      AND  u.id         = ug.user_id
      AND  u.client_id  = ug.client_id;

    RETURN v_inserted;  -- >= 0 = number of scopes the group now gives
END;
$$;
''',

    "stp_SetUserScopes": '''/****** Object: Stored Procedure [stp_SetUserScopes] ******/
-- Replaces the EXTRA App Central scopes given to one person -- what they hold on
-- top of their groups -- wholesale. Scopes kept from the previous set keep their
-- original attribution; scopes dropped are removed; new ones are recorded as
-- given by p_grantedByUserId (a user of the same tenant) or p_grantedByOwnerId
-- (an Owner), at most one of which is set.
--
-- The user is looked up by (id, tenant) and must be live: another tenant's user
-- or a deleted one changes nothing (-1). An unknown scope, or an API client's
-- scope, fails the foreign key into tbl_scopes.
--
-- The user's admin_version is bumped in this same transaction.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetUserScopes(
    p_userId           TEXT,
    p_clientId         TEXT,
    p_scopes           TEXT[],
    p_grantedByUserId  TEXT,
    p_grantedByOwnerId TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_held INTEGER := 0;
BEGIN
    PERFORM 1
    FROM   tbl_users u
    WHERE  u.id = p_userId AND u.client_id = p_clientId AND u.deleted_at IS NULL
    FOR    UPDATE;

    IF NOT FOUND THEN
        RETURN -1;  -- -1 = no such live user in this tenant
    END IF;

    DELETE FROM tbl_user_scopes
    WHERE  user_id   = p_userId
      AND  client_id = p_clientId
      AND  (p_scopes IS NULL OR NOT (scope = ANY (p_scopes)));

    IF p_scopes IS NOT NULL AND cardinality(p_scopes) > 0 THEN
        INSERT INTO tbl_user_scopes (user_id, client_id, scope, granted_by_user_id, granted_by_owner_id)
        SELECT DISTINCT p_userId, p_clientId, s, p_grantedByUserId, p_grantedByOwnerId
        FROM   unnest(p_scopes) AS s
        ON CONFLICT (user_id, scope) DO NOTHING;
    END IF;

    SELECT count(*)::int INTO v_held
    FROM   tbl_user_scopes
    WHERE  user_id = p_userId AND client_id = p_clientId;

    UPDATE tbl_users
    SET    admin_version = admin_version + 1
    WHERE  id = p_userId AND client_id = p_clientId;

    RETURN v_held;  -- >= 0 = number of extra scopes now held
END;
$$;
''',

    "stp_SetApiClientScopes": '''/****** Object: Stored Procedure [stp_SetApiClientScopes] ******/
-- Replaces where an API client's credential may be used -- its CLIENT scopes --
-- wholesale, so the caller submits the complete desired state.
--
-- The API client is looked up by (id, tenant) and locked: another tenant's
-- changes nothing (-1). An unknown scope, or a person's scope, fails the
-- foreign key into tbl_scopes.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetApiClientScopes(
    p_apiClientId TEXT,
    p_clientId    TEXT,
    p_scopes      TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_inserted INTEGER := 0;
BEGIN
    PERFORM 1
    FROM   tbl_api_clients a
    WHERE  a.id = p_apiClientId AND a.client_id = p_clientId
    FOR    UPDATE;

    IF NOT FOUND THEN
        RETURN -1;  -- -1 = no such API client in this tenant
    END IF;

    DELETE FROM tbl_api_client_scopes
    WHERE  api_client_id = p_apiClientId AND client_id = p_clientId;

    IF p_scopes IS NOT NULL AND cardinality(p_scopes) > 0 THEN
        INSERT INTO tbl_api_client_scopes (api_client_id, client_id, scope)
        SELECT DISTINCT p_apiClientId, p_clientId, s
        FROM   unnest(p_scopes) AS s;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
    END IF;

    UPDATE tbl_api_clients
    SET    updated_at = now()
    WHERE  id = p_apiClientId AND client_id = p_clientId;

    RETURN v_inserted;  -- >= 0 = number of scopes the client now holds
END;
$$;
''',

    "stp_SetApiClientProducts": '''/****** Object: Stored Procedure [stp_SetApiClientProducts] ******/
-- Replaces the products an API client may get a token for, wholesale. A product
-- ADDED to the list must be a live subscription of the tenant (switched on,
-- started, not ended) to an active product that accepts API clients; if one is
-- not, nothing changes (-2). A
-- product already on the list may stay whatever has changed since: it is inert
-- until it is usable again, since every token is checked against the same
-- conditions. Another tenant's API client changes nothing (-1).
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetApiClientProducts(
    p_apiClientId TEXT,
    p_clientId    TEXT,
    p_productIds  TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_wanted TEXT[] := coalesce(p_productIds, '{}'::text[]);
    v_bad    INTEGER;
    v_held   INTEGER;
BEGIN
    PERFORM 1
    FROM   tbl_api_clients a
    WHERE  a.id = p_apiClientId AND a.client_id = p_clientId
    FOR    UPDATE;

    IF NOT FOUND THEN
        RETURN -1;  -- -1 = no such API client in this tenant
    END IF;

    SELECT count(*) INTO v_bad
    FROM   (SELECT DISTINCT w FROM unnest(v_wanted) AS w) wanted
    WHERE  NOT EXISTS (SELECT 1 FROM tbl_api_client_products ap
                       WHERE  ap.api_client_id = p_apiClientId
                         AND  ap.client_id     = p_clientId
                         AND  ap.product_id    = wanted.w)
      AND  NOT EXISTS (SELECT 1
                       FROM   tbl_client_products cp
                       JOIN   tbl_products p ON p.id = cp.product_id
                       WHERE  cp.client_id  = p_clientId
                         AND  cp.product_id = wanted.w
                         AND  cp.is_active
                         AND  cp.starts_at <= now()
                         AND  (cp.ends_at IS NULL OR cp.ends_at > now())
                         AND  p.is_active
                         AND  p.accepts_api_clients);

    IF v_bad > 0 THEN
        RETURN -2;  -- -2 = a product that cannot be added to an API client's list
    END IF;

    DELETE FROM tbl_api_client_products
    WHERE  api_client_id = p_apiClientId
      AND  client_id     = p_clientId
      AND  NOT (product_id = ANY (v_wanted));

    INSERT INTO tbl_api_client_products (api_client_id, client_id, product_id)
    SELECT DISTINCT p_apiClientId, p_clientId, w
    FROM   unnest(v_wanted) AS w
    ON CONFLICT (api_client_id, product_id) DO NOTHING;

    SELECT count(*)::int INTO v_held
    FROM   tbl_api_client_products
    WHERE  api_client_id = p_apiClientId AND client_id = p_clientId;

    UPDATE tbl_api_clients
    SET    updated_at = now()
    WHERE  id = p_apiClientId AND client_id = p_clientId;

    RETURN v_held;  -- >= 0 = number of products on the list
END;
$$;
''',

    "stp_CreateApiClientSecret": '''/****** Object: Stored Procedure [stp_CreateApiClientSecret] ******/
-- Adds a secret to an API client. Only its SHA-256 and a short prefix -- enough
-- to tell two secrets apart on screen, never enough to use -- are stored; the
-- plaintext is shown once, by the caller, and never again.
--
-- At most two secrets are live at a time, so a client rotates without downtime:
-- make a second, deploy it, revoke the first. The API client's row is locked,
-- so two concurrent requests cannot both add a second secret.
--
-- Returns ZERO rows when the API client is not in this tenant, or already has
-- two live secrets; the caller has checked the first, so it reports the second.
-- The row returned is the secret's projection, never its hash.
--
-- Implemented as a FUNCTION: the caller needs the new secret's row.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateApiClientSecret(
    p_apiClientId      TEXT,
    p_clientId         TEXT,
    p_secretHash       TEXT,
    p_prefix           TEXT,
    p_expiresAt        TIMESTAMPTZ,
    p_createdByUserId  TEXT,
    p_createdByOwnerId TEXT
)
RETURNS SETOF vw_ApiClientSecret
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_id TEXT;
BEGIN
    PERFORM 1
    FROM   tbl_api_clients a
    WHERE  a.id = p_apiClientId AND a.client_id = p_clientId
    FOR    UPDATE;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF (SELECT count(*)
        FROM   tbl_api_client_secrets x
        WHERE  x.api_client_id = p_apiClientId
          AND  x.client_id     = p_clientId
          AND  x.revoked_at IS NULL
          AND  (x.expires_at IS NULL OR x.expires_at > now())) >= 2 THEN
        RETURN;
    END IF;

    INSERT INTO tbl_api_client_secrets (api_client_id, client_id, secret_hash, prefix, expires_at,
                                        created_by_user_id, created_by_owner_id)
    VALUES (p_apiClientId, p_clientId, p_secretHash, p_prefix, p_expiresAt,
            p_createdByUserId, p_createdByOwnerId)
    RETURNING id INTO v_id;

    RETURN QUERY SELECT * FROM vw_ApiClientSecret v WHERE v.id = v_id;
END;
$$;
''',

    "stp_CreateClient": '''/****** Object: Stored Procedure [stp_CreateClient] ******/
-- Provisions a tenant TOGETHER WITH the two things every tenant must have: its
-- ADMINS system group and its default login policy. Creating them in the same
-- transaction is what lets the rest of the schema assume they exist.
--
-- domain_verified_at is deliberately NOT settable here: a new tenant starts
-- UNVERIFIED, because a verified domain governs federated-login tenant
-- resolution. At most one tenant may be the platform company.
--
-- Implemented as a FUNCTION: the caller needs the inserted row.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateClient(
    p_name               TEXT,
    p_domain             TEXT,
    p_subscriptionStatus "SubscriptionStatus",
    p_maxSeats           INTEGER,
    p_isActive           BOOLEAN,
    p_isPlatform         BOOLEAN
)
RETURNS SETOF tbl_clients
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_client tbl_clients;
BEGIN
    INSERT INTO tbl_clients (name, domain, subscription_status, max_seats, is_active, is_platform)
    VALUES (p_name, lower(p_domain), p_subscriptionStatus, p_maxSeats, p_isActive, p_isPlatform)
    RETURNING * INTO v_client;

    INSERT INTO tbl_groups (client_id, name, description, system_key)
    VALUES (v_client.id, 'Admins', 'Administrators of this organisation.', 'ADMINS');

    INSERT INTO tbl_login_policies (client_id, name, allow_password, allow_google, priority, is_default)
    VALUES (v_client.id, 'Default', true, true, 0, true);

    RETURN NEXT v_client;
END;
$$;
''',

    "stp_CreateCentralFamily": '''/****** Object: Stored Procedure [stp_CreateCentralFamily] ******/
-- Opens a CENTRAL login at App Central: the family row, which carries how the
-- user authenticated and the absolute cap every refresh is bounded by, and its
-- first refresh-token generation. Only the token's hash is stored.
--
-- Implemented as a FUNCTION: the caller needs the session row (and through it
-- the family id).
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateCentralFamily(
    p_userId            TEXT,
    p_clientId          TEXT,
    p_authMethod        "IdpProvider",
    p_authConnectionId  TEXT,
    p_absoluteExpiresAt TIMESTAMPTZ,
    p_sessionUuid       TEXT,
    p_refreshTokenHash  TEXT,
    p_expiresAt         TIMESTAMPTZ,
    p_ipAddress         TEXT,
    p_deviceLabel       TEXT,
    p_userAgent         TEXT
)
RETURNS SETOF tbl_user_sessions
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_familyId TEXT;
BEGIN
    INSERT INTO tbl_session_families (user_id, client_id, kind, auth_method,
                                      auth_connection_id, absolute_expires_at)
    VALUES (p_userId, p_clientId, 'CENTRAL', p_authMethod,
            p_authConnectionId, p_absoluteExpiresAt)
    RETURNING id INTO v_familyId;

    RETURN QUERY
    INSERT INTO tbl_user_sessions (user_id, client_id, session_uuid, family_id,
                                   refresh_token_hash, expires_at,
                                   ip_address, device_label, user_agent)
    VALUES (p_userId, p_clientId, p_sessionUuid, v_familyId,
            p_refreshTokenHash, LEAST(p_expiresAt, p_absoluteExpiresAt),
            p_ipAddress, p_deviceLabel, p_userAgent)
    RETURNING *;
END;
$$;
''',

    "stp_CreateProductFamily": '''/****** Object: Stored Procedure [stp_CreateProductFamily] ******/
-- Opens a PRODUCT login under a live central login of the SAME user and tenant,
-- inheriting how the user authenticated and the parent's absolute cap: a product
-- can never stay signed in longer than the App Central login it came from.
--
-- Returns ZERO rows when the parent is not a live central login, which the
-- caller treats as "sign in again". The parent row is share-locked while the
-- child is attached, so a concurrent logout cannot slip between the check and
-- the insert.
--
-- Implemented as a FUNCTION: the caller needs the session row.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateProductFamily(
    p_parentFamilyId   TEXT,
    p_userId           TEXT,
    p_clientId         TEXT,
    p_productId        TEXT,
    p_sessionUuid      TEXT,
    p_refreshTokenHash TEXT,
    p_expiresAt        TIMESTAMPTZ,
    p_ipAddress        TEXT,
    p_deviceLabel      TEXT,
    p_userAgent        TEXT
)
RETURNS SETOF tbl_user_sessions
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_parent   tbl_session_families;
    v_familyId TEXT;
BEGIN
    SELECT * INTO v_parent
    FROM   tbl_session_families f
    WHERE  f.id          = p_parentFamilyId
      AND  f.user_id     = p_userId
      AND  f.client_id   = p_clientId
      AND  f.kind        = 'CENTRAL'
      AND  f.revoked_at IS NULL
      AND  f.absolute_expires_at > now()
    FOR    SHARE;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    INSERT INTO tbl_session_families (user_id, client_id, kind, product_id, parent_family_id,
                                      auth_method, auth_connection_id, authenticated_at,
                                      absolute_expires_at)
    VALUES (p_userId, p_clientId, 'PRODUCT', p_productId, p_parentFamilyId,
            v_parent.auth_method, v_parent.auth_connection_id, v_parent.authenticated_at,
            v_parent.absolute_expires_at)
    RETURNING id INTO v_familyId;

    RETURN QUERY
    INSERT INTO tbl_user_sessions (user_id, client_id, session_uuid, family_id,
                                   refresh_token_hash, expires_at,
                                   ip_address, device_label, user_agent)
    VALUES (p_userId, p_clientId, p_sessionUuid, v_familyId,
            p_refreshTokenHash, LEAST(p_expiresAt, v_parent.absolute_expires_at),
            p_ipAddress, p_deviceLabel, p_userAgent)
    RETURNING *;
END;
$$;
''',

    "stp_RemoveGroupMember": '''/****** Object: Stored Procedure [stp_RemoveGroupMember] ******/
-- Removes a member, scoped by user, group and tenant together so a foreign group
-- id removes nothing.
--
-- Refuses (-2) to remove the last ACTIVE member of a tenant's ADMINS group: that
-- would leave the organisation with nobody able to administer it. The group row
-- is locked first, so two concurrent removals of the last two admins serialise
-- and the second sees the first.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RemoveGroupMember(
    p_userId   TEXT,
    p_groupId  TEXT,
    p_clientId TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_system  TEXT;
    v_removed INTEGER;
BEGIN
    SELECT g.system_key INTO v_system
    FROM   tbl_groups g
    WHERE  g.id = p_groupId AND g.client_id = p_clientId
    FOR    UPDATE;

    IF v_system = 'ADMINS'
       AND EXISTS (SELECT 1 FROM tbl_user_groups
                   WHERE  group_id = p_groupId AND client_id = p_clientId AND user_id = p_userId)
       AND NOT EXISTS (
            SELECT 1
            FROM   tbl_user_groups ug
            JOIN   tbl_users u ON u.id = ug.user_id AND u.client_id = ug.client_id
            WHERE  ug.group_id   = p_groupId
              AND  ug.client_id  = p_clientId
              AND  ug.user_id   <> p_userId
              AND  u.deleted_at IS NULL
              AND  u.is_active   = true) THEN
        RETURN -2;  -- -2 = this is the last active Admin
    END IF;

    DELETE FROM tbl_user_groups
    WHERE  user_id   = p_userId
      AND  group_id  = p_groupId
      AND  client_id = p_clientId;
    GET DIAGNOSTICS v_removed = ROW_COUNT;

    -- Same transaction as the removal: what the group granted stops applying at
    -- the member's next token.
    IF v_removed > 0 THEN
        UPDATE tbl_users
        SET    permissions_version = permissions_version + 1,
               admin_version       = admin_version + 1
        WHERE  id = p_userId AND client_id = p_clientId;
    END IF;
    RETURN v_removed;
END;
$$;
''',

    "stp_AddGroupManager": '''/****** Object: Stored Procedure [stp_AddGroupManager] ******/
-- Appoints a manager of a group: someone who may add and remove its members and
-- nothing else. The group is looked up by (id, tenant): -1 when it is not in
-- this tenant. A system group never has managers (-2): whoever could change the
-- Admins group's members could make anyone an Admin. The appointee must be a
-- live user of the tenant (-3); the composite keys refuse another tenant's user
-- anyway, and a CHECK refuses anyone appointing themselves.
--
-- Returns 1 when appointed, 0 when they already manage it. An appointment bumps
-- the appointee's admin_version in this same transaction: their login token
-- describes what they may do in App Central, and it is now out of date.
--
-- The group row is share-locked, so it cannot be deleted mid-appointment.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_AddGroupManager(
    p_groupId   TEXT,
    p_clientId  TEXT,
    p_userId    TEXT,
    p_byUserId  TEXT,
    p_byOwnerId TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_system TEXT;
    v_added  INTEGER;
BEGIN
    SELECT g.system_key INTO v_system
    FROM   tbl_groups g
    WHERE  g.id = p_groupId AND g.client_id = p_clientId
    FOR    SHARE;
    IF NOT FOUND THEN
        RETURN -1;  -- -1 = no such group in this tenant
    END IF;
    IF v_system IS NOT NULL THEN
        RETURN -2;  -- -2 = a system group
    END IF;
    PERFORM 1 FROM tbl_users u
    WHERE  u.id = p_userId AND u.client_id = p_clientId AND u.deleted_at IS NULL;
    IF NOT FOUND THEN
        RETURN -3;  -- -3 = no such live user in this tenant
    END IF;

    INSERT INTO tbl_group_managers (group_id, client_id, user_id,
                                    appointed_by_user_id, appointed_by_owner_id)
    VALUES (p_groupId, p_clientId, p_userId, p_byUserId, p_byOwnerId)
    ON CONFLICT (group_id, user_id) DO NOTHING;
    GET DIAGNOSTICS v_added = ROW_COUNT;

    IF v_added > 0 THEN
        UPDATE tbl_users
        SET    admin_version = admin_version + 1
        WHERE  id = p_userId AND client_id = p_clientId;
    END IF;
    RETURN v_added;
END;
$$;
''',

    "stp_RemoveGroupManager": '''/****** Object: Stored Procedure [stp_RemoveGroupManager] ******/
-- Dismisses a group's manager, scoped by group, user and tenant together, so a
-- foreign id removes nothing. Returns 1 when dismissed, 0 when they did not
-- manage it, -1 when the group is not in this tenant.
--
-- The group row is locked FOR UPDATE first. A manager's membership change
-- (stp_ManagerAddGroupMember, stp_ManagerRemoveGroupMember) share-locks the same
-- row and only then checks that its caller still manages the group, so the two
-- serialise: a manager dismissed a moment ago cannot slip one more change in.
--
-- A dismissal bumps the former manager's admin_version in this same
-- transaction.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RemoveGroupManager(
    p_groupId  TEXT,
    p_clientId TEXT,
    p_userId   TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_removed INTEGER;
BEGIN
    PERFORM 1 FROM tbl_groups g
    WHERE  g.id = p_groupId AND g.client_id = p_clientId
    FOR    UPDATE;
    IF NOT FOUND THEN
        RETURN -1;  -- -1 = no such group in this tenant
    END IF;

    DELETE FROM tbl_group_managers
    WHERE  group_id  = p_groupId
      AND  client_id = p_clientId
      AND  user_id   = p_userId;
    GET DIAGNOSTICS v_removed = ROW_COUNT;

    IF v_removed > 0 THEN
        UPDATE tbl_users
        SET    admin_version = admin_version + 1
        WHERE  id = p_userId AND client_id = p_clientId;
    END IF;
    RETURN v_removed;
END;
$$;
''',

    "stp_ManagerAddGroupMember": '''/****** Object: Stored Procedure [stp_ManagerAddGroupMember] ******/
-- A group's manager adds a member. The API has already checked that the caller
-- manages the group; this checks again at the moment of the change, so a
-- manager dismissed after their request began is still refused:
--
--   * the group row is share-locked, which waits for a dismissal holding it
--     (stp_RemoveGroupManager locks it FOR UPDATE);
--   * then, in a NEW statement -- so a dismissal that has just committed is
--     seen -- the caller must still manage the group (-1 otherwise, and when
--     the group is not in this tenant).
--
-- Also refused: a system group (-2; it never has managers, so this is defence
-- in depth); one of the group's own managers as the member, the caller
-- included (-3: managers do not decide their own or each other's membership);
-- and anyone who is not a live user of the tenant (-4).
--
-- Returns 1 when added, 0 when already a member. The member's
-- permissions_version and admin_version are bumped in this same transaction.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_ManagerAddGroupMember(
    p_managerId TEXT,
    p_userId    TEXT,
    p_groupId   TEXT,
    p_clientId  TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_system TEXT;
    v_added  INTEGER;
    v_pid    TEXT;
BEGIN
    SELECT g.system_key INTO v_system
    FROM   tbl_groups g
    WHERE  g.id = p_groupId AND g.client_id = p_clientId
    FOR    SHARE;
    IF NOT FOUND THEN
        RETURN -1;
    END IF;
    PERFORM 1 FROM tbl_group_managers gm
    WHERE  gm.group_id = p_groupId AND gm.client_id = p_clientId AND gm.user_id = p_managerId;
    IF NOT FOUND THEN
        RETURN -1;  -- -1 = the caller does not manage this group
    END IF;
    IF v_system IS NOT NULL THEN
        RETURN -2;  -- -2 = a system group
    END IF;
    PERFORM 1 FROM tbl_group_managers gm
    WHERE  gm.group_id = p_groupId AND gm.client_id = p_clientId AND gm.user_id = p_userId;
    IF FOUND THEN
        RETURN -3;  -- -3 = the member would be one of the group's managers
    END IF;
    PERFORM 1 FROM tbl_users u
    WHERE  u.id = p_userId AND u.client_id = p_clientId AND u.deleted_at IS NULL;
    IF NOT FOUND THEN
        RETURN -4;  -- -4 = no such live user in this tenant
    END IF;

    INSERT INTO tbl_user_groups (user_id, group_id, client_id, assigned_by)
    VALUES (p_userId, p_groupId, p_clientId, p_managerId)
    ON CONFLICT (user_id, group_id) DO NOTHING;
    GET DIAGNOSTICS v_added = ROW_COUNT;

    IF v_added > 0 THEN
        UPDATE tbl_users
        SET    permissions_version = permissions_version + 1,
               admin_version       = admin_version + 1
        WHERE  id = p_userId AND client_id = p_clientId;

        -- Joining the group grants its products; hold each one's seat_limit.
        FOR v_pid IN
            SELECT product_id FROM tbl_group_product_grants
            WHERE  group_id = p_groupId AND client_id = p_clientId
            ORDER  BY product_id
        LOOP
            PERFORM stp_AssertProductSeat(p_clientId, v_pid);
        END LOOP;
    END IF;
    RETURN v_added;
END;
$$;
''',

    "stp_ManagerRemoveGroupMember": '''/****** Object: Stored Procedure [stp_ManagerRemoveGroupMember] ******/
-- A group's manager removes a member, with the same checks at the moment of the
-- change as stp_ManagerAddGroupMember: the caller must still manage the group
-- (-1), never a system group (-2), never one of the group's managers, the
-- caller included (-3). Returns 1 when removed, 0 when they were not a member;
-- the member's versions are bumped in this same transaction.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_ManagerRemoveGroupMember(
    p_managerId TEXT,
    p_userId    TEXT,
    p_groupId   TEXT,
    p_clientId  TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_system  TEXT;
    v_removed INTEGER;
BEGIN
    SELECT g.system_key INTO v_system
    FROM   tbl_groups g
    WHERE  g.id = p_groupId AND g.client_id = p_clientId
    FOR    SHARE;
    IF NOT FOUND THEN
        RETURN -1;
    END IF;
    PERFORM 1 FROM tbl_group_managers gm
    WHERE  gm.group_id = p_groupId AND gm.client_id = p_clientId AND gm.user_id = p_managerId;
    IF NOT FOUND THEN
        RETURN -1;  -- -1 = the caller does not manage this group
    END IF;
    IF v_system IS NOT NULL THEN
        RETURN -2;  -- -2 = a system group
    END IF;
    PERFORM 1 FROM tbl_group_managers gm
    WHERE  gm.group_id = p_groupId AND gm.client_id = p_clientId AND gm.user_id = p_userId;
    IF FOUND THEN
        RETURN -3;  -- -3 = the member is one of the group's managers
    END IF;

    DELETE FROM tbl_user_groups
    WHERE  user_id   = p_userId
      AND  group_id  = p_groupId
      AND  client_id = p_clientId;
    GET DIAGNOSTICS v_removed = ROW_COUNT;

    IF v_removed > 0 THEN
        UPDATE tbl_users
        SET    permissions_version = permissions_version + 1,
               admin_version       = admin_version + 1
        WHERE  id = p_userId AND client_id = p_clientId;
    END IF;
    RETURN v_removed;
END;
$$;
''',

    "stp_SetGroupProductGrants": '''/****** Object: Stored Procedure [stp_SetGroupProductGrants] ******/
-- Replaces the product roles a group confers, wholesale. Tenant ownership is
-- re-derived through tbl_groups (-1 when the group is not in this tenant), and
-- the composite keys refuse a product the tenant does not subscribe to or a role
-- outside the product's catalogue.
--
-- Every member's permissions_version is bumped: their tokens carry roles, so
-- they must be re-minted before a revoked role stops applying.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetGroupProductGrants(
    p_groupId    TEXT,
    p_clientId   TEXT,
    p_productIds TEXT[],
    p_roleNames  TEXT[],
    p_grantedBy  TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_inserted INTEGER := 0;
    v_pid      TEXT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM tbl_groups g
                   WHERE  g.id = p_groupId AND g.client_id = p_clientId) THEN
        RETURN -1;
    END IF;
    IF coalesce(array_length(p_productIds, 1), 0) <> coalesce(array_length(p_roleNames, 1), 0) THEN
        RAISE EXCEPTION 'product and role lists differ in length' USING ERRCODE = '22023';
    END IF;

    DELETE FROM tbl_group_product_grants
    WHERE  group_id = p_groupId AND client_id = p_clientId;

    IF coalesce(array_length(p_productIds, 1), 0) > 0 THEN
        INSERT INTO tbl_group_product_grants (group_id, client_id, product_id, role_name, granted_by)
        SELECT p_groupId, p_clientId, g.product_id, g.role_name, p_grantedBy
        FROM   unnest(p_productIds, p_roleNames) AS g(product_id, role_name);
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
    END IF;

    UPDATE tbl_users u
    SET    permissions_version = u.permissions_version + 1,
           updated_at          = now()
    FROM   tbl_user_groups ug
    WHERE  ug.group_id  = p_groupId
      AND  ug.client_id = p_clientId
      AND  u.id         = ug.user_id
      AND  u.client_id  = ug.client_id;

    -- Attaching a product to the group grants it to every member at once, so
    -- hold each newly-granted product's seat_limit (product-id order, so
    -- concurrent grants take the subscription locks consistently).
    FOR v_pid IN
        SELECT product_id FROM tbl_group_product_grants
        WHERE  group_id = p_groupId AND client_id = p_clientId
        ORDER  BY product_id
    LOOP
        PERFORM stp_AssertProductSeat(p_clientId, v_pid);
    END LOOP;

    RETURN v_inserted;
END;
$$;
''',

    "stp_SetDefaultLoginPolicy": '''/****** Object: Stored Procedure [stp_SetDefaultLoginPolicy] ******/
-- Makes a policy its tenant's default. The old default is cleared first, in the
-- same transaction, so the one-default-per-tenant unique index is never violated
-- even transiently. Returns 0 for a policy outside the tenant.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetDefaultLoginPolicy(
    p_policyId TEXT,
    p_clientId TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM tbl_login_policies
                   WHERE  id = p_policyId AND client_id = p_clientId) THEN
        RETURN 0;
    END IF;

    UPDATE tbl_login_policies
    SET    is_default = false, updated_at = now()
    WHERE  client_id = p_clientId AND is_default AND id <> p_policyId;

    UPDATE tbl_login_policies
    SET    is_default = true, updated_at = now()
    WHERE  id = p_policyId AND client_id = p_clientId;

    RETURN 1;
END;
$$;
''',

    "stp_SetSsoConnectionDomains": '''/****** Object: Stored Procedure [stp_SetSsoConnectionDomains] ******/
-- Replaces the email domains routed to a connection, wholesale.
--
-- Refuses (-2) a domain that ANOTHER tenant has verified: attaching it here would
-- route that tenant's users' sign-ins to this tenant's identity provider. A
-- domain already attached to another connection raises 23505 on the primary key.
-- Returns -1 for a connection outside the tenant.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetSsoConnectionDomains(
    p_connectionId TEXT,
    p_clientId     TEXT,
    p_domains      TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_inserted INTEGER := 0;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM tbl_sso_connections
                   WHERE  id = p_connectionId AND client_id = p_clientId) THEN
        RETURN -1;
    END IF;

    IF EXISTS (SELECT 1 FROM tbl_clients c
               WHERE  c.id <> p_clientId
                 AND  c.domain_verified_at IS NOT NULL
                 AND  lower(c.domain) IN (SELECT lower(d) FROM unnest(p_domains) AS d)) THEN
        RETURN -2;
    END IF;

    DELETE FROM tbl_sso_connection_domains
    WHERE  connection_id = p_connectionId AND client_id = p_clientId;

    IF coalesce(array_length(p_domains, 1), 0) > 0 THEN
        INSERT INTO tbl_sso_connection_domains (domain, connection_id, client_id)
        SELECT DISTINCT lower(d), p_connectionId, p_clientId FROM unnest(p_domains) AS d;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
    END IF;

    RETURN v_inserted;
END;
$$;
''',
}


def wrap(text, width=74, indent="-- "):
    out = []
    for para in text.split("\n"):
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


def emit(name, kind, params, returns, purpose, body):
    sig = f"{name}({params})" if params else f"{name}()"
    if kind == "proc":
        form = ("-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller\n"
                "-- invokes it with CALL.")
        head = f"CREATE OR REPLACE PROCEDURE {sig}\nLANGUAGE sql\nAS $$\n"
    else:
        form = ("-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,\n"
                "-- and PostgreSQL procedures cannot return a result set.")
        head = f"CREATE OR REPLACE FUNCTION {sig}\nRETURNS {returns}\nLANGUAGE sql\nVOLATILE\nAS $$\n"
    return (
        f"/****** Object: Stored Procedure [{name}] ******/\n"
        f"{wrap(purpose)}\n--\n{form}\n--\n"
        f"-- CREATE OR REPLACE so the build is idempotent.\n\n"
        f"{head}    {body.strip()};\n$$;\n"
    )


os.makedirs(OUT, exist_ok=True)
for spec in WRITES:
    with open(os.path.join(OUT, spec[0] + ".sql"), "w", encoding="utf-8", newline="\n") as f:
        f.write(emit(*spec))

for name, text in EXPLICIT.items():
    with open(os.path.join(OUT, name + ".sql"), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

print(f"wrote {len(WRITES) + len(EXPLICIT)} write files")
