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
  as plain SQL functions the planner can inline.

Run:  python db/gen_procedures.py
"""
import os

OUT = os.path.join(os.path.dirname(__file__), "Programmability", "StoredProcedures")

# kind: "proc" (CREATE PROCEDURE, no return) | "func" (CREATE FUNCTION + returns)
# (name, kind, params, returns_or_None, purpose, body)
WRITES = [
    # ---- users -------------------------------------------------------------
    ("stp_CreateUser", "func",
     'p_clientId TEXT, p_email TEXT, p_passwordHash TEXT, p_accountType "AccountType"',
     "SETOF tbl_users",
     "Creates a member. The address is stored lower-cased so it is aligned with the "
     "case-insensitive unique index; inserting mixed case would let two rows differ "
     "only by case and defeat that index. A duplicate live address raises 23505, "
     "which the caller maps to 409.",
     """INSERT INTO tbl_users (client_id, email, password_hash, account_type)
    VALUES (p_clientId, lower(p_email), p_passwordHash, p_accountType)
    RETURNING *"""),

    ("stp_SetUserActive", "func",
     "p_userId TEXT, p_clientId TEXT, p_isActive BOOLEAN", "INTEGER",
     "Enables or disables a member, tenant-scoped. Returns the affected-row count so "
     "the caller can answer 404 for an unknown or another tenant's user rather than "
     "silently reporting success.",
     """WITH upd AS (
        UPDATE tbl_users
        SET    is_active  = p_isActive,
               updated_at = now()
        WHERE  id        = p_userId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int FROM upd"""),

    ("stp_SetUserPassword", "proc",
     "p_userId TEXT, p_clientId TEXT, p_passwordHash TEXT", None,
     "Sets a new password hash. Tenant-scoped so a leaked user id from another "
     "organisation cannot be used to overwrite a password.",
     """UPDATE tbl_users
    SET    password_hash = p_passwordHash,
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

    # ---- clients / products -------------------------------------------------
    ("stp_CreateClient", "func",
     'p_name TEXT, p_domain TEXT, p_allowedIdpProviders "IdpProvider"[], p_requireMfa BOOLEAN, '
     'p_subscriptionStatus "SubscriptionStatus", p_maxSeats INTEGER, p_isActive BOOLEAN',
     "SETOF tbl_clients",
     "Provisions a tenant. domain_verified_at is deliberately NOT settable here: a "
     "new tenant starts UNVERIFIED, because a verified domain grants CORS trust and "
     "governs federated-login tenant resolution.",
     """INSERT INTO tbl_clients (name, domain, allowed_idp_providers, require_mfa,
                             subscription_status, max_seats, is_active)
    VALUES (p_name, lower(p_domain), p_allowedIdpProviders, p_requireMfa,
            p_subscriptionStatus, p_maxSeats, p_isActive)
    RETURNING *"""),

    ("stp_UpdateClient", "func",
     'p_clientId TEXT, p_name TEXT, p_requireMfa BOOLEAN, p_allowedIdpProviders "IdpProvider"[], '
     'p_domainVerifiedAt TIMESTAMPTZ, p_subscriptionStatus "SubscriptionStatus", '
     'p_maxSeats INTEGER, p_isActive BOOLEAN',
     "SETOF tbl_clients",
     "Full tenant update. The domain itself is immutable here — changing it would "
     "move CORS trust to a new origin, which must be an explicit, separately "
     "audited operation.",
     """UPDATE tbl_clients
    SET    name                  = p_name,
           require_mfa           = p_requireMfa,
           allowed_idp_providers = p_allowedIdpProviders,
           domain_verified_at    = p_domainVerifiedAt,
           subscription_status   = p_subscriptionStatus,
           max_seats             = p_maxSeats,
           is_active             = p_isActive,
           updated_at            = now()
    WHERE  id = p_clientId
    RETURNING *"""),

    ("stp_CreateProduct", "func",
     "p_key TEXT, p_name TEXT, p_description TEXT, p_baseUrl TEXT, p_isActive BOOLEAN",
     "SETOF tbl_products",
     "Adds a product to the global catalogue. A duplicate key raises 23505.",
     """INSERT INTO tbl_products (key, name, description, base_url, is_active)
    VALUES (p_key, p_name, p_description, p_baseUrl, p_isActive)
    RETURNING *"""),

    ("stp_UpdateProduct", "func",
     "p_productId TEXT, p_name TEXT, p_description TEXT, p_baseUrl TEXT, p_isActive BOOLEAN",
     "SETOF tbl_products",
     "Updates a catalogue entry. The key is immutable: it is embedded in already-"
     "issued JWT audiences, so changing it would invalidate live tokens.",
     """UPDATE tbl_products
    SET    name        = p_name,
           description = p_description,
           base_url    = p_baseUrl,
           is_active   = p_isActive,
           updated_at  = now()
    WHERE  id = p_productId
    RETURNING *"""),

    # ---- sessions ----------------------------------------------------------
    ("stp_CreateSession", "func",
     "p_userId TEXT, p_clientId TEXT, p_sessionUuid TEXT, p_familyId TEXT, "
     "p_refreshTokenHash TEXT, p_expiresAt TIMESTAMPTZ, p_ipAddress TEXT, "
     "p_deviceLabel TEXT, p_userAgent TEXT",
     "SETOF tbl_user_sessions",
     "Opens a NEW token family at login. Generation defaults to 0 and "
     "prev_token_hash stays NULL, marking this as the root of the chain. Only the "
     "hash of the token is stored.",
     """INSERT INTO tbl_user_sessions (user_id, client_id, session_uuid, family_id,
                                   refresh_token_hash, expires_at,
                                   ip_address, device_label, user_agent)
    VALUES (p_userId, p_clientId, p_sessionUuid, p_familyId,
            p_refreshTokenHash, p_expiresAt,
            p_ipAddress, p_deviceLabel, p_userAgent)
    RETURNING *"""),

    ("stp_CreateSuccessorSession", "func",
     "p_userId TEXT, p_clientId TEXT, p_sessionUuid TEXT, p_familyId TEXT, "
     "p_generation INTEGER, p_refreshTokenHash TEXT, p_prevTokenHash TEXT, "
     "p_expiresAt TIMESTAMPTZ, p_ipAddress TEXT, p_deviceLabel TEXT, p_userAgent TEXT",
     "SETOF tbl_user_sessions",
     "Appends the next generation to an existing family. The family id is inherited, "
     "never regenerated — that is what keeps a stolen token traceable to every other "
     "token derived from the same login. prev_token_hash is what makes the "
     "grace-window race detectable. A collision on (family_id, generation) means a "
     "concurrent rotation won, and the unique index turns that into 23505 rather "
     "than a forked family.",
     """INSERT INTO tbl_user_sessions (user_id, client_id, session_uuid, family_id, generation,
                                   refresh_token_hash, prev_token_hash, expires_at,
                                   ip_address, device_label, user_agent)
    VALUES (p_userId, p_clientId, p_sessionUuid, p_familyId, p_generation,
            p_refreshTokenHash, p_prevTokenHash, p_expiresAt,
            p_ipAddress, p_deviceLabel, p_userAgent)
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

    ("stp_RevokeSession", "func",
     'p_sessionId TEXT, p_clientId TEXT, p_reason "SessionRevokedReason"', "INTEGER",
     "Revokes one session, tenant-scoped and idempotent (already-revoked rows are "
     "skipped). Returns the affected count so a cross-tenant id yields 404.",
     """WITH upd AS (
        UPDATE tbl_user_sessions
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  id          = p_sessionId
          AND  client_id   = p_clientId
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM upd"""),

    ("stp_RevokeAllUserSessions", "func",
     'p_userId TEXT, p_reason "SessionRevokedReason"', "INTEGER",
     "Revokes every live session for a user — used on password change, reset and "
     "deactivation. Scoped by user_id alone is safe because the composite tenant "
     "foreign key pins a user to exactly one tenant.",
     """WITH upd AS (
        UPDATE tbl_user_sessions
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  user_id     = p_userId
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM upd"""),

    ("stp_RevokeTokenFamily", "proc",
     "p_familyId TEXT, p_reason TEXT DEFAULT 'REUSE_DETECTED'", None,
     "THE reuse-detection response: burns every live session descended from one "
     "login. Called when a spent refresh token is replayed outside the grace "
     "window. The caller must COMMIT this before returning the error — if it is "
     "rolled back with the failing request, the family is never actually revoked "
     "and the detection is cosmetic.",
     """UPDATE tbl_user_sessions
    SET    revoked_at     = now(),
           revoked_reason = p_reason::"SessionRevokedReason"
    WHERE  family_id   = p_familyId
      AND  revoked_at IS NULL"""),

    ("stp_ExpireSessions", "proc",
     "p_batchSize INTEGER DEFAULT 500", None,
     "Scheduled sweep for timed-out sessions. Batched so the transaction stays "
     "short and never holds locks against live rotation traffic. Purely hygiene: "
     "every read path already filters on expires_at, so a late sweep is not a "
     "security gap.",
     """UPDATE tbl_user_sessions
    SET    revoked_at     = now(),
           revoked_reason = 'EXPIRED'
    WHERE  id IN (
        SELECT s.id
        FROM   tbl_user_sessions s
        WHERE  s.expires_at  < now()
          AND  s.revoked_at IS NULL
        LIMIT  p_batchSize
    )"""),

    # ---- oauth -------------------------------------------------------------
    ("stp_CreateAuthorizationCode", "func",
     "p_code TEXT, p_productId TEXT, p_userId TEXT, p_redirectUrl TEXT, "
     "p_codeChallenge TEXT, p_codeChallengeMethod TEXT, p_state TEXT, p_expiresAt TIMESTAMPTZ",
     "SETOF tbl_authorization_codes",
     "Issues a single-use authorization code. redirect_url and code_challenge are "
     "stored WITH the code so both are re-verified at redemption and cannot be "
     "swapped between the two legs of the flow.",
     """INSERT INTO tbl_authorization_codes (code, product_id, user_id, redirect_url,
                                         code_challenge, code_challenge_method,
                                         state, expires_at)
    VALUES (p_code, p_productId, p_userId, p_redirectUrl,
            p_codeChallenge, p_codeChallengeMethod, p_state, p_expiresAt)
    RETURNING *"""),

    ("stp_ClaimAuthorizationCode", "func",
     "p_code TEXT", "SETOF tbl_authorization_codes",
     "Redeems a code in ONE atomic statement. The used_at IS NULL and expiry guards "
     "are part of the UPDATE, so two concurrent redemptions cannot both succeed — "
     "the second updates zero rows. A SELECT-then-UPDATE here would be a "
     "double-spend, which is the classic authorization-code attack.",
     """UPDATE tbl_authorization_codes
    SET    used_at = now()
    WHERE  code       = p_code
      AND  used_at   IS NULL
      AND  expires_at > now()
    RETURNING *"""),

    ("stp_CleanupExpiredAuthCodes", "func", "", "INTEGER",
     "Housekeeping sweep for expired codes. Safe to delete outright: an expired "
     "code is unredeemable, so nothing references it.",
     """WITH del AS (
        DELETE FROM tbl_authorization_codes
        WHERE  expires_at < now()
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

    ("stp_CreateLinkedIdentity", "func",
     'p_userId TEXT, p_provider "IdpProvider", p_providerId TEXT, p_emailVerified BOOLEAN',
     "SETOF tbl_linked_identities",
     "Binds an external identity to a local account on first federated sign-in. The "
     "unique constraint on (provider, provider_id) means one provider account can "
     "never be linked to two local users.",
     """INSERT INTO tbl_linked_identities (user_id, provider, provider_id, email_verified)
    VALUES (p_userId, p_provider, p_providerId, p_emailVerified)
    RETURNING *"""),

    # ---- invitations -------------------------------------------------------
    ("stp_CreateInvitation", "func",
     "p_email TEXT, p_clientId TEXT, p_invitedByUserId TEXT, p_tokenHash TEXT, "
     "p_expiresAt TIMESTAMPTZ", "SETOF tbl_invitations",
     "Issues an invitation. Only the token's SHA-256 is stored; the raw value exists "
     "solely in the email that was sent, so a database leak yields nothing "
     "redeemable. The address is lower-cased for index alignment.",
     """INSERT INTO tbl_invitations (email, client_id, invited_by_user_id, token_hash, expires_at)
    VALUES (lower(p_email), p_clientId, p_invitedByUserId, p_tokenHash, p_expiresAt)
    RETURNING *"""),

    ("stp_CreateInvitationProduct", "proc",
     "p_invitationId TEXT, p_productId TEXT, p_roleName TEXT", None,
     "Attaches one product grant to an invitation. Called once per grant inside the "
     "same transaction as the invitation itself, so a committed invitation always "
     "carries the access it promised.",
     """INSERT INTO tbl_invitation_products (invitation_id, product_id, role_name)
    VALUES (p_invitationId, p_productId, p_roleName)"""),

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
     "outstanding token first so exactly one link is ever live — otherwise "
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
    ("stp_UpsertProductPermission", "proc",
     "p_userId TEXT, p_clientId TEXT, p_productId TEXT, p_roleName TEXT, p_grantedBy TEXT", None,
     "Grants or re-grants a product role. ON CONFLICT on the natural key makes a "
     "regrant idempotent instead of raising a duplicate-key error.",
     """INSERT INTO tbl_product_permissions (user_id, client_id, product_id, role_name, granted_by)
    VALUES (p_userId, p_clientId, p_productId, p_roleName, p_grantedBy)
    ON CONFLICT (user_id, client_id, product_id)
    DO UPDATE SET role_name  = EXCLUDED.role_name,
                  granted_by = EXCLUDED.granted_by"""),

    ("stp_DeleteProductPermission", "func",
     "p_userId TEXT, p_clientId TEXT, p_productId TEXT", "INTEGER",
     "Revokes a product role, tenant-scoped. The count lets the caller answer 404 "
     "rather than reporting success for a grant that never existed.",
     """WITH del AS (
        DELETE FROM tbl_product_permissions
        WHERE  user_id    = p_userId
          AND  client_id  = p_clientId
          AND  product_id = p_productId
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
     "Renames or re-describes a group, tenant-scoped. Zero rows means unknown or "
     "another tenant's group.",
     """UPDATE tbl_groups
    SET    name        = p_name,
           description = p_description,
           updated_at  = now()
    WHERE  id        = p_groupId
      AND  client_id = p_clientId
    RETURNING *"""),

    ("stp_DeleteGroup", "func",
     "p_groupId TEXT, p_clientId TEXT", "INTEGER",
     "Deletes a group; its features and memberships cascade. Tenant-scoped, so a "
     "foreign id deletes nothing.",
     """WITH del AS (
        DELETE FROM tbl_groups
        WHERE  id        = p_groupId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

    ("stp_AddGroupMember", "proc",
     "p_userId TEXT, p_groupId TEXT, p_clientId TEXT, p_assignedBy TEXT", None,
     "Adds a member. A duplicate raises 23505 on the composite primary key, and the "
     "composite tenant foreign key independently refuses a user from another "
     "organisation even if the caller's checks were bypassed.",
     """INSERT INTO tbl_user_groups (user_id, group_id, client_id, assigned_by)
    VALUES (p_userId, p_groupId, p_clientId, p_assignedBy)"""),

    ("stp_RemoveGroupMember", "func",
     "p_userId TEXT, p_groupId TEXT, p_clientId TEXT", "INTEGER",
     "Removes a member. Scoped by all three columns so a foreign group id removes "
     "nothing.",
     """WITH del AS (
        DELETE FROM tbl_user_groups
        WHERE  user_id   = p_userId
          AND  group_id  = p_groupId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int FROM del"""),

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

# stp_SetGroupFeatures needs two statements, so it is written explicitly.
SET_GROUP_FEATURES = '''/****** Object: Stored Procedure [stp_SetGroupFeatures] ******/
-- Replaces a group's feature keys wholesale, so the caller submits the complete
-- desired state instead of computing a diff.
--
-- Tenant scoping is ENFORCED HERE rather than assumed. tbl_group_features has no
-- client_id of its own, so ownership is re-derived through tbl_groups on both
-- statements: a group id belonging to another organisation therefore deletes and
-- inserts nothing, instead of silently rewriting their permissions.
--
-- Implemented as a FUNCTION because the caller needs the inserted count to tell
-- "wrong tenant" from "no features requested".
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetGroupFeatures(
    p_groupId     TEXT,
    p_clientId    TEXT,
    p_featureKeys TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_owned    BOOLEAN;
    v_inserted INTEGER := 0;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM tbl_groups g
        WHERE  g.id = p_groupId AND g.client_id = p_clientId
    ) INTO v_owned;

    IF NOT v_owned THEN
        RETURN -1;  -- -1 = group not found in this tenant
    END IF;

    DELETE FROM tbl_group_features WHERE group_id = p_groupId;

    IF p_featureKeys IS NOT NULL AND array_length(p_featureKeys, 1) > 0 THEN
        INSERT INTO tbl_group_features (group_id, feature_key)
        SELECT p_groupId, k
        FROM   unnest(p_featureKeys) AS k;

        v_inserted := array_length(p_featureKeys, 1);
    END IF;

    RETURN v_inserted;  -- >= 0 = number of feature keys now attached
END;
$$;
'''


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

with open(os.path.join(OUT, "stp_SetGroupFeatures.sql"), "w", encoding="utf-8", newline="\n") as f:
    f.write(SET_GROUP_FEATURES)

print(f"wrote {len(WRITES) + 1} write files")
