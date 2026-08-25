"""Generates db/Tables/tbl_*.sql — one file per table, following the house
convention: explicit constraint names (PK_/FK_/UQ_/CK_/DF_), idempotent guards,
and each table's own indexes co-located with it.

Run once to (re)materialise the Tables folder:
    python db/gen_tables.py

Kept in the repo so the layout can be regenerated deterministically rather than
hand-maintained across 15 files.
"""
import os

OUT = os.path.join(os.path.dirname(__file__), "Tables")

# (table, [ (column, type, extra) ], [pk cols], [ (name, cols, kind, predicate) ], [ (name, child_cols, parent_table, parent_cols, on_delete, extra) ], notes)
TABLES = [
    ("tbl_clients", "A tenant (organisation). This is the root of every isolation boundary in the schema.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("name", "TEXT", "NOT NULL"),
        ("domain", "TEXT", "NULL"),
        ("domain_verified_at", "TIMESTAMPTZ", "NULL"),
        ("allowed_idp_providers", '"IdpProvider"[]', "NULL DEFAULT ARRAY['EMAIL','GOOGLE']::\"IdpProvider\"[]"),
        ("require_mfa", "BOOLEAN", "NOT NULL DEFAULT false"),
        ("subscription_status", '"SubscriptionStatus"', "NOT NULL DEFAULT 'TRIAL'"),
        ("max_seats", "INTEGER", "NULL"),
        ("is_active", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_clients_domain_verified", "(lower(domain))", "UNIQUE",
         "WHERE domain IS NOT NULL AND domain_verified_at IS NOT NULL",
         "Only VERIFIED domains are globally unique. An unverified domain must not "
         "block another tenant from claiming it, and verification is what grants "
         "CORS trust, so uniqueness matters only once verified."),
    ], [], None),

    ("tbl_products", "The global product catalogue. NOT tenant-scoped: products are "
                     "platform-wide, and a tenant's access is expressed by tbl_client_products.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("key", "TEXT", "NOT NULL"),
        ("name", "TEXT", "NOT NULL"),
        ("description", "TEXT", "NULL"),
        ("base_url", "TEXT", "NULL"),
        ("is_active", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_products_key", "(key)", "UNIQUE", "",
         "The key is embedded in the JWT audience as product:<key>, so it must "
         "identify exactly one product."),
    ], [], None),

    ("tbl_users", "A member of a tenant. Soft-deleted via deleted_at so an audit "
                  "trail survives GDPR erasure of the account.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("client_id", "TEXT", "NOT NULL"),
        ("email", "TEXT", "NOT NULL"),
        ("password_hash", "TEXT", "NULL"),
        ("account_type", '"AccountType"', "NOT NULL DEFAULT 'EMAIL'"),
        ("is_active", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("is_global_admin", "BOOLEAN", "NOT NULL DEFAULT false"),
        ("permissions_version", "INTEGER", "NOT NULL DEFAULT 1"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("deleted_at", "TIMESTAMPTZ", "NULL"),
    ], ["id"], [
        ("UQ_tbl_users_id_client_id", "(id, client_id)", "UNIQUE", "",
         "Not redundant with the primary key: this is the TARGET of the composite "
         "foreign keys that pin child rows to one tenant, and PostgreSQL requires "
         "a unique constraint on the referenced columns."),
        ("UQ_tbl_users_email_active", "(client_id, lower(email))", "UNIQUE",
         "WHERE deleted_at IS NULL",
         "Email is unique per tenant only among LIVE users, and case-insensitively. "
         "Partial so a soft-deleted account never blocks re-invitation of the same "
         "address; lower() so Bob@x and bob@x cannot both exist."),
        ("IX_tbl_users_lower_email_active", "(lower(email))", "INDEX",
         "WHERE deleted_at IS NULL",
         "The login lookup matches lower(email) with NO client_id, so the composite "
         "index above cannot serve it and every sign-in would seq-scan."),
    ], [
        ("FK_tbl_users_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
    ], None),

    ("tbl_user_sessions", "One refresh-token generation. A login opens a family "
                          "(family_id); each refresh appends a generation and revokes its predecessor, "
                          "which is what makes token replay detectable.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("user_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("session_uuid", "TEXT", "NOT NULL"),
        ("family_id", "TEXT", "NOT NULL"),
        ("generation", "INTEGER", "NOT NULL DEFAULT 0"),
        ("refresh_token_hash", "TEXT", "NOT NULL"),
        ("prev_token_hash", "TEXT", "NULL"),
        ("expires_at", "TIMESTAMPTZ", "NOT NULL"),
        ("revoked_at", "TIMESTAMPTZ", "NULL"),
        ("revoked_reason", '"SessionRevokedReason"', "NULL"),
        ("ip_address", "TEXT", "NULL"),
        ("device_label", "TEXT", "NULL"),
        ("user_agent", "TEXT", "NULL"),
        ("last_seen_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("replaced_by_id", "TEXT", "NULL"),
    ], ["id"], [
        ("UQ_tbl_user_sessions_session_uuid", "(session_uuid)", "UNIQUE", "", ""),
        ("UQ_tbl_user_sessions_refresh_token_hash", "(refresh_token_hash)", "UNIQUE", "",
         "Only the SHA-256 of the token is stored, so a database leak yields no "
         "usable credentials. Unique because it is the rotation lookup key."),
        ("UQ_tbl_user_sessions_replaced_by_id", "(replaced_by_id)", "UNIQUE", "",
         "A session may be superseded by at most one successor, so the family "
         "cannot fork."),
        ("UQ_tbl_user_sessions_family_generation", "(family_id, generation)", "UNIQUE", "",
         "Database-level backstop against two concurrent rotations both minting "
         "the same generation."),
        ("IX_tbl_user_sessions_family_id", "(family_id)", "INDEX", "",
         "Burning a family on reuse detection updates every row sharing it."),
        ("IX_tbl_user_sessions_user_client", "(user_id, client_id)", "INDEX", "", ""),
        ("IX_tbl_user_sessions_user_revoked", "(user_id, revoked_at)", "INDEX", "",
         "Serves the active-sessions list."),
        ("IX_tbl_user_sessions_expires_at", "(expires_at)", "INDEX", "",
         "Serves the hourly expiry sweep."),
        ("IX_tbl_user_sessions_prev_token_hash", "(prev_token_hash)", "INDEX",
         "WHERE prev_token_hash IS NOT NULL AND revoked_at IS NULL",
         "The grace-race lookup runs INSIDE the rotation transaction while holding "
         "a FOR UPDATE lock; unindexed it would hold that lock for O(n)."),
    ], [
        ("FK_tbl_user_sessions_tbl_users_user_id", "(user_id)", "tbl_users", "(id)", "CASCADE", ""),
        ("FK_tbl_user_sessions_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
        ("FK_tbl_user_sessions_tbl_user_sessions_replaced_by_id", "(replaced_by_id)", "tbl_user_sessions", "(id)", "SET NULL", ""),
        ("FK_tbl_user_sessions_tbl_users_user_id_client_id", "(user_id, client_id)", "tbl_users", "(id, client_id)", "CASCADE",
         "TENANT ISOLATION. Makes a session belonging to user A but tenant B "
         "physically unrepresentable, independently of any application check."),
    ], None),

    ("tbl_client_products", "A tenant's subscription to a product.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("client_id", "TEXT", "NOT NULL"),
        ("product_id", "TEXT", "NOT NULL"),
        ("is_active", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("seat_limit", "INTEGER", "NULL"),
        ("starts_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("ends_at", "TIMESTAMPTZ", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_client_products_client_product", "(client_id, product_id)", "UNIQUE", "", ""),
        ("IX_tbl_client_products_client_active", "(client_id, is_active)", "INDEX", "",
         "Serves the entitlement check on every login."),
    ], [
        ("FK_tbl_client_products_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "CASCADE", ""),
        ("FK_tbl_client_products_tbl_products_product_id", "(product_id)", "tbl_products", "(id)", "RESTRICT", ""),
    ], None),

    ("tbl_product_permissions", "A user's role within one product. These rows become "
                                "the JWT roles claim, so their tenant scoping is security-critical.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("user_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("product_id", "TEXT", "NOT NULL"),
        ("role_name", "TEXT", "NOT NULL"),
        ("granted_by", "TEXT", "NULL"),
        ("valid_from", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("valid_until", "TIMESTAMPTZ", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_product_permissions_user_client_product", "(user_id, client_id, product_id)", "UNIQUE", "",
         "One role per user per product; a regrant is an upsert on this key."),
        ("IX_tbl_product_permissions_client_id", "(client_id)", "INDEX", "",
         "Child side of the tenant foreign key, probed on tenant delete."),
    ], [
        ("FK_tbl_product_permissions_tbl_users_user_id", "(user_id)", "tbl_users", "(id)", "CASCADE", ""),
        ("FK_tbl_product_permissions_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
        ("FK_tbl_product_permissions_tbl_products_product_id", "(product_id)", "tbl_products", "(id)", "RESTRICT", ""),
        ("FK_tbl_product_permissions_tbl_users_user_id_client_id", "(user_id, client_id)", "tbl_users", "(id, client_id)", "CASCADE",
         "TENANT ISOLATION: a grant cannot reference a user from another tenant."),
    ], None),

    ("tbl_linked_identities", "An external identity (e.g. a Google account) bound to a local user.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("user_id", "TEXT", "NOT NULL"),
        ("provider", '"IdpProvider"', "NOT NULL"),
        ("provider_id", "TEXT", "NOT NULL"),
        ("email_verified", "BOOLEAN", "NOT NULL DEFAULT false"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_linked_identities_provider_provider_id", "(provider, provider_id)", "UNIQUE", "",
         "provider_id is the provider's STABLE subject id, never the email: a user "
         "who changes their Google address keeps their account, and someone who "
         "acquires a recycled address does not inherit one."),
        ("IX_tbl_linked_identities_user_id", "(user_id)", "INDEX", "", ""),
    ], [
        ("FK_tbl_linked_identities_tbl_users_user_id", "(user_id)", "tbl_users", "(id)", "CASCADE", ""),
    ], None),

    ("tbl_invitations", "A pending invitation. Only the SHA-256 of the token is stored; "
                        "the raw value exists solely in the email that was sent.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("email", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("invited_by_user_id", "TEXT", "NOT NULL"),
        ("token_hash", "TEXT", "NOT NULL"),
        ("expires_at", "TIMESTAMPTZ", "NOT NULL"),
        ("status", '"InvitationStatus"', "NOT NULL DEFAULT 'PENDING'"),
        ("accepted_at", "TIMESTAMPTZ", "NULL"),
        ("accepted_by_user_id", "TEXT", "NULL"),
        ("revoked_at", "TIMESTAMPTZ", "NULL"),
        ("revoked_by_user_id", "TEXT", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_invitations_token_hash", "(token_hash)", "UNIQUE", "", ""),
        ("IX_tbl_invitations_email_client_status", "(email, client_id, status)", "INDEX", "", ""),
        ("IX_tbl_invitations_client_status_created", "(client_id, status, created_at)", "INDEX", "",
         "Serves the admin pending-invitations list."),
        ("IX_tbl_invitations_expires_status", "(expires_at, status)", "INDEX", "",
         "Serves the six-hourly expiry sweep."),
        ("IX_tbl_invitations_invited_by", "(invited_by_user_id)", "INDEX", "",
         "Child side of a RESTRICT foreign key, probed on every user delete."),
        ("IX_tbl_invitations_accepted_by", "(accepted_by_user_id)", "INDEX", "", ""),
    ], [
        ("FK_tbl_invitations_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
        ("FK_tbl_invitations_tbl_users_invited_by_user_id", "(invited_by_user_id)", "tbl_users", "(id)", "RESTRICT", ""),
        ("FK_tbl_invitations_tbl_users_accepted_by_user_id", "(accepted_by_user_id)", "tbl_users", "(id)", "SET NULL", ""),
        ("FK_tbl_invitations_tbl_users_invited_by_user_id_client_id", "(invited_by_user_id, client_id)", "tbl_users", "(id, client_id)", "RESTRICT",
         "TENANT ISOLATION: the inviter must belong to the invited tenant."),
    ], None),

    ("tbl_invitation_products", "The products and roles an invitation grants on acceptance.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("invitation_id", "TEXT", "NOT NULL"),
        ("product_id", "TEXT", "NOT NULL"),
        ("role_name", "TEXT", "NOT NULL"),
    ], ["id"], [
        ("UQ_tbl_invitation_products_invitation_product", "(invitation_id, product_id)", "UNIQUE", "", ""),
    ], [
        ("FK_tbl_invitation_products_tbl_invitations_invitation_id", "(invitation_id)", "tbl_invitations", "(id)", "CASCADE", ""),
        ("FK_tbl_invitation_products_tbl_products_product_id", "(product_id)", "tbl_products", "(id)", "RESTRICT", ""),
    ], None),

    ("tbl_audit_logs", "Append-only audit trail. No procedure in this schema updates or "
                       "deletes from this table, which is what makes the trail trustworthy.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("client_id", "TEXT", "NOT NULL"),
        ("actor_user_id", "TEXT", "NULL"),
        ("event_type", "TEXT", "NOT NULL"),
        ("event_metadata", "JSONB", "NULL"),
        ("ip_address", "TEXT", "NULL"),
        ("user_agent", "TEXT", "NULL"),
        ("request_id", "TEXT", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("IX_tbl_audit_logs_client_created", "(client_id, created_at)", "INDEX", "", ""),
        ("IX_tbl_audit_logs_client_event_created", "(client_id, event_type, created_at)", "INDEX", "", ""),
        ("IX_tbl_audit_logs_request_id", "(request_id)", "INDEX", "", ""),
        ("IX_tbl_audit_logs_actor_user_id", "(actor_user_id)", "INDEX", "", ""),
    ], [
        ("FK_tbl_audit_logs_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
        ("FK_tbl_audit_logs_tbl_users_actor_user_id", "(actor_user_id)", "tbl_users", "(id)", "SET NULL", ""),
    ], None),

    ("tbl_authorization_codes", "A single-use OAuth2 authorization code with its PKCE challenge. "
                               "Redeemed by exactly one atomic UPDATE, so it cannot be double-spent.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("code", "TEXT", "NOT NULL"),
        ("product_id", "TEXT", "NOT NULL"),
        ("user_id", "TEXT", "NOT NULL"),
        ("redirect_url", "TEXT", "NOT NULL"),
        ("code_challenge", "TEXT", "NOT NULL"),
        ("code_challenge_method", "TEXT", "NOT NULL DEFAULT 'S256'"),
        ("state", "TEXT", "NULL"),
        ("expires_at", "TIMESTAMPTZ", "NOT NULL"),
        ("used_at", "TIMESTAMPTZ", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_authorization_codes_code", "(code)", "UNIQUE", "", ""),
        ("IX_tbl_authorization_codes_product_id", "(product_id)", "INDEX", "", ""),
        ("IX_tbl_authorization_codes_user_id", "(user_id)", "INDEX", "",
         "Child side of a RESTRICT foreign key, probed on user delete."),
        ("IX_tbl_authorization_codes_expires_at", "(expires_at)", "INDEX", "", ""),
    ], [
        ("FK_tbl_authorization_codes_tbl_products_product_id", "(product_id)", "tbl_products", "(id)", "RESTRICT", ""),
        ("FK_tbl_authorization_codes_tbl_users_user_id", "(user_id)", "tbl_users", "(id)", "RESTRICT", ""),
    ], None),

    ("tbl_groups", "A named bundle of admin feature grants within one tenant.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("client_id", "TEXT", "NOT NULL"),
        ("name", "TEXT", "NOT NULL"),
        ("description", "TEXT", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_groups_client_name", "(client_id, lower(name))", "UNIQUE", "",
         "Case-insensitive so 'Sales' and 'sales' cannot both exist in one tenant."),
    ], [
        ("FK_tbl_groups_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
    ], None),

    ("tbl_group_features", "The feature keys a group grants.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("group_id", "TEXT", "NOT NULL"),
        ("feature_key", "TEXT", "NOT NULL"),
    ], ["id"], [
        ("UQ_tbl_group_features_group_feature", "(group_id, feature_key)", "UNIQUE", "", ""),
        ("IX_tbl_group_features_feature_group", "(feature_key, group_id)", "INDEX", "",
         "Serves the authorisation check, which looks up by feature key first."),
    ], [
        ("FK_tbl_group_features_tbl_groups_group_id", "(group_id)", "tbl_groups", "(id)", "CASCADE", ""),
    ], None),

    ("tbl_user_groups", "Group membership. The composite primary key is the membership "
                        "itself, so no surrogate id is needed.", [
        ("user_id", "TEXT", "NOT NULL"),
        ("group_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("assigned_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("assigned_by", "TEXT", "NULL"),
    ], ["user_id", "group_id"], [
        ("IX_tbl_user_groups_user_client", "(user_id, client_id)", "INDEX", "", ""),
    ], [
        ("FK_tbl_user_groups_tbl_users_user_id", "(user_id)", "tbl_users", "(id)", "CASCADE", ""),
        ("FK_tbl_user_groups_tbl_groups_group_id", "(group_id)", "tbl_groups", "(id)", "CASCADE", ""),
        ("FK_tbl_user_groups_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
        ("FK_tbl_user_groups_tbl_users_user_id_client_id", "(user_id, client_id)", "tbl_users", "(id, client_id)", "CASCADE",
         "TENANT ISOLATION: a user from tenant A cannot join a group in tenant B."),
    ], None),

    ("tbl_password_reset_tokens", "A single-use password reset token, stored as its "
                                 "SHA-256 only. At most one is live per user at a time.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("user_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("token_hash", "TEXT", "NOT NULL"),
        ("expires_at", "TIMESTAMPTZ", "NOT NULL"),
        ("used_at", "TIMESTAMPTZ", "NULL"),
        ("created_by", "TEXT", "NOT NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_password_reset_tokens_token_hash", "(token_hash)", "UNIQUE", "", ""),
        ("IX_tbl_password_reset_tokens_user_client", "(user_id, client_id)", "INDEX", "", ""),
    ], [
        ("FK_tbl_password_reset_tokens_tbl_users_user_id", "(user_id)", "tbl_users", "(id)", "CASCADE", ""),
        ("FK_tbl_password_reset_tokens_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
        ("FK_tbl_password_reset_tokens_tbl_users_user_id_client_id", "(user_id, client_id)", "tbl_users", "(id, client_id)", "CASCADE",
         "TENANT ISOLATION: a reset token cannot span tenants."),
    ], None),
]

# The audit-actor composite FK is special-cased: ON DELETE SET NULL is impossible
# on a composite containing a NOT NULL column, so it is NO ACTION + DEFERRABLE.
SPECIAL_FKS = {
    "tbl_audit_logs": [(
        "FK_tbl_audit_logs_tbl_users_actor_user_id_client_id",
        "(actor_user_id, client_id)", "tbl_users", "(id, client_id)",
        "NO ACTION",
        "TENANT ISOLATION for a nullable actor. ON DELETE SET NULL is impossible "
        "here: it would null client_id too, which is NOT NULL. Instead the "
        "single-column actor FK nulls the actor first, and MATCH SIMPLE lets this "
        "composite pass once actor_user_id IS NULL. DEFERRABLE so the check runs "
        "at COMMIT, after that SET NULL has applied.",
        "DEFERRABLE INITIALLY DEFERRED",
    )],
}


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


def emit(table, purpose, cols, pk, idx, fks, _notes):
    w = max(len(c[0]) for c in cols) + 2
    t = max(len(c[1]) for c in cols) + 2
    lines = [f"/****** Object: Table [{table}] ******/", wrap(purpose), "--",
             wrap("Idempotent: guarded so re-running the build is safe."), ""]
    lines.append(f"CREATE TABLE IF NOT EXISTS {table} (")
    body = [f"    {c[0]:<{w}}{c[1]:<{t}}{c[2]}" for c in cols]
    body.append(f"    CONSTRAINT PK_{table} PRIMARY KEY ({', '.join(pk)})")
    lines.append(",\n".join(body))
    lines.append(");")

    if fks or table in SPECIAL_FKS:
        lines += ["", "-- Foreign keys. Added separately from CREATE TABLE so the build can apply",
                  "-- every table first and wire the references afterwards, which removes any",
                  "-- ordering requirement between table files."]
        for fk in list(fks) + SPECIAL_FKS.get(table, []):
            name, child, parent, pcols, ondel = fk[0], fk[1], fk[2], fk[3], fk[4]
            note = fk[5] if len(fk) > 5 else ""
            extra = fk[6] if len(fk) > 6 else ""
            if note:
                lines.append("--")
                lines.append(wrap(note))
            lines.append("DO $$ BEGIN")
            lines.append(f"    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '{name.lower()}') THEN")
            lines.append(f"        ALTER TABLE {table} ADD CONSTRAINT {name}")
            lines.append(f"            FOREIGN KEY {child} REFERENCES {parent} {pcols}")
            lines.append(f"            ON DELETE {ondel}{(' ' + extra) if extra else ''};")
            lines.append("    END IF;")
            lines.append("END $$;")

    if idx:
        lines += ["", "-- Unique constraints and indexes."]
        for name, cols_expr, kind, pred, note in idx:
            if note:
                lines.append("--")
                lines.append(wrap(note))
            uniq = "UNIQUE " if kind == "UNIQUE" else ""
            lines.append(f"CREATE {uniq}INDEX IF NOT EXISTS {name}")
            lines.append(f"    ON {table} {cols_expr}{(' ' + pred) if pred else ''};")

    return "\n".join(lines) + "\n"


os.makedirs(OUT, exist_ok=True)
for spec in TABLES:
    path = os.path.join(OUT, spec[0] + ".sql")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(emit(*spec))
print(f"wrote {len(TABLES)} table files to {OUT}")
