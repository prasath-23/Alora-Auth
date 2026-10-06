"""Generates db/Tables/tbl_*.sql — one file per table, following the house
convention: explicit constraint names (PK_/FK_/UQ_/CK_/DF_), idempotent guards,
and each table's own indexes co-located with it.

Run once to (re)materialise the Tables folder:
    python db/gen_tables.py

Kept in the repo so the layout can be regenerated deterministically rather than
hand-maintained across the table files.
"""
import os

OUT = os.path.join(os.path.dirname(__file__), "Tables")

# (table, purpose, [ (column, type, extra) ], [pk cols],
#  [ (name, cols, kind, predicate, note) ],
#  [ (name, child_cols, parent_table, parent_cols, on_delete, note[, extra]) ], notes)
TABLES = [
    ("tbl_clients", "A tenant (organisation). This is the root of every isolation boundary in the schema. "
                    "Exactly one tenant may be the PLATFORM company: the vendor's own, whose "
                    "members can be Owners of every other tenant.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("name", "TEXT", "NOT NULL"),
        ("domain", "TEXT", "NULL"),
        ("domain_verified_at", "TIMESTAMPTZ", "NULL"),
        ("subscription_status", '"SubscriptionStatus"', "NOT NULL DEFAULT 'TRIAL'"),
        ("max_seats", "INTEGER", "NULL"),
        ("is_active", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("is_platform", "BOOLEAN", "NOT NULL DEFAULT false"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_clients_domain_verified", "(lower(domain))", "UNIQUE",
         "WHERE domain IS NOT NULL AND domain_verified_at IS NOT NULL",
         "Only VERIFIED domains are globally unique. An unverified domain must not "
         "block another tenant from claiming it, and verification is what ties a "
         "domain's users to a tenant, so uniqueness matters only once verified."),
        ("UQ_tbl_clients_single_platform", "(is_platform)", "UNIQUE", "WHERE is_platform",
         "At most one platform company."),
        ("UQ_tbl_clients_id_is_platform", "(id, is_platform)", "UNIQUE", "",
         "The target of tbl_platform_owners' composite key, which is what confines "
         "Owners to the platform company."),
    ], [], None),

    ("tbl_products", "The global product catalogue, and each product's registration as a "
                     "CONFIDENTIAL OAuth client. NOT tenant-scoped: products are platform-wide, "
                     "and a tenant's access is expressed by tbl_client_products. A product "
                     "receives application tokens (API clients) only once the Owner switches "
                     "accepts_api_clients on.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("key", "TEXT", "NOT NULL"),
        ("name", "TEXT", "NOT NULL"),
        ("description", "TEXT", "NULL"),
        ("base_url", "TEXT", "NULL"),
        ("initiate_login_uri", "TEXT", "NULL"),
        ("client_secret_hash", "TEXT", "NULL"),
        ("secret_rotated_at", "TIMESTAMPTZ", "NULL"),
        ("is_active", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("accepts_api_clients", "BOOLEAN", "NOT NULL DEFAULT false"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_products_key", "(key)", "UNIQUE", "",
         "The key is embedded in the token audience as product:<key>, so it must "
         "identify exactly one product."),
    ], [], None),

    ("tbl_product_roles", "The role catalogue of a product. Role names become token claims, "
                          "so they are validated against this list rather than free text: a "
                          "typo would otherwise grant nothing, silently.", [
        ("product_id", "TEXT", "NOT NULL"),
        ("role_name", "TEXT", "NOT NULL"),
        ("description", "TEXT", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["product_id", "role_name"], [], [
        ("FK_tbl_product_roles_tbl_products_product_id", "(product_id)", "tbl_products", "(id)", "CASCADE", ""),
    ], None),

    ("tbl_product_redirect_uris", "The exact redirect URIs a product may receive codes at. "
                                  "Matched byte-for-byte, never by prefix or origin.", [
        ("product_id", "TEXT", "NOT NULL"),
        ("redirect_uri", "TEXT", "NOT NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["product_id", "redirect_uri"], [], [
        ("FK_tbl_product_redirect_uris_tbl_products_product_id", "(product_id)", "tbl_products", "(id)", "CASCADE", ""),
    ], None),

    ("tbl_sso_connections", "A tenant's own OIDC identity provider (Okta, Entra ID, Google "
                            "Workspace). The client secret is stored only as ciphertext, "
                            "encrypted with a key held outside the database.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("client_id", "TEXT", "NOT NULL"),
        ("name", "TEXT", "NOT NULL"),
        ("issuer", "TEXT", "NOT NULL"),
        ("oidc_client_id", "TEXT", "NOT NULL"),
        ("client_secret_ciphertext", "BYTEA", "NULL"),
        ("secret_key_id", "TEXT", "NULL"),
        ("scopes", "TEXT", "NOT NULL DEFAULT 'openid email profile'"),
        ("trust_unverified_email", "BOOLEAN", "NOT NULL DEFAULT false"),
        ("is_active", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_sso_connections_id_client_id", "(id, client_id)", "UNIQUE", "",
         "The target of the composite keys that pin policies, identities and "
         "sessions to the connection's own tenant."),
        ("UQ_tbl_sso_connections_client_name", "(client_id, lower(name))", "UNIQUE", "", ""),
        ("UQ_tbl_sso_connections_issuer_client", "(issuer, oidc_client_id)", "UNIQUE", "",
         "One registration at an identity provider serves one connection."),
    ], [
        ("FK_tbl_sso_connections_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
    ], None),

    ("tbl_login_policies", "How a tenant's users may sign in: password, Google, and/or one "
                           "SSO connection. Each tenant has exactly one default; groups and "
                           "users may point at another, and the higher priority wins among "
                           "a user's groups.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("client_id", "TEXT", "NOT NULL"),
        ("name", "TEXT", "NOT NULL"),
        ("allow_password", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("allow_google", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("sso_connection_id", "TEXT", "NULL"),
        ("priority", "INTEGER", "NOT NULL DEFAULT 0"),
        ("is_default", "BOOLEAN", "NOT NULL DEFAULT false"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_login_policies_id_client_id", "(id, client_id)", "UNIQUE", "",
         "The target of the users' and groups' composite keys, so a policy can only "
         "be assigned inside its own tenant."),
        ("UQ_tbl_login_policies_client_name", "(client_id, lower(name))", "UNIQUE", "", ""),
        ("UQ_tbl_login_policies_client_priority", "(client_id, priority)", "UNIQUE", "",
         "Priorities are unique per tenant, so resolving a user in several groups is "
         "never a tie."),
        ("UQ_tbl_login_policies_client_default", "(client_id)", "UNIQUE", "WHERE is_default",
         "Exactly one default per tenant: stp_CreateClient creates it, and "
         "stp_SetDefaultLoginPolicy moves it."),
    ], [
        ("FK_tbl_login_policies_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
        ("FK_tbl_login_policies_sso_connection", "(sso_connection_id, client_id)",
         "tbl_sso_connections", "(id, client_id)", "RESTRICT",
         "A policy can only name its own tenant's connection."),
    ], None),

    ("tbl_scopes", "The closed catalogue of scopes. PERSON scopes are what a person may do in "
                   "App Central (each feature has a read scope and, where it can be changed, an "
                   "edit scope); CLIENT scopes are where an API client's credential may be used. "
                   "Every grant of a scope references this table, so an unknown scope cannot be "
                   "stored, and the ADMINS group's 'every scope' is this table's PERSON rows.", [
        ("scope", "TEXT", "NOT NULL"),
        ("kind", "TEXT", "NOT NULL"),
        ("feature", "TEXT", "NOT NULL"),
        ("level", "TEXT", "NOT NULL"),
        ("description", "TEXT", "NOT NULL"),
        ("sort_order", "INTEGER", "NOT NULL"),
    ], ["scope"], [
        ("UQ_tbl_scopes_scope_kind", "(scope, kind)", "UNIQUE", "",
         "The target of the grant tables' composite keys, which pin each grant to "
         "a scope of the right kind."),
    ], [], None),

    ("tbl_users", "A member of a tenant. Soft-deleted via deleted_at so an audit "
                  "trail survives GDPR erasure of the account.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("client_id", "TEXT", "NOT NULL"),
        ("email", "TEXT", "NOT NULL"),
        ("password_hash", "TEXT", "NULL"),
        ("account_type", '"AccountType"', "NOT NULL DEFAULT 'EMAIL'"),
        ("is_active", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("permissions_version", "INTEGER", "NOT NULL DEFAULT 1"),
        ("admin_version", "INTEGER", "NOT NULL DEFAULT 1"),
        ("login_policy_id", "TEXT", "NULL"),
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
        ("FK_tbl_users_tbl_login_policies_login_policy_id_client_id", "(login_policy_id, client_id)",
         "tbl_login_policies", "(id, client_id)", "RESTRICT",
         "A user's own policy must belong to their tenant."),
    ], None),

    ("tbl_platform_owners", "The Owners: platform staff who manage every tenant. The application "
                            "role can only READ this table, so no application bug can promote "
                            "anyone; rows are written by provisioning, as the schema owner.", [
        ("user_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("is_platform", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["user_id"], [], [
        ("FK_tbl_platform_owners_tbl_users_user_id_client_id", "(user_id, client_id)", "tbl_users", "(id, client_id)", "RESTRICT", ""),
        ("FK_tbl_platform_owners_tbl_clients_client_id_is_platform", "(client_id, is_platform)",
         "tbl_clients", "(id, is_platform)", "RESTRICT",
         "Together with the CHECK, only a member of the platform company can be an Owner."),
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
        ("UQ_tbl_client_products_client_product", "(client_id, product_id)", "UNIQUE", "",
         "Also the target of the composite keys that tie grants and product sessions "
         "to a subscription."),
        ("IX_tbl_client_products_client_active", "(client_id, is_active)", "INDEX", "",
         "Serves the entitlement check on every launch."),
    ], [
        ("FK_tbl_client_products_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "CASCADE", ""),
        ("FK_tbl_client_products_tbl_products_product_id", "(product_id)", "tbl_products", "(id)", "RESTRICT", ""),
    ], None),

    ("tbl_groups", "A named bundle of grants within one tenant: App Central scopes, product "
                   "roles and optionally a login policy. The system group ADMINS is created "
                   "with its tenant, holds every scope, and cannot be renamed, re-scoped or "
                   "deleted.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("client_id", "TEXT", "NOT NULL"),
        ("name", "TEXT", "NOT NULL"),
        ("description", "TEXT", "NULL"),
        ("system_key", "TEXT", "NULL"),
        ("login_policy_id", "TEXT", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_groups_client_name", "(client_id, lower(name))", "UNIQUE", "",
         "Case-insensitive so 'Sales' and 'sales' cannot both exist in one tenant."),
        ("UQ_tbl_groups_id_client_id", "(id, client_id)", "UNIQUE", "",
         "The target of the composite keys that keep memberships, grants and "
         "invitations inside the group's own tenant."),
        ("UQ_tbl_groups_client_system_key", "(client_id, system_key)", "UNIQUE",
         "WHERE system_key IS NOT NULL", "One of each system group per tenant."),
    ], [
        ("FK_tbl_groups_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
        ("FK_tbl_groups_tbl_login_policies_login_policy_id_client_id", "(login_policy_id, client_id)",
         "tbl_login_policies", "(id, client_id)", "RESTRICT", ""),
    ], None),

    ("tbl_session_families", "One login: a CENTRAL family at App Central, or a PRODUCT family a "
                             "product obtained through it. The refresh-token generations of a "
                             "family live in tbl_user_sessions; this row carries what applies to "
                             "all of them, including the absolute lifetime cap.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("user_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("kind", '"SessionKind"', "NOT NULL"),
        ("product_id", "TEXT", "NULL"),
        ("parent_family_id", "TEXT", "NULL"),
        ("auth_method", '"IdpProvider"', "NOT NULL"),
        ("auth_connection_id", "TEXT", "NULL"),
        ("authenticated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("absolute_expires_at", "TIMESTAMPTZ", "NOT NULL"),
        ("revoked_at", "TIMESTAMPTZ", "NULL"),
        ("revoked_reason", '"SessionRevokedReason"', "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_session_families_id_user_client", "(id, user_id, client_id)", "UNIQUE", "",
         "The target of the keys that pin a child family, its generations and its "
         "codes to the same user and tenant as the family itself."),
        ("IX_tbl_session_families_parent_family_id", "(parent_family_id)", "INDEX",
         "WHERE parent_family_id IS NOT NULL", "Revoking a central login revokes its children."),
        ("IX_tbl_session_families_user_live", "(user_id)", "INDEX", "WHERE revoked_at IS NULL", ""),
        ("IX_tbl_session_families_client_live", "(client_id)", "INDEX", "WHERE revoked_at IS NULL",
         "Serves revoking every live login of a whole company on suspension."),
        ("IX_tbl_session_families_absolute_expires_at", "(absolute_expires_at)", "INDEX",
         "WHERE revoked_at IS NULL", "Serves the expiry sweep."),
    ], [
        ("FK_tbl_session_families_tbl_users_user_id_client_id", "(user_id, client_id)", "tbl_users", "(id, client_id)", "CASCADE",
         "TENANT ISOLATION: a family belongs to one user in one tenant."),
        ("FK_tbl_session_families_subscription", "(client_id, product_id)",
         "tbl_client_products", "(client_id, product_id)", "RESTRICT",
         "A product login exists only under that tenant's subscription."),
        ("FK_tbl_session_families_auth_connection", "(auth_connection_id, client_id)",
         "tbl_sso_connections", "(id, client_id)", "RESTRICT", ""),
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
         "Serves revoking every session of a user."),
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
        ("FK_tbl_user_sessions_family", "(family_id, user_id, client_id)",
         "tbl_session_families", "(id, user_id, client_id)", "CASCADE",
         "Every generation belongs to a family of the same user and tenant."),
    ], None),

    ("tbl_product_permissions", "A user's DIRECT role within one product, granted by an Owner. "
                                "Effective access adds the roles the user's groups grant.", [
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
        ("FK_tbl_product_permissions_subscription", "(client_id, product_id)",
         "tbl_client_products", "(client_id, product_id)", "RESTRICT",
         "A role can only be granted in a product the tenant subscribes to."),
        ("FK_tbl_product_permissions_role", "(product_id, role_name)",
         "tbl_product_roles", "(product_id, role_name)", "RESTRICT",
         "The role must be in the product's catalogue; a role still granted cannot be removed from it."),
    ], None),

    ("tbl_group_product_grants", "A product role a group confers on every member.", [
        ("group_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("product_id", "TEXT", "NOT NULL"),
        ("role_name", "TEXT", "NOT NULL"),
        ("granted_by", "TEXT", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["group_id", "product_id"], [
        ("IX_tbl_group_product_grants_client_product", "(client_id, product_id)", "INDEX", "", ""),
    ], [
        ("FK_tbl_group_product_grants_tbl_groups_group_id_client_id", "(group_id, client_id)",
         "tbl_groups", "(id, client_id)", "CASCADE", "TENANT ISOLATION: the grant lives in the group's tenant."),
        ("FK_tbl_group_product_grants_subscription", "(client_id, product_id)",
         "tbl_client_products", "(client_id, product_id)", "RESTRICT",
         "A group can only grant a product its tenant subscribes to."),
        ("FK_tbl_group_product_grants_role", "(product_id, role_name)",
         "tbl_product_roles", "(product_id, role_name)", "RESTRICT", ""),
    ], None),

    ("tbl_group_scopes", "The App Central scopes a group gives its members. The ADMINS group "
                         "holds every scope implicitly and has no rows here.", [
        ("group_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("scope", "TEXT", "NOT NULL"),
        ("kind", "TEXT", "NOT NULL DEFAULT 'PERSON'"),
    ], ["group_id", "scope"], [], [
        ("FK_tbl_group_scopes_tbl_groups_group_id_client_id", "(group_id, client_id)", "tbl_groups",
         "(id, client_id)", "CASCADE", "TENANT ISOLATION: the grant lives in the group's tenant."),
        ("FK_tbl_group_scopes_tbl_scopes_scope_kind", "(scope, kind)", "tbl_scopes", "(scope, kind)",
         "RESTRICT", "Only a person scope from the catalogue can be given."),
    ], None),

    ("tbl_user_scopes", "Extra App Central scopes given to one person, on top of what their "
                        "groups give. Granted by a user of the same tenant or by an Owner.", [
        ("user_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("scope", "TEXT", "NOT NULL"),
        ("kind", "TEXT", "NOT NULL DEFAULT 'PERSON'"),
        ("granted_by_user_id", "TEXT", "NULL"),
        ("granted_by_owner_id", "TEXT", "NULL"),
        ("granted_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["user_id", "scope"], [
        ("IX_tbl_user_scopes_granted_by", "(granted_by_user_id)", "INDEX", "",
         "Child side of a RESTRICT foreign key, probed on every user delete."),
    ], [
        ("FK_tbl_user_scopes_tbl_users_user_id_client_id", "(user_id, client_id)", "tbl_users",
         "(id, client_id)", "CASCADE", "TENANT ISOLATION: the grant lives in the user's tenant."),
        ("FK_tbl_user_scopes_tbl_scopes_scope_kind", "(scope, kind)", "tbl_scopes", "(scope, kind)",
         "RESTRICT", "Only a person scope from the catalogue can be given."),
        ("FK_tbl_user_scopes_tbl_users_granted_by_user_id_client_id", "(granted_by_user_id, client_id)",
         "tbl_users", "(id, client_id)", "RESTRICT",
         "A user who grants must belong to the same tenant."),
        ("FK_tbl_user_scopes_tbl_platform_owners_granted_by_owner_id", "(granted_by_owner_id)",
         "tbl_platform_owners", "(user_id)", "RESTRICT", "An Owner may grant in any tenant."),
    ], None),

    ("tbl_api_clients", "An application's identity: a sync job, a backend or an agent that calls "
                        "products with no person present. Its id is its OAuth client_id -- 'aci_' "
                        "and a uuid, so it can never be mistaken for a product's. It belongs to "
                        "one tenant and holds where its credential may be used (CLIENT scopes), "
                        "which of the tenant's products it may get a token for, and its secrets. "
                        "Created by a user of the tenant or by an Owner, never both.", [
        ("id", "TEXT", "NOT NULL DEFAULT 'aci_' || gen_random_uuid()::text"),
        ("client_id", "TEXT", "NOT NULL"),
        ("name", "TEXT", "NOT NULL"),
        ("description", "TEXT", "NULL"),
        ("is_active", "BOOLEAN", "NOT NULL DEFAULT true"),
        ("created_by_user_id", "TEXT", "NULL"),
        ("created_by_owner_id", "TEXT", "NULL"),
        ("last_used_at", "TIMESTAMPTZ", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
        ("updated_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_api_clients_client_name", "(client_id, lower(name))", "UNIQUE", "",
         "Case-insensitive, like group names, so a tenant can tell its API clients apart."),
        ("UQ_tbl_api_clients_id_client_id", "(id, client_id)", "UNIQUE", "",
         "The target of the composite keys that keep an API client's scopes, products "
         "and secrets inside its own tenant."),
        ("IX_tbl_api_clients_created_by", "(created_by_user_id)", "INDEX", "",
         "Child side of a RESTRICT foreign key, probed on every user delete."),
    ], [
        ("FK_tbl_api_clients_tbl_clients_client_id", "(client_id)", "tbl_clients", "(id)", "RESTRICT", ""),
        ("FK_tbl_api_clients_created_by_user", "(created_by_user_id, client_id)",
         "tbl_users", "(id, client_id)", "RESTRICT",
         "TENANT ISOLATION: a user who creates one must belong to its tenant."),
        ("FK_tbl_api_clients_created_by_owner", "(created_by_owner_id)",
         "tbl_platform_owners", "(user_id)", "RESTRICT", "An Owner may create one in any tenant."),
    ], None),

    ("tbl_api_client_scopes", "Where an API client's credential may be used: CLIENT scopes from "
                              "the catalogue (a product's REST API, its gRPC services, its MCP "
                              "tools). A product token issued to the client carries these, or "
                              "fewer.", [
        ("api_client_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("scope", "TEXT", "NOT NULL"),
        ("kind", "TEXT", "NOT NULL DEFAULT 'CLIENT'"),
    ], ["api_client_id", "scope"], [], [
        ("FK_tbl_api_client_scopes_api_client", "(api_client_id, client_id)",
         "tbl_api_clients", "(id, client_id)", "CASCADE",
         "TENANT ISOLATION: the scope lives in the API client's tenant."),
        ("FK_tbl_api_client_scopes_tbl_scopes_scope_kind", "(scope, kind)", "tbl_scopes", "(scope, kind)",
         "RESTRICT", "Only an application scope from the catalogue can be given."),
    ], None),

    ("tbl_api_client_products", "The products an API client may get a token for, each one its "
                                "tenant subscribes to. Whether the product accepts API clients "
                                "is checked when it is put on the list and again at every token.", [
        ("api_client_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("product_id", "TEXT", "NOT NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["api_client_id", "product_id"], [
        ("IX_tbl_api_client_products_client_product", "(client_id, product_id)", "INDEX", "",
         "Child side of the subscription key."),
    ], [
        ("FK_tbl_api_client_products_api_client", "(api_client_id, client_id)",
         "tbl_api_clients", "(id, client_id)", "CASCADE",
         "TENANT ISOLATION: the entry lives in the API client's tenant."),
        ("FK_tbl_api_client_products_subscription", "(client_id, product_id)",
         "tbl_client_products", "(client_id, product_id)", "RESTRICT",
         "Only a product the tenant subscribes to can be listed."),
    ], None),

    ("tbl_api_client_secrets", "An API client's secrets, as SHA-256 hashes only: the plaintext is "
                               "shown once, when it is made. At most two are live at a time, so a "
                               "secret rotates without downtime -- make a second, deploy it, revoke "
                               "the first. A secret is revoked by stamping revoked_at, never deleted.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("api_client_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("secret_hash", "TEXT", "NOT NULL"),
        ("prefix", "TEXT", "NOT NULL"),
        ("expires_at", "TIMESTAMPTZ", "NULL"),
        ("revoked_at", "TIMESTAMPTZ", "NULL"),
        ("last_used_at", "TIMESTAMPTZ", "NULL"),
        ("created_by_user_id", "TEXT", "NULL"),
        ("created_by_owner_id", "TEXT", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_api_client_secrets_secret_hash", "(secret_hash)", "UNIQUE", "", ""),
        ("IX_tbl_api_client_secrets_api_client", "(api_client_id, client_id)", "INDEX", "",
         "Serves client authentication: the live secrets of one API client."),
        ("IX_tbl_api_client_secrets_created_by", "(created_by_user_id)", "INDEX", "",
         "Child side of a RESTRICT foreign key, probed on every user delete."),
    ], [
        ("FK_tbl_api_client_secrets_api_client", "(api_client_id, client_id)",
         "tbl_api_clients", "(id, client_id)", "CASCADE",
         "TENANT ISOLATION: the secret lives in the API client's tenant."),
        ("FK_tbl_api_client_secrets_created_by_user", "(created_by_user_id, client_id)",
         "tbl_users", "(id, client_id)", "RESTRICT", "A user who makes one must belong to its tenant."),
        ("FK_tbl_api_client_secrets_created_by_owner", "(created_by_owner_id)",
         "tbl_platform_owners", "(user_id)", "RESTRICT", ""),
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
        ("FK_tbl_user_groups_tbl_groups_group_id_client_id", "(group_id, client_id)", "tbl_groups", "(id, client_id)", "CASCADE",
         "TENANT ISOLATION, the other side: the membership's tenant is the group's own."),
    ], None),

    ("tbl_group_managers", "The people who run one group: they add and remove its members, and "
                           "nothing else. Appointed by a user of the same tenant or by an Owner, "
                           "never both, and never by themselves. A system group never has "
                           "managers: stp_AddGroupManager refuses one, since whoever decides the "
                           "Admins group's members decides who is an Admin.", [
        ("group_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("user_id", "TEXT", "NOT NULL"),
        ("appointed_by_user_id", "TEXT", "NULL"),
        ("appointed_by_owner_id", "TEXT", "NULL"),
        ("appointed_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["group_id", "user_id"], [
        ("IX_tbl_group_managers_user_client", "(user_id, client_id)", "INDEX", "",
         "The groups a person manages: read by /api/me, the manager door and rule 2's reach."),
        ("IX_tbl_group_managers_appointed_by", "(appointed_by_user_id)", "INDEX", "",
         "Child side of a RESTRICT foreign key, probed on every user delete."),
    ], [
        ("FK_tbl_group_managers_group", "(group_id, client_id)", "tbl_groups", "(id, client_id)",
         "CASCADE", "TENANT ISOLATION: the appointment lives in the group's tenant."),
        ("FK_tbl_group_managers_user", "(user_id, client_id)", "tbl_users", "(id, client_id)",
         "CASCADE", "TENANT ISOLATION, the other side: only the group's own tenant's users manage it."),
        ("FK_tbl_group_managers_appointed_by_user", "(appointed_by_user_id, client_id)", "tbl_users",
         "(id, client_id)", "RESTRICT", "A user who appoints must belong to the same tenant."),
        ("FK_tbl_group_managers_appointed_by_owner", "(appointed_by_owner_id)", "tbl_platform_owners",
         "(user_id)", "RESTRICT", "An Owner may appoint in any tenant."),
    ], None),

    ("tbl_linked_identities", "An external identity (Google, or a tenant's own OIDC provider) "
                              "bound to a local user. A Google account is linked at most once per "
                              "tenant; an SSO subject once per connection.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("user_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("provider", '"IdpProvider"', "NOT NULL"),
        ("connection_id", "TEXT", "NULL"),
        ("provider_id", "TEXT", "NOT NULL"),
        ("email_verified", "BOOLEAN", "NOT NULL DEFAULT false"),
        ("email_at_link", "TEXT", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_linked_identities_google_subject_client", "(provider_id, client_id)", "UNIQUE",
         "WHERE provider = 'GOOGLE'",
         "provider_id is the provider's STABLE subject id, never the email: a user "
         "who changes their Google address keeps their account, and someone who "
         "acquires a recycled address does not inherit one. One Google account may "
         "serve accounts in several tenants, but only one per tenant."),
        ("UQ_tbl_linked_identities_google_user", "(user_id)", "UNIQUE", "WHERE provider = 'GOOGLE'", ""),
        ("UQ_tbl_linked_identities_oidc_subject", "(connection_id, provider_id)", "UNIQUE",
         "WHERE provider = 'OIDC'", ""),
        ("UQ_tbl_linked_identities_oidc_user", "(user_id, connection_id)", "UNIQUE",
         "WHERE provider = 'OIDC'", ""),
        ("IX_tbl_linked_identities_user_id", "(user_id)", "INDEX", "", ""),
    ], [
        ("FK_tbl_linked_identities_tbl_users_user_id_client_id", "(user_id, client_id)", "tbl_users", "(id, client_id)", "CASCADE", ""),
        ("FK_tbl_linked_identities_connection", "(connection_id, client_id)",
         "tbl_sso_connections", "(id, client_id)", "RESTRICT", ""),
    ], None),

    ("tbl_invitations", "A pending invitation. Only the SHA-256 of the token is stored; "
                        "the raw value exists solely in the email that was sent. Issued by a "
                        "tenant Admin or by an Owner, never both.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("email", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("invited_by_user_id", "TEXT", "NULL"),
        ("invited_by_owner_id", "TEXT", "NULL"),
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
        ("UQ_tbl_invitations_id_client_id", "(id, client_id)", "UNIQUE", "",
         "The target of tbl_invitation_groups' composite key."),
        ("UQ_tbl_invitations_client_email_pending", "(client_id, lower(email))", "UNIQUE",
         "WHERE status = 'PENDING'",
         "One live invitation per address per company, whatever arrives at once: a "
         "re-invite can never leave two independently redeemable tokens, so revoking "
         "an invitation revokes the address's only one. stp_CreateInvitation expires a "
         "pending invitation past its expiry first, so it never blocks a new one."),
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
         "TENANT ISOLATION: an Admin inviter must belong to the invited tenant."),
        ("FK_tbl_invitations_tbl_platform_owners_invited_by_owner_id", "(invited_by_owner_id)",
         "tbl_platform_owners", "(user_id)", "RESTRICT",
         "An Owner may invite into any tenant, which is how a new tenant gets its first Admin."),
    ], None),

    ("tbl_invitation_groups", "The groups an invitation adds its user to on acceptance.", [
        ("invitation_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("group_id", "TEXT", "NOT NULL"),
    ], ["invitation_id", "group_id"], [], [
        ("FK_tbl_invitation_groups_invitation", "(invitation_id, client_id)",
         "tbl_invitations", "(id, client_id)", "CASCADE", ""),
        ("FK_tbl_invitation_groups_tbl_groups_group_id_client_id", "(group_id, client_id)",
         "tbl_groups", "(id, client_id)", "CASCADE",
         "TENANT ISOLATION: an invitation can only offer its own tenant's groups."),
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
        ("FK_tbl_audit_logs_tbl_users_actor_user_id", "(actor_user_id)", "tbl_users", "(id)", "RESTRICT",
         "-- RESTRICT, NOT SET NULL. This was SET NULL, and that quietly defeated the\n"
         "-- whole table: deleting a user made PostgreSQL rewrite existing audit rows and\n"
         "-- erase WHO performed each action. Revoking UPDATE on this table does not\n"
         "-- prevent it, because a referential action runs as the referencing table's\n"
         "-- owner rather than as the caller -- verified against PostgreSQL 16, where the\n"
         "-- app role was refused a direct UPDATE and then erased the same column anyway\n"
         "-- by deleting the user.\n"
         "--\n"
         "-- With RESTRICT, a user who has done anything cannot be hard-deleted at all.\n"
         "-- That costs nothing: every procedure here soft-deletes (deleted_at) and no\n"
         "-- code path in this system hard-deletes a user. Erasure requests are served by\n"
         "-- scrubbing the PII on tbl_users while the actor linkage stays intact, which\n"
         "-- is the outcome you want anyway -- \"some deleted account did this\" is not an\n"
         "-- audit trail."),
    ], None),

    ("tbl_authorization_codes", "A single-use OAuth2 authorization code, stored as its SHA-256 "
                               "only, with its PKCE challenge and the central login that "
                               "authorized it. Redeemed by exactly one atomic UPDATE, so it "
                               "cannot be double-spent.", [
        ("id", "TEXT", "NOT NULL DEFAULT gen_random_uuid()::text"),
        ("code_hash", "TEXT", "NOT NULL"),
        ("product_id", "TEXT", "NOT NULL"),
        ("user_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
        ("parent_family_id", "TEXT", "NOT NULL"),
        ("redirect_uri", "TEXT", "NOT NULL"),
        ("code_challenge", "TEXT", "NOT NULL"),
        ("code_challenge_method", "TEXT", "NOT NULL DEFAULT 'S256'"),
        ("nonce", "TEXT", "NULL"),
        ("scope", "TEXT", "NULL"),
        ("expires_at", "TIMESTAMPTZ", "NOT NULL"),
        ("used_at", "TIMESTAMPTZ", "NULL"),
        ("issued_family_id", "TEXT", "NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["id"], [
        ("UQ_tbl_authorization_codes_code_hash", "(code_hash)", "UNIQUE", "", ""),
        ("IX_tbl_authorization_codes_product_id", "(product_id)", "INDEX", "", ""),
        ("IX_tbl_authorization_codes_user_id", "(user_id)", "INDEX", "", ""),
        ("IX_tbl_authorization_codes_expires_at", "(expires_at)", "INDEX", "", ""),
    ], [
        ("FK_tbl_authorization_codes_tbl_products_product_id", "(product_id)", "tbl_products", "(id)", "RESTRICT", ""),
        ("FK_tbl_authorization_codes_tbl_users_user_id_client_id", "(user_id, client_id)", "tbl_users", "(id, client_id)", "CASCADE", ""),
        ("FK_tbl_authorization_codes_parent_family", "(parent_family_id, user_id, client_id)",
         "tbl_session_families", "(id, user_id, client_id)", "CASCADE",
         "A code is issued under one central login of the same user and tenant."),
        ("FK_tbl_authorization_codes_issued_family", "(issued_family_id)",
         "tbl_session_families", "(id)", "SET NULL",
         "The product login the code produced, revoked if the code is ever replayed."),
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

    ("tbl_login_states", "Short-lived, single-use state for a sign-in in progress: a Google or "
                         "SSO round trip (nonce and PKCE verifier) or the account chooser after "
                         "a password matched several accounts. Keyed by the SHA-256 of a random "
                         "value that only the browser's cookie carries.", [
        ("state_hash", "TEXT", "NOT NULL"),
        ("kind", '"LoginStateKind"', "NOT NULL"),
        ("connection_id", "TEXT", "NULL"),
        ("nonce", "TEXT", "NULL"),
        ("code_verifier", "TEXT", "NULL"),
        ("return_to", "TEXT", "NULL"),
        ("candidate_user_ids", "TEXT[]", "NULL"),
        ("auth_method", '"IdpProvider"', "NULL"),
        ("expires_at", "TIMESTAMPTZ", "NOT NULL"),
        ("created_at", "TIMESTAMPTZ", "NOT NULL DEFAULT now()"),
    ], ["state_hash"], [
        ("IX_tbl_login_states_expires_at", "(expires_at)", "INDEX", "", "Serves the cleanup sweep."),
    ], [], None),

    ("tbl_rate_limit_counters", "Fixed-window rate-limit counters shared across API instances, so "
                                "several processes behind a load balancer enforce ONE budget "
                                "instead of each granting it in full. Keyed by '<limiter>:<ip-or-id>'. "
                                "Rows are ephemeral and best-effort: swept once expired, and safe to "
                                "lose -- a lost row only resets that one window early. Carries no "
                                "foreign keys: a key is an opaque string, not a reference.", [
        ("bucket_key", "TEXT", "NOT NULL"),
        ("hits", "INTEGER", "NOT NULL"),
        ("reset_at", "TIMESTAMPTZ", "NOT NULL"),
    ], ["bucket_key"], [
        ("IX_tbl_rate_limit_counters_reset_at", "(reset_at)", "INDEX", "", "Serves the cleanup sweep."),
    ], [], None),

    ("tbl_sso_connection_domains", "The email domains an Owner attested for an SSO connection. "
                                   "Globally unique, so one domain routes to one connection.", [
        ("domain", "TEXT", "NOT NULL"),
        ("connection_id", "TEXT", "NOT NULL"),
        ("client_id", "TEXT", "NOT NULL"),
    ], ["domain"], [], [
        ("FK_tbl_sso_connection_domains_connection", "(connection_id, client_id)",
         "tbl_sso_connections", "(id, client_id)", "CASCADE", ""),
    ], None),
]

# The audit-actor composite FK is special-cased: it is NO ACTION + DEFERRABLE,
# because the single-column actor FK above is RESTRICT and refuses a delete first.
SPECIAL_FKS = {
    "tbl_audit_logs": [(
        "FK_tbl_audit_logs_tbl_users_actor_user_id_client_id",
        "(actor_user_id, client_id)", "tbl_users", "(id, client_id)",
        "NO ACTION",
        "-- TENANT ISOLATION. Stops an audit row naming an actor from one tenant against\n"
        "-- another tenant's client_id. MATCH SIMPLE (the default) skips the check when\n"
        "-- actor_user_id IS NULL, which is what lets unauthenticated events -- a failed\n"
        "-- login, a password-reset request -- be recorded with no actor.\n"
        "--\n"
        "-- NO ACTION rather than a cascade: the single-column FK above is RESTRICT, so\n"
        "-- a delete is refused before this constraint is ever consulted. DEFERRABLE is\n"
        "-- kept so a procedure may insert the audit row and the user row in either\n"
        "-- order within one transaction.",
        "DEFERRABLE INITIALLY DEFERRED",
    )],
}

# CHECK constraints, emitted inside CREATE TABLE: (name, expression, note).
CHECKS = {
    "tbl_clients": [
        ("CK_tbl_clients_domain_length", "domain IS NULL OR length(domain) <= 253",
         "A domain name is at most 253 characters (RFC 1035)."),
    ],
    "tbl_products": [
        ("CK_tbl_products_initiate_login_uri",
         "initiate_login_uri IS NULL OR initiate_login_uri ~ '^https?://[^#]+$'", ""),
    ],
    "tbl_product_roles": [
        ("CK_tbl_product_roles_role_name", "role_name ~ '^[A-Za-z][A-Za-z0-9 _-]{0,63}$'",
         "Role names travel in tokens, so they stay short and plain."),
    ],
    "tbl_product_redirect_uris": [
        ("CK_tbl_product_redirect_uris_redirect_uri", "redirect_uri ~ '^https?://[^#]+$'",
         "An absolute http(s) URI without a fragment (RFC 6749 3.1.2)."),
    ],
    "tbl_sso_connections": [
        ("CK_tbl_sso_connections_issuer", "issuer ~ '^https?://'",
         "The service additionally requires https in production."),
    ],
    "tbl_login_policies": [
        ("CK_tbl_login_policies_some_method",
         "allow_password OR allow_google OR sso_connection_id IS NOT NULL",
         "A policy that allows no method would lock its users out."),
    ],
    "tbl_platform_owners": [
        ("CK_tbl_platform_owners_is_platform", "is_platform", ""),
    ],
    "tbl_groups": [
        ("CK_tbl_groups_system_key", "system_key IS NULL OR system_key IN ('ADMINS')", ""),
    ],
    "tbl_scopes": [
        ("CK_tbl_scopes_kind", "kind IN ('PERSON', 'CLIENT')", ""),
        ("CK_tbl_scopes_scope", "scope ~ '^[a-z][a-z-]*:[a-z]+$'",
         "feature:level, lower case: scope strings travel in tokens, space-separated."),
        ("CK_tbl_scopes_level", "level IN ('read', 'edit', 'tools')", ""),
    ],
    "tbl_group_scopes": [
        ("CK_tbl_group_scopes_kind", "kind = 'PERSON'", ""),
    ],
    "tbl_user_scopes": [
        ("CK_tbl_user_scopes_kind", "kind = 'PERSON'", ""),
        ("CK_tbl_user_scopes_one_granter", "num_nonnulls(granted_by_user_id, granted_by_owner_id) <= 1", ""),
    ],
    "tbl_group_managers": [
        ("CK_tbl_group_managers_one_appointer",
         "num_nonnulls(appointed_by_user_id, appointed_by_owner_id) = 1", ""),
        ("CK_tbl_group_managers_not_self",
         "appointed_by_user_id IS DISTINCT FROM user_id AND appointed_by_owner_id IS DISTINCT FROM user_id",
         "Nobody appoints themselves: a manager could otherwise keep running a group after losing the "
         "right to change it."),
    ],
    "tbl_api_clients": [
        ("CK_tbl_api_clients_id", "id ~ '^aci_[0-9a-f-]{36}$'",
         "The prefix is how client authentication tells an API client from a product."),
        ("CK_tbl_api_clients_one_creator", "num_nonnulls(created_by_user_id, created_by_owner_id) = 1", ""),
    ],
    "tbl_api_client_scopes": [
        ("CK_tbl_api_client_scopes_kind", "kind = 'CLIENT'", ""),
    ],
    "tbl_api_client_secrets": [
        ("CK_tbl_api_client_secrets_prefix", "prefix ~ '^acc_[A-Za-z0-9_-]{4,12}$'",
         "Enough of the secret to tell two apart on screen, never enough to use."),
        ("CK_tbl_api_client_secrets_one_creator",
         "num_nonnulls(created_by_user_id, created_by_owner_id) = 1", ""),
    ],
    "tbl_session_families": [
        ("CK_tbl_session_families_kind",
         "(kind = 'CENTRAL' AND product_id IS NULL AND parent_family_id IS NULL) OR "
         "(kind = 'PRODUCT' AND product_id IS NOT NULL AND parent_family_id IS NOT NULL)",
         "A central login has no product and no parent; a product login has both."),
        ("CK_tbl_session_families_auth_connection",
         "(auth_method = 'OIDC') = (auth_connection_id IS NOT NULL)", ""),
    ],
    "tbl_linked_identities": [
        ("CK_tbl_linked_identities_provider", "provider IN ('GOOGLE', 'OIDC')", ""),
        ("CK_tbl_linked_identities_connection",
         "(provider = 'OIDC') = (connection_id IS NOT NULL)", ""),
        ("CK_tbl_linked_identities_provider_id_length", "length(provider_id) BETWEEN 1 AND 255",
         "A provider's subject is at most 255 characters (OpenID Connect Core 2)."),
    ],
    "tbl_invitations": [
        ("CK_tbl_invitations_one_inviter",
         "num_nonnulls(invited_by_user_id, invited_by_owner_id) = 1", ""),
    ],
    "tbl_sso_connection_domains": [
        ("CK_tbl_sso_connection_domains_lower", "domain = lower(domain)", ""),
        ("CK_tbl_sso_connection_domains_length", "length(domain) BETWEEN 1 AND 253",
         "A domain name is at most 253 characters (RFC 1035)."),
    ],
}

# Reference rows emitted at the end of a table's own file, as an upsert: the build
# keeps them current (a changed description is updated in place) and never
# deletes one, since a grant may still name it. The Go registry in
# internal/core/shared/scopes.go must list exactly these; a test holds the two in
# step.
SEEDS = {
    "tbl_scopes": {
        "columns": ["scope", "kind", "feature", "level", "description", "sort_order"],
        "conflict": "scope",
        "rows": [
            ("users:read", "PERSON", "users", "read", "See the company's users", 10),
            ("users:edit", "PERSON", "users", "edit",
             "Activate and deactivate users, send password resets, give extra scopes", 11),
            ("groups:read", "PERSON", "groups", "read", "See groups and their members", 20),
            ("groups:edit", "PERSON", "groups", "edit",
             "Create, rename and delete groups, choose their scopes, add and remove members", 21),
            ("invitations:read", "PERSON", "invitations", "read", "See invitations", 30),
            ("invitations:edit", "PERSON", "invitations", "edit",
             "Invite people into groups, revoke invitations", 31),
            ("sessions:read", "PERSON", "sessions", "read", "See who is signed in", 40),
            ("sessions:edit", "PERSON", "sessions", "edit", "Revoke sessions", 41),
            ("products:read", "PERSON", "products", "read", "See the company's subscriptions", 50),
            ("company:read", "PERSON", "company", "read", "See the company's settings", 60),
            ("company:edit", "PERSON", "company", "edit", "Rename the company", 61),
            ("api-clients:read", "PERSON", "api-clients", "read", "See API clients", 70),
            ("api-clients:edit", "PERSON", "api-clients", "edit",
             "Create API clients, rotate their secrets, choose their products and scope", 71),
            ("api:read", "CLIENT", "api", "read", "Read through the product's REST API", 110),
            ("api:edit", "CLIENT", "api", "edit", "Change data through the product's REST API", 111),
            ("grpc:read", "CLIENT", "grpc", "read", "Read through the product's gRPC services", 120),
            ("grpc:edit", "CLIENT", "grpc", "edit", "Change data through the product's gRPC services", 121),
            ("mcp:tools", "CLIENT", "mcp", "tools", "Use the product's MCP tools", 130),
        ],
    },
}


def seed_lines(table):
    spec = SEEDS[table]
    cols = spec["columns"]

    def lit(v):
        return str(v) if isinstance(v, int) else "'" + v.replace("'", "''") + "'"

    out = ["", "-- Reference rows: upserted on every build, never deleted here (a grant may",
           "-- still name one).",
           f"INSERT INTO {table} ({', '.join(cols)}) VALUES"]
    rows = [f"    ({', '.join(lit(v) for v in row)})" for row in spec["rows"]]
    out.append(",\n".join(rows))
    keep = [c for c in cols if c != spec["conflict"]]
    out.append(f"ON CONFLICT ({spec['conflict']}) DO UPDATE")
    out.append("SET    " + ",\n       ".join(f"{c} = EXCLUDED.{c}" for c in keep) + ";")
    return out


# Foreign keys emitted AFTER the table's own indexes: a self-reference, or a key
# whose target unique index is created in the same file.
LATE_FKS = {
    "tbl_session_families": [(
        "FK_tbl_session_families_parent_family", "(parent_family_id, user_id, client_id)",
        "tbl_session_families", "(id, user_id, client_id)", "CASCADE",
        "A product login's parent is a central login of the SAME user and tenant, and "
        "revoking the parent revokes it.",
    )],
}


# Word-wraps each line of text as a comment. A line already starting with "--" is
# kept verbatim, so a hand-written note survives regeneration.
def wrap(text, width=74, indent="-- "):
    lines = []
    for para in text.split("\n"):
        if para.startswith("--"):
            lines.append(para)
            continue
        cur = ""
        for w in para.split():
            if len(cur) + len(w) + 1 > width:
                lines.append(indent + cur)
                cur = w
            else:
                cur = (cur + " " + w).strip()
        if cur:
            lines.append(indent + cur)
    return "\n".join(lines)


def fk_lines(table, fk):
    name, child, parent, pcols, ondel = fk[0], fk[1], fk[2], fk[3], fk[4]
    note = fk[5] if len(fk) > 5 else ""
    extra = fk[6] if len(fk) > 6 else ""
    out = []
    if note:
        out.append("--")
        out.append(wrap(note))
    out.append("DO $$ BEGIN")
    out.append(f"    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '{name.lower()}') THEN")
    out.append(f"        ALTER TABLE {table} ADD CONSTRAINT {name}")
    out.append(f"            FOREIGN KEY {child} REFERENCES {parent} {pcols}")
    out.append(f"            ON DELETE {ondel}{(' ' + extra) if extra else ''};")
    out.append("    END IF;")
    out.append("END $$;")
    return out


def check_names(table, idx, fks):
    names = [f"PK_{table}"] + [i[0] for i in idx] + [f[0] for f in fks]
    names += [c[0] for c in CHECKS.get(table, [])] + [f[0] for f in LATE_FKS.get(table, [])]
    for n in names:
        assert len(n) <= 63, f"{n}: {len(n)} characters; PostgreSQL would truncate it to 63"


def emit(table, purpose, cols, pk, idx, fks, _notes):
    check_names(table, idx, fks)
    w = max(len(c[0]) for c in cols) + 2
    t = max(len(c[1]) for c in cols) + 2
    lines = [f"/****** Object: Table [{table}] ******/", wrap(purpose), "--",
             wrap("Idempotent: guarded so re-running the build is safe."), ""]
    lines.append(f"CREATE TABLE IF NOT EXISTS {table} (")
    body = [f"    {c[0]:<{w}}{c[1]:<{t}}{c[2]}" for c in cols]
    body.append(f"    CONSTRAINT PK_{table} PRIMARY KEY ({', '.join(pk)})")
    for name, expr, _note in CHECKS.get(table, []):
        body.append(f"    CONSTRAINT {name} CHECK ({expr})")
    lines.append(",\n".join(body))
    lines.append(");")

    if fks or table in SPECIAL_FKS:
        lines += ["", "-- Foreign keys. Added separately from CREATE TABLE so the build can apply",
                  "-- every table first and wire the references afterwards, which removes any",
                  "-- ordering requirement between table files."]
        for fk in list(fks) + SPECIAL_FKS.get(table, []):
            lines += fk_lines(table, fk)

    if idx:
        lines += ["", "-- Unique constraints and indexes."]
        for name, cols_expr, kind, pred, note in idx:
            if note:
                lines.append("--")
                lines.append(wrap(note))
            uniq = "UNIQUE " if kind == "UNIQUE" else ""
            lines.append(f"CREATE {uniq}INDEX IF NOT EXISTS {name}")
            lines.append(f"    ON {table} {cols_expr}{(' ' + pred) if pred else ''};")

    if table in LATE_FKS:
        lines += ["", "-- Foreign keys that target an index created above."]
        for fk in LATE_FKS[table]:
            lines += fk_lines(table, fk)

    if table in SEEDS:
        lines += seed_lines(table)

    return "\n".join(lines) + "\n"


os.makedirs(OUT, exist_ok=True)
for spec in TABLES:
    path = os.path.join(OUT, spec[0] + ".sql")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(emit(*spec))
print(f"wrote {len(TABLES)} table files to {OUT}")
