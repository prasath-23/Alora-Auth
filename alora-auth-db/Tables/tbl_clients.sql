/****** Object: Table [tbl_clients] ******/
-- A tenant (organisation). This is the root of every isolation boundary in
-- the schema. Exactly one tenant may be the PLATFORM company: the vendor's
-- own, whose members can be Owners of every other tenant.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_clients (
    id                   TEXT                  NOT NULL DEFAULT gen_random_uuid()::text,
    name                 TEXT                  NOT NULL,
    domain               TEXT                  NULL,
    domain_verified_at   TIMESTAMPTZ           NULL,
    subscription_status  "SubscriptionStatus"  NOT NULL DEFAULT 'TRIAL',
    max_seats            INTEGER               NULL,
    is_active            BOOLEAN               NOT NULL DEFAULT true,
    is_platform          BOOLEAN               NOT NULL DEFAULT false,
    created_at           TIMESTAMPTZ           NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ           NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_clients PRIMARY KEY (id),
    CONSTRAINT CK_tbl_clients_domain_length CHECK (domain IS NULL OR length(domain) <= 253)
);

-- Unique constraints and indexes.
--
-- Only VERIFIED domains are globally unique. An unverified domain must not
-- block another tenant from claiming it, and verification is what ties a
-- domain's users to a tenant, so uniqueness matters only once verified.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_clients_domain_verified
    ON tbl_clients (lower(domain)) WHERE domain IS NOT NULL AND domain_verified_at IS NOT NULL;
--
-- At most one platform company.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_clients_single_platform
    ON tbl_clients (is_platform) WHERE is_platform;
--
-- The target of tbl_platform_owners' composite key, which is what confines
-- Owners to the platform company.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_clients_id_is_platform
    ON tbl_clients (id, is_platform);
