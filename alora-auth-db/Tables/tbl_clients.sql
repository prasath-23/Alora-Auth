/****** Object: Table [tbl_clients] ******/
-- A tenant (organisation). This is the root of every isolation boundary in
-- the schema.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_clients (
    id                     TEXT                  NOT NULL DEFAULT gen_random_uuid()::text,
    name                   TEXT                  NOT NULL,
    domain                 TEXT                  NULL,
    domain_verified_at     TIMESTAMPTZ           NULL,
    allowed_idp_providers  "IdpProvider"[]       NULL DEFAULT ARRAY['EMAIL','GOOGLE']::"IdpProvider"[],
    require_mfa            BOOLEAN               NOT NULL DEFAULT false,
    subscription_status    "SubscriptionStatus"  NOT NULL DEFAULT 'TRIAL',
    max_seats              INTEGER               NULL,
    is_active              BOOLEAN               NOT NULL DEFAULT true,
    created_at             TIMESTAMPTZ           NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ           NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_clients PRIMARY KEY (id)
);

-- Unique constraints and indexes.
--
-- Only VERIFIED domains are globally unique. An unverified domain must not
-- block another tenant from claiming it, and verification is what grants
-- CORS trust, so uniqueness matters only once verified.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_clients_domain_verified
    ON tbl_clients (lower(domain)) WHERE domain IS NOT NULL AND domain_verified_at IS NOT NULL;
