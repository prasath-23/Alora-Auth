/****** Object: Stored Procedure [stp_UpdateClient] ******/
-- Full tenant update. The domain itself is immutable here — changing it
-- would move CORS trust to a new origin, which must be an explicit,
-- separately audited operation.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_UpdateClient(p_clientId TEXT, p_name TEXT, p_requireMfa BOOLEAN, p_allowedIdpProviders "IdpProvider"[], p_domainVerifiedAt TIMESTAMPTZ, p_subscriptionStatus "SubscriptionStatus", p_maxSeats INTEGER, p_isActive BOOLEAN)
RETURNS SETOF tbl_clients
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_clients
    SET    name                  = p_name,
           require_mfa           = p_requireMfa,
           allowed_idp_providers = p_allowedIdpProviders,
           domain_verified_at    = p_domainVerifiedAt,
           subscription_status   = p_subscriptionStatus,
           max_seats             = p_maxSeats,
           is_active             = p_isActive,
           updated_at            = now()
    WHERE  id = p_clientId
    RETURNING *;
$$;
