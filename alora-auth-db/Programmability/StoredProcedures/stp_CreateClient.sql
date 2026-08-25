/****** Object: Stored Procedure [stp_CreateClient] ******/
-- Provisions a tenant. domain_verified_at is deliberately NOT settable here:
-- a new tenant starts UNVERIFIED, because a verified domain grants CORS
-- trust and governs federated-login tenant resolution.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateClient(p_name TEXT, p_domain TEXT, p_allowedIdpProviders "IdpProvider"[], p_requireMfa BOOLEAN, p_subscriptionStatus "SubscriptionStatus", p_maxSeats INTEGER, p_isActive BOOLEAN)
RETURNS SETOF tbl_clients
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_clients (name, domain, allowed_idp_providers, require_mfa,
                             subscription_status, max_seats, is_active)
    VALUES (p_name, lower(p_domain), p_allowedIdpProviders, p_requireMfa,
            p_subscriptionStatus, p_maxSeats, p_isActive)
    RETURNING *;
$$;
