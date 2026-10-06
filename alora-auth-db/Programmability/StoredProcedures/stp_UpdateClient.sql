/****** Object: Stored Procedure [stp_UpdateClient] ******/
-- Full tenant update. The domain itself changes only through
-- stp_SetClientDomain, and is_platform never changes after creation.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_UpdateClient(p_clientId TEXT, p_name TEXT, p_domainVerifiedAt TIMESTAMPTZ, p_subscriptionStatus "SubscriptionStatus", p_maxSeats INTEGER, p_isActive BOOLEAN)
RETURNS SETOF tbl_clients
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_clients
    SET    name                = p_name,
           domain_verified_at  = p_domainVerifiedAt,
           subscription_status = p_subscriptionStatus,
           max_seats           = p_maxSeats,
           is_active           = p_isActive,
           updated_at          = now()
    WHERE  id = p_clientId
    RETURNING *;
$$;
