/****** Object: Stored Procedure [stp_CreateClient] ******/
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
