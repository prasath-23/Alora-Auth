/****** Object: Stored Procedure [stp_InsertAuditLog] ******/
-- Appends an audit record. INSERT-only by design: no procedure in this
-- schema updates or deletes tbl_audit_logs, which is what makes the trail
-- trustworthy.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_InsertAuditLog(p_clientId TEXT, p_actorUserId TEXT, p_eventType TEXT, p_eventMetadata JSONB, p_ipAddress TEXT, p_userAgent TEXT, p_requestId TEXT)
LANGUAGE sql
AS $$
    INSERT INTO tbl_audit_logs (client_id, actor_user_id, event_type, event_metadata,
                                ip_address, user_agent, request_id)
    VALUES (p_clientId, p_actorUserId, p_eventType, p_eventMetadata,
            p_ipAddress, p_userAgent, p_requestId);
$$;
