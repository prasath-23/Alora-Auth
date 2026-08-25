/****** Migration: 0001_audit_actor_restrict ******/
-- Stops a user deletion from erasing that user from the audit trail.
--
-- THE PROBLEM
-- FK_tbl_audit_logs_tbl_users_actor_user_id was ON DELETE SET NULL. Deleting a
-- user therefore made PostgreSQL rewrite every audit row that named them,
-- replacing the actor with NULL. The trail survived; the answer to "who did
-- this" did not.
--
-- Revoking UPDATE on tbl_audit_logs does not prevent this. A referential action
-- executes as the owner of the referencing table, not as the caller, so the
-- grant is never consulted. Verified on PostgreSQL 16: the application role was
-- refused `UPDATE tbl_audit_logs SET actor_user_id = NULL` with "permission
-- denied", then achieved exactly that result by deleting the user.
--
-- THE FIX
-- RESTRICT. A user with history cannot be hard-deleted; the delete fails loudly
-- instead of succeeding destructively. Nothing in this system hard-deletes a
-- user (every procedure sets deleted_at), so no working code path changes.
--
-- If you need to remove a person's data, scrub the PII on tbl_users and leave
-- the id in place. The audit trail keeps referring to an id, which is what an
-- audit trail is for.

-- One transaction, per the rule in this folder's README: if the verification at
-- the bottom fails, the constraint change rolls back with it rather than leaving
-- a database nobody has checked.
BEGIN;

-- Guarded so this is safe to run against a database that was already built from
-- the corrected table definition, where the constraint is RESTRICT already.
DO $$
DECLARE
    v_action "char";
BEGIN
    SELECT confdeltype INTO v_action
    FROM   pg_constraint
    WHERE  conname = 'fk_tbl_audit_logs_tbl_users_actor_user_id';

    IF v_action IS NULL THEN
        RAISE NOTICE 'constraint absent; the object build will create it as RESTRICT';
        RETURN;
    END IF;

    IF v_action = 'r' THEN
        RAISE NOTICE 'already RESTRICT; nothing to do';
        RETURN;
    END IF;

    -- Any audit row already stripped by the old behaviour cannot be recovered:
    -- the actor is gone and nothing recorded what it was. Report the damage
    -- rather than let a silent migration imply the trail is sound.
    RAISE NOTICE 'audit rows with no actor (may include pre-existing erasures): %',
        (SELECT count(*) FROM tbl_audit_logs WHERE actor_user_id IS NULL);

    ALTER TABLE tbl_audit_logs DROP CONSTRAINT FK_tbl_audit_logs_tbl_users_actor_user_id;
    ALTER TABLE tbl_audit_logs ADD  CONSTRAINT FK_tbl_audit_logs_tbl_users_actor_user_id
        FOREIGN KEY (actor_user_id) REFERENCES tbl_users (id)
        ON DELETE RESTRICT;

    RAISE NOTICE 'audit actor FK is now ON DELETE RESTRICT';
END $$;

-- Fails the migration rather than leaving the trail quietly erasable.
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE  conname = 'fk_tbl_audit_logs_tbl_users_actor_user_id'
          AND  confdeltype = 'r'
    ) THEN
        RAISE EXCEPTION 'audit actor FK is not ON DELETE RESTRICT after migration';
    END IF;
END $$;

COMMIT;
