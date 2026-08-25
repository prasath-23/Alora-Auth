/****** Object: View [vw_ValidResetToken] ******/
-- A redeemable password-reset token joined to its owner. Carries the unused
-- and unexpired predicates so no caller can accidentally honour a spent
-- link, and surfaces the owner's state so a reset cannot revive a disabled
-- account.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_ValidResetToken AS
SELECT t.id,
       t.user_id,
       t.client_id,
       t.token_hash,
       u.email,
       u.is_active,
       u.deleted_at
FROM   tbl_password_reset_tokens t
JOIN   tbl_users u ON u.id = t.user_id
WHERE  t.used_at    IS NULL
  AND  t.expires_at  > now();
