/****** Object: View [vw_InvitationProductRole] ******/
-- The products and roles an invitation confers, with the product resolved.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_InvitationProductRole AS
SELECT ip.invitation_id,
       ip.product_id,
       p.key  AS product_key,
       p.name AS product_name,
       ip.role_name
FROM   tbl_invitation_products ip
JOIN   tbl_products p ON p.id = ip.product_id;
