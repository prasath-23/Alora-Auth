/****** Object: View [vw_EffectiveScope] ******/
-- Every App Central scope a person holds, one row per (scope, source): from
-- each group they belong to (the ADMINS group gives every person scope in
-- the catalogue), and their own extras. A scope held twice appears twice,
-- once per source; the effective set is the distinct scopes. Groups are
-- joined on their OWN client_id, so another tenant's group can never give
-- anything here. (The extras branch comes first so the group columns are
-- typed as nullable.)
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_EffectiveScope AS
SELECT us.user_id,
       us.client_id,
       us.scope,
       'EXTRA'::text AS source,
       NULL::text    AS group_id,
       NULL::text    AS group_name
FROM   tbl_user_scopes us
UNION ALL
SELECT ug.user_id,
       ug.client_id,
       s.scope,
       'GROUP'::text,
       g.id,
       g.name
FROM   tbl_user_groups ug
JOIN   tbl_groups g ON g.id         = ug.group_id
                   AND g.client_id  = ug.client_id
                   AND g.system_key = 'ADMINS'
JOIN   tbl_scopes s ON s.kind = 'PERSON'
UNION ALL
SELECT ug.user_id,
       ug.client_id,
       gs.scope,
       'GROUP'::text,
       g.id,
       g.name
FROM   tbl_user_groups ug
JOIN   tbl_groups g        ON g.id        = ug.group_id
                          AND g.client_id = ug.client_id
JOIN   tbl_group_scopes gs ON gs.group_id  = g.id
                          AND gs.client_id = g.client_id;
