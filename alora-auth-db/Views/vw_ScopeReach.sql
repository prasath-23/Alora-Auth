/****** Object: View [vw_ScopeReach] ******/
-- Rule 2's measure of a person: every App Central scope they hold
-- (vw_EffectiveScope), plus the scopes of each group they manage, since a
-- manager can hand those out. It GRANTS nothing -- the session gate reads
-- vw_EffectiveScope, never this -- it only decides who may act on whom. One
-- row per (scope, source); the reach is the distinct scopes. (A system group
-- never has managers, so the Admins group's implicit scopes need no branch
-- here.)
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_ScopeReach AS
SELECT es.user_id,
       es.client_id,
       es.scope,
       'HELD'::text AS via,
       es.group_id
FROM   vw_EffectiveScope es
UNION ALL
SELECT gm.user_id,
       gm.client_id,
       gs.scope,
       'MANAGES'::text,
       gm.group_id
FROM   tbl_group_managers gm
JOIN   tbl_group_scopes gs ON gs.group_id  = gm.group_id
                          AND gs.client_id = gm.client_id;
