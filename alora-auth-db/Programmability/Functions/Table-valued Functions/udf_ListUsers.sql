/****** Object: Table-valued Function [udf_ListUsers] ******/
-- Keyset-paginated user list. Keyset rather than OFFSET because OFFSET
-- degrades linearly and can skip or repeat rows when the set changes between
-- pages. The search term has backslash, percent and underscore escaped, so a
-- caller cannot inject LIKE wildcards to widen the match.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListUsers(p_clientId TEXT, p_search TEXT DEFAULT NULL, p_cursorCreated TIMESTAMPTZ DEFAULT NULL, p_cursorId TEXT DEFAULT NULL, p_take INTEGER DEFAULT 26)
RETURNS SETOF vw_UserListItem
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserListItem v
    WHERE  v.client_id = p_clientId
      AND  (p_search IS NULL
            OR v.email ILIKE '%' || replace(replace(replace(p_search, '\\', '\\\\'),
                                                    '%', '\\%'), '_', '\\_') || '%' ESCAPE '\\')
      AND  (p_cursorCreated IS NULL
            OR (v.created_at, v.id) < (p_cursorCreated, p_cursorId))
    ORDER  BY v.created_at DESC, v.id DESC
    LIMIT  p_take;
$$;
