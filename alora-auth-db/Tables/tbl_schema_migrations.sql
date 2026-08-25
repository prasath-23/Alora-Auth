/****** Object: Table [tbl_schema_migrations] ******/
-- Ledger of which versioned migration scripts have been applied.
--
-- The object scripts under Tables/, Views/ and Programmability/ are idempotent
-- and simply re-applied on every build. This table exists for the changes that
-- CANNOT be expressed that way — a column rename, a backfill, a type narrowing —
-- where re-running would corrupt data or fail. Each such script runs exactly
-- once, and this is the record of it.
--
-- checksum is stored so an already-applied script that has since been EDITED is
-- detected: silently ignoring the edit would leave environments diverged with no
-- signal.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_schema_migrations (
    version      TEXT         NOT NULL,
    checksum     TEXT         NOT NULL,
    applied_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    applied_by   TEXT         NOT NULL DEFAULT current_user,
    duration_ms  INTEGER      NULL,
    CONSTRAINT PK_tbl_schema_migrations PRIMARY KEY (version)
);
