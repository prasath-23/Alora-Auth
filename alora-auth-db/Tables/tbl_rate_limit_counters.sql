/****** Object: Table [tbl_rate_limit_counters] ******/
-- Fixed-window rate-limit counters shared across API instances, so several
-- processes behind a load balancer enforce ONE budget instead of each
-- granting it in full. Keyed by '<limiter>:<ip-or-id>'. Rows are ephemeral
-- and best-effort: swept once expired, and safe to lose -- a lost row only
-- resets that one window early. Carries no foreign keys: a key is an opaque
-- string, not a reference.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_rate_limit_counters (
    bucket_key  TEXT         NOT NULL,
    hits        INTEGER      NOT NULL,
    reset_at    TIMESTAMPTZ  NOT NULL,
    CONSTRAINT PK_tbl_rate_limit_counters PRIMARY KEY (bucket_key)
);

-- Unique constraints and indexes.
--
-- Serves the cleanup sweep.
CREATE INDEX IF NOT EXISTS IX_tbl_rate_limit_counters_reset_at
    ON tbl_rate_limit_counters (reset_at);
