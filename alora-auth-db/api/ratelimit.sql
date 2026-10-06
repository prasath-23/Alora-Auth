-- ─────────────────────────────────────────────────────────────────────────────
-- API surface: shared rate limiting
--
-- Fixed-window counters kept in the database so several API instances enforce one
-- budget together. RateLimitHit spends a unit atomically (the upsert's row lock
-- serialises concurrent hits of a key across instances); RateLimitPeek reads a
-- key's state without spending; CleanupRateLimitCounters is the periodic sweep.
-- ─────────────────────────────────────────────────────────────────────────────

-- name: RateLimitHit :one
SELECT stp_RateLimitHit($1, $2, $3);

-- name: RateLimitPeek :one
SELECT udf_RateLimitPeek($1, $2);

-- name: CleanupRateLimitCounters :one
SELECT stp_CleanupRateLimitCounters();
