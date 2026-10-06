/****** Object: Table [tbl_login_states] ******/
-- Short-lived, single-use state for a sign-in in progress: a Google or SSO
-- round trip (nonce and PKCE verifier) or the account chooser after a
-- password matched several accounts. Keyed by the SHA-256 of a random value
-- that only the browser's cookie carries.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_login_states (
    state_hash          TEXT              NOT NULL,
    kind                "LoginStateKind"  NOT NULL,
    connection_id       TEXT              NULL,
    nonce               TEXT              NULL,
    code_verifier       TEXT              NULL,
    return_to           TEXT              NULL,
    candidate_user_ids  TEXT[]            NULL,
    auth_method         "IdpProvider"     NULL,
    expires_at          TIMESTAMPTZ       NOT NULL,
    created_at          TIMESTAMPTZ       NOT NULL DEFAULT now(),
    CONSTRAINT PK_tbl_login_states PRIMARY KEY (state_hash)
);

-- Unique constraints and indexes.
--
-- Serves the cleanup sweep.
CREATE INDEX IF NOT EXISTS IX_tbl_login_states_expires_at
    ON tbl_login_states (expires_at);
