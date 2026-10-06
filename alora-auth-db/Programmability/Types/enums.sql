/****** Object: Types (enumerations) ******/
-- Enumerated domains shared across tables. Kept together because they form one
-- logical unit: adding a value here is the only way to extend any of the state
-- machines below, and reviewing them side by side prevents drift.
--
-- Deliberately written as PLAIN CREATE TYPE statements with no DO-block guard.
-- Wrapping them in `DO $$ ... $$` makes them invisible to sqlc's parser, which
-- silently degrades every enum column to interface{} and every enum array to
-- []interface{} in the generated Go — losing the type safety these exist for.
-- Idempotency is handled by build.sql, which includes this file only when the
-- types are absent.

CREATE TYPE "SubscriptionStatus"   AS ENUM ('TRIAL', 'ACTIVE', 'SUSPENDED', 'CANCELLED');
CREATE TYPE "IdpProvider"          AS ENUM ('EMAIL', 'GOOGLE', 'MICROSOFT', 'SAML', 'OIDC');
CREATE TYPE "AccountType"          AS ENUM ('EMAIL', 'OAUTH_ONLY', 'HYBRID');
CREATE TYPE "SessionRevokedReason" AS ENUM ('LOGOUT', 'LOGOUT_ALL', 'REUSE_DETECTED', 'ADMIN', 'EXPIRED', 'POLICY', 'ACCESS_LOST', 'SUSPENDED');
CREATE TYPE "InvitationStatus"     AS ENUM ('PENDING', 'ACCEPTED', 'EXPIRED', 'REVOKED');
CREATE TYPE "SessionKind"          AS ENUM ('CENTRAL', 'PRODUCT');
CREATE TYPE "LoginStateKind"       AS ENUM ('GOOGLE', 'OIDC', 'ACCOUNT_CHOICE');
