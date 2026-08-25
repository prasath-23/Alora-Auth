/****** Object: Table [tbl_group_features] ******/
-- The feature keys a group grants.
--
-- Idempotent: guarded so re-running the build is safe.

CREATE TABLE IF NOT EXISTS tbl_group_features (
    id           TEXT  NOT NULL DEFAULT gen_random_uuid()::text,
    group_id     TEXT  NOT NULL,
    feature_key  TEXT  NOT NULL,
    CONSTRAINT PK_tbl_group_features PRIMARY KEY (id)
);

-- Foreign keys. Added separately from CREATE TABLE so the build can apply
-- every table first and wire the references afterwards, which removes any
-- ordering requirement between table files.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_tbl_group_features_tbl_groups_group_id') THEN
        ALTER TABLE tbl_group_features ADD CONSTRAINT FK_tbl_group_features_tbl_groups_group_id
            FOREIGN KEY (group_id) REFERENCES tbl_groups (id)
            ON DELETE CASCADE;
    END IF;
END $$;

-- Unique constraints and indexes.
CREATE UNIQUE INDEX IF NOT EXISTS UQ_tbl_group_features_group_feature
    ON tbl_group_features (group_id, feature_key);
--
-- Serves the authorisation check, which looks up by feature key first.
CREATE INDEX IF NOT EXISTS IX_tbl_group_features_feature_group
    ON tbl_group_features (feature_key, group_id);
