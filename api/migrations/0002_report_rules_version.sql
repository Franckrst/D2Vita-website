-- The rules version a report's signature was computed under (design section
-- 5.3). Kept per report so that a later bump of RULES_VERSION does not rewrite
-- what older reports say, and so that history can be reclassified knowingly.
-- Existing rows were all counted under version 1.
ALTER TABLE reports ADD COLUMN rules_version INTEGER NOT NULL DEFAULT 1;
