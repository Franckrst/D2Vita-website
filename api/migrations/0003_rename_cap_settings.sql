-- The caps were renamed to the names of admin.v1#Caps (every one now says
-- _per_day, and the dev/test pair says prerelease_). loadSettings ignores a
-- `cap:` key it does not know, so a database carried over from wave 1 would
-- have gone back to the compiled defaults without a word. Rename the eight
-- stored overrides instead. If the new name is already set, that value wins
-- and the old row is dropped.
UPDATE OR IGNORE settings SET key = 'cap:install_claims_per_day'                       WHERE key = 'cap:install_claims';
UPDATE OR IGNORE settings SET key = 'cap:install_artifact_bytes_per_day'               WHERE key = 'cap:install_artifact_bytes';
UPDATE OR IGNORE settings SET key = 'cap:prerelease_install_claims_per_day'            WHERE key = 'cap:install_claims_dev';
UPDATE OR IGNORE settings SET key = 'cap:prerelease_install_artifact_bytes_per_day'    WHERE key = 'cap:install_artifact_bytes_dev';
UPDATE OR IGNORE settings SET key = 'cap:ip_claims_per_day'                            WHERE key = 'cap:ip_claims';
UPDATE OR IGNORE settings SET key = 'cap:ip_bugs_per_day'                              WHERE key = 'cap:ip_bugs';
UPDATE OR IGNORE settings SET key = 'cap:global_claims_per_day'                        WHERE key = 'cap:global_claims';
UPDATE OR IGNORE settings SET key = 'cap:global_artifact_bytes_per_day'                WHERE key = 'cap:global_artifact_bytes';
UPDATE OR IGNORE settings SET key = 'cap:global_new_signatures_per_day'                WHERE key = 'cap:global_new_signatures';
UPDATE OR IGNORE settings SET key = 'cap:global_bugs_per_day'                          WHERE key = 'cap:global_bugs';

DELETE FROM settings WHERE key IN (
  'cap:install_claims',
  'cap:install_artifact_bytes',
  'cap:install_claims_dev',
  'cap:install_artifact_bytes_dev',
  'cap:ip_claims',
  'cap:ip_bugs',
  'cap:global_claims',
  'cap:global_artifact_bytes',
  'cap:global_new_signatures',
  'cap:global_bugs'
);
