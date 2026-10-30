package controlplane

// A preview is a short-lived explanation, never an authorization to deploy or
// proof that local files exist. Only keyed proofs and safe summaries persist.
const configurationRestoreSchema = `
CREATE TABLE v3_configuration_restore_previews(
 token_hash text PRIMARY KEY,username text NOT NULL REFERENCES v3_accounts(username),
 account_revision bigint NOT NULL CHECK(account_revision>0),
 backup text NOT NULL REFERENCES v3_configuration_backups(id) ON DELETE CASCADE,
 options jsonb NOT NULL,archive_proof text NOT NULL,state_proof text NOT NULL,
 summary jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes'
);
CREATE INDEX v3_configuration_restore_preview_owner ON v3_configuration_restore_previews(username,expires_at);
CREATE INDEX v3_configuration_restore_preview_expiry ON v3_configuration_restore_previews(expires_at,token_hash);
INSERT INTO v3_schema(version) VALUES(16);
`
