package controlplane

// The public table contains only normalized, non-executable history. Complete
// source rows and original log/configuration bytes stay Vault authenticated.
const migrationLegacyHistorySchema = `
CREATE TABLE v3_legacy_history(
 id text PRIMARY KEY,session text NOT NULL REFERENCES v3_migration_sessions(id),
 source_id text NOT NULL,role text NOT NULL,table_name text NOT NULL,record_key bigint NOT NULL,
 payload jsonb NOT NULL,UNIQUE(session,source_id,table_name,record_key)
);
CREATE INDEX v3_legacy_history_source ON v3_legacy_history(session,role,table_name,record_key);
CREATE TABLE v3_migration_legacy_history_rows(
 id text PRIMARY KEY REFERENCES v3_legacy_history(id) ON DELETE CASCADE,
 revision text NOT NULL REFERENCES v3_migration_revisions(id),archive_digest text NOT NULL,
 key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL
);
CREATE TABLE v3_migration_legacy_history_runs(
 session text NOT NULL REFERENCES v3_migration_sessions(id),revision text NOT NULL REFERENCES v3_migration_revisions(id),
 source_id text NOT NULL,role text NOT NULL,report jsonb NOT NULL,
 key_id text NOT NULL,evidence_digest text NOT NULL,rows_digest text NOT NULL,
 request_version bigint NOT NULL,finished_version bigint NOT NULL,
 PRIMARY KEY(session,revision)
);
`
