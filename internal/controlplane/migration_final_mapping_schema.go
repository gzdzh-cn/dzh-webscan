package controlplane

const migrationFinalMappingSchema = `
CREATE TABLE v3_migration_final_batches(
 id text PRIMARY KEY,session text NOT NULL REFERENCES v3_migration_sessions(id),
 request_version bigint NOT NULL,finished_version bigint NOT NULL,revision_digest text NOT NULL,
 report jsonb NOT NULL,key_id text NOT NULL DEFAULT '',candidate_digest text NOT NULL DEFAULT '',
 evidence_digest text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE v3_migration_final_owned(
 session text NOT NULL REFERENCES v3_migration_sessions(id),table_name text NOT NULL,logical_key text NOT NULL,
 key_data jsonb NOT NULL,key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL,
 batch text NOT NULL REFERENCES v3_migration_final_batches(id),
 PRIMARY KEY(session,table_name,logical_key),UNIQUE(session,table_name,key_data)
);
CREATE TABLE v3_migration_final_changes(
 batch text NOT NULL REFERENCES v3_migration_final_batches(id),table_name text NOT NULL,logical_key text NOT NULL,
 operation text NOT NULL CHECK(operation IN ('ADD','UPDATE','DELETE')),
 key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL,
 PRIMARY KEY(batch,table_name,logical_key)
);
`
