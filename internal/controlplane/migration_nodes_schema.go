package controlplane

// Private migration evidence is excluded from the target business journal.
// Source YAML and before/after images are encrypted with the retained Vault.
const migrationNodesSchema = `
CREATE TABLE v3_migration_node_sources(
 id text PRIMARY KEY,session text NOT NULL REFERENCES v3_migration_sessions(id),source_id text NOT NULL,
 revision text NOT NULL REFERENCES v3_migration_revisions(id),sequence bigint NOT NULL,
 content_hmac text NOT NULL,key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL,
 request_version bigint NOT NULL,finished_version bigint NOT NULL,report jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(session,source_id,content_hmac),UNIQUE(session,source_id,sequence)
);
CREATE TABLE v3_migration_node_rows(
 source text NOT NULL REFERENCES v3_migration_node_sources(id),node text NOT NULL,
 key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL,
 PRIMARY KEY(source,node)
);
`
