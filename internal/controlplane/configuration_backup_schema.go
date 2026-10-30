package controlplane

// Ciphertext is split into bounded rows so a maximum-sized document still fits
// the existing PostgreSQL JSONL backup/restore line limit (bytea becomes hex).
const configurationBackupSchema = `
CREATE TABLE v3_configuration_backups(
 id text PRIMARY KEY,source text NOT NULL CHECK(source IN ('manual','before_edit','before_deploy','before_restore','import')),
 created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 document_created_at text NOT NULL,settings_version bigint NOT NULL CHECK(settings_version>0),
 node_count integer NOT NULL CHECK(node_count BETWEEN 0 AND 20000),needs_completion boolean NOT NULL,
 key_id text NOT NULL,revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),nonce bytea NOT NULL,
 ciphertext_bytes integer NOT NULL CHECK(ciphertext_bytes BETWEEN 17 AND 33554448)
);
CREATE INDEX v3_configuration_backups_history ON v3_configuration_backups(created_at DESC,id DESC);
CREATE TABLE v3_configuration_backup_parts(
 backup text NOT NULL REFERENCES v3_configuration_backups(id) ON DELETE CASCADE,
 part integer NOT NULL CHECK(part BETWEEN 0 AND 32),payload bytea NOT NULL CHECK(octet_length(payload) BETWEEN 1 AND 1048576),
 PRIMARY KEY(backup,part)
);
CREATE TABLE v3_configuration_backup_pins(
 backup text NOT NULL REFERENCES v3_configuration_backups(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('export','restore','deployment','rollback')),reference text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz,
 CHECK(kind<>'export' OR expires_at IS NOT NULL),PRIMARY KEY(backup,kind,reference)
);
CREATE INDEX v3_configuration_backup_pins_expiry ON v3_configuration_backup_pins(expires_at) WHERE expires_at IS NOT NULL;
INSERT INTO v3_schema(version) VALUES(14);
`
