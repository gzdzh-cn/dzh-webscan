package controlplane

const websiteBackupSchema = `
CREATE TABLE v3_website_backups(
 id text PRIMARY KEY,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 source text NOT NULL,payload jsonb NOT NULL,digest text NOT NULL,count integer NOT NULL,
 restored_at timestamptz,result jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX v3_website_backups_history ON v3_website_backups(created_at DESC,id DESC);
CREATE INDEX v3_websites_restore_url ON v3_websites(url,deleted,id DESC);
CREATE TABLE v3_website_backup_previews(
 token_hash text PRIMARY KEY,username text NOT NULL,backup text NOT NULL REFERENCES v3_website_backups(id),
 digest text NOT NULL,revision text NOT NULL,expires_at timestamptz NOT NULL,
 used boolean NOT NULL DEFAULT false
);
CREATE INDEX v3_website_backup_pins ON v3_website_backup_previews(backup,expires_at) WHERE NOT used;
INSERT INTO v3_schema(version) VALUES(10);
`
