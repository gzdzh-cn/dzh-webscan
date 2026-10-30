package controlplane

const configurationDeleteSchema = `
CREATE TABLE v3_configuration_delete_previews(
 id text PRIMARY KEY,username text NOT NULL,settings_version bigint NOT NULL,
 records jsonb NOT NULL CHECK(jsonb_typeof(records)='array' AND jsonb_array_length(records) BETWEEN 1 AND 200),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes',used boolean NOT NULL DEFAULT false
);
CREATE INDEX v3_configuration_delete_preview_owner ON v3_configuration_delete_previews(username,expires_at) WHERE NOT used;
CREATE INDEX v3_configuration_delete_preview_expiry ON v3_configuration_delete_previews(expires_at,id);
CREATE TABLE v3_configuration_delete_jobs(
 id text PRIMARY KEY,username text NOT NULL,preview text NOT NULL UNIQUE REFERENCES v3_configuration_delete_previews(id),
 settings_version bigint NOT NULL,selected integer NOT NULL CHECK(selected BETWEEN 1 AND 200),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','partial','cancelled')),
 deleted integer NOT NULL DEFAULT 0,skipped integer NOT NULL DEFAULT 0,failed integer NOT NULL DEFAULT 0,
 message text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),finished_at timestamptz,
 CHECK(deleted>=0 AND skipped>=0 AND failed>=0 AND deleted+skipped+failed<=selected)
);
CREATE INDEX v3_configuration_delete_job_pending ON v3_configuration_delete_jobs(created_at,id) WHERE status IN ('queued','running');
CREATE INDEX v3_configuration_delete_job_owner ON v3_configuration_delete_jobs(username,created_at DESC,id DESC);
CREATE TABLE v3_configuration_delete_items(
 job text NOT NULL REFERENCES v3_configuration_delete_jobs(id) ON DELETE CASCADE,
 ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 200),backup text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','deleted','skipped','failed')),reason text NOT NULL DEFAULT '',
 PRIMARY KEY(job,ordinal),UNIQUE(job,backup)
);
CREATE UNIQUE INDEX v3_configuration_delete_pending_backup ON v3_configuration_delete_items(backup) WHERE status='pending';
INSERT INTO v3_schema(version) VALUES(15);
`
