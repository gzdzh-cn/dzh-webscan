package controlplane

// Part of the unpublished schema 37 migration. Policy and task history are
// private business records; the dashboard receives a fixed public projection.
const singleBackupScheduleSchema = `
CREATE TABLE v3_single_backup_policies(
 instance text PRIMARY KEY,sha256 text NOT NULL CHECK(length(sha256)=64),
 policy jsonb NOT NULL,enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE v3_single_backup_runs(
 id text PRIMARY KEY,instance text NOT NULL REFERENCES v3_single_backup_policies(instance),
 policy_sha256 text NOT NULL CHECK(length(policy_sha256)=64),
 status text NOT NULL CHECK(status IN ('running','captured','failed','interrupted','purging','expired')),
 directory text NOT NULL UNIQUE,manifest_sha256 text NOT NULL DEFAULT '',
 files bigint NOT NULL DEFAULT 0,bytes bigint NOT NULL DEFAULT 0,
 restore_validated boolean NOT NULL DEFAULT false,
 reason text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX v3_single_backup_runs_instance ON v3_single_backup_runs(instance,created_at DESC,id DESC);
`
