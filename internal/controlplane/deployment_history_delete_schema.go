package controlplane

// Archiving hides public history and removes logs only. The original jobs,
// installation evidence, idempotency receipts and recovery ancestry survive.
const deploymentHistoryDeleteSchema = `
CREATE TABLE v3_deployment_history_delete_previews(
 id text PRIMARY KEY,username text NOT NULL REFERENCES v3_accounts(username),
 account_revision bigint NOT NULL CHECK(account_revision>0),settings_version bigint NOT NULL,
 operation_generation bigint NOT NULL,state_digest text NOT NULL CHECK(length(state_digest)=64),
 records jsonb NOT NULL CHECK(jsonb_typeof(records)='array' AND jsonb_array_length(records) BETWEEN 1 AND 200),
 used boolean NOT NULL DEFAULT false,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes'
);
CREATE INDEX v3_deployment_history_delete_preview_owner ON v3_deployment_history_delete_previews(username,expires_at) WHERE NOT used;
CREATE TABLE v3_deployment_history_delete_jobs(
 id text PRIMARY KEY,username text NOT NULL,account_revision bigint NOT NULL CHECK(account_revision>0),
 preview text NOT NULL UNIQUE REFERENCES v3_deployment_history_delete_previews(id),
 selected integer NOT NULL CHECK(selected BETWEEN 1 AND 200),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','partial','cancelled')),
 deleted integer NOT NULL DEFAULT 0,skipped integer NOT NULL DEFAULT 0,failed integer NOT NULL DEFAULT 0,
 message text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),finished_at timestamptz,
 CHECK(deleted>=0 AND skipped>=0 AND failed>=0 AND deleted+skipped+failed<=selected),
 CHECK((status IN ('succeeded','partial','cancelled'))=(finished_at IS NOT NULL))
);
CREATE INDEX v3_deployment_history_delete_job_pending ON v3_deployment_history_delete_jobs(created_at,id) WHERE status IN ('queued','running');
CREATE TABLE v3_deployment_history_delete_items(
 job text NOT NULL REFERENCES v3_deployment_history_delete_jobs(id),ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 200),
 deployment text NOT NULL,state_digest text NOT NULL CHECK(length(state_digest)=64),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','deleted','skipped','failed')),
 reason text NOT NULL DEFAULT '',deleted_logs bigint NOT NULL DEFAULT 0 CHECK(deleted_logs>=0),
 PRIMARY KEY(job,ordinal),UNIQUE(job,deployment)
);
CREATE UNIQUE INDEX v3_deployment_history_delete_pending ON v3_deployment_history_delete_items(deployment) WHERE status='pending';
CREATE TABLE v3_deployment_history_archives(
 deployment text PRIMARY KEY REFERENCES v3_deployment_jobs(id),
 deletion text NOT NULL REFERENCES v3_deployment_history_delete_jobs(id),
 username text NOT NULL,actor_revision bigint NOT NULL CHECK(actor_revision>0),
 plan_digest text NOT NULL CHECK(length(plan_digest)=64),log_cursor bigint NOT NULL CHECK(log_cursor>=0),
 deleted_logs bigint NOT NULL CHECK(deleted_logs>=0),created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX v3_deployment_recovery_head ON v3_deployment_recoveries(head);
CREATE INDEX v3_deployment_success_baseline ON v3_deployment_jobs(node,created_at DESC,id DESC) WHERE status='succeeded';
CREATE INDEX v3_deployment_preview_reference ON v3_deployment_previews(job,expires_at) WHERE job IS NOT NULL;
CREATE INDEX v3_deployment_preview_node ON v3_deployment_previews(node,expires_at) WHERE job IS NULL;
CREATE INDEX v3_deployment_preparation_history_guard ON v3_deployment_preparations(node,status,expires_at);
INSERT INTO v3_schema(version) VALUES(40);
`
