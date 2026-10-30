package controlplane

// Existing tasks are not backfilled with invented remote installation proof.
const deploymentInstallationSchema = `
CREATE TABLE v3_deployment_installations(
 job text PRIMARY KEY REFERENCES v3_deployment_jobs(id),
 node text NOT NULL REFERENCES v3_nodes(id),plan_digest text NOT NULL,
 spec jsonb NOT NULL,capture_sha256 text NOT NULL,active_sha256 text NOT NULL,
 recorded_epoch bigint NOT NULL CHECK(recorded_epoch>0),
 key_id text NOT NULL,proof text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(length(plan_digest)=64 AND length(capture_sha256)=64 AND length(active_sha256)=64)
);
CREATE INDEX v3_deployment_installations_node ON v3_deployment_installations(node,job);
INSERT INTO v3_schema(version) VALUES(28);
`
