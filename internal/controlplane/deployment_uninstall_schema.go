package controlplane

// Removal is a lifecycle operation, never deletion of the central record.
// Source authorizations and remote receipts remain available after UI history
// archival; a restore must not infer an installation from an offline node.
const deploymentUninstallSchema = `
ALTER TABLE v3_deployment_jobs DROP CONSTRAINT v3_deployment_jobs_kind_check;
ALTER TABLE v3_deployment_jobs ADD CONSTRAINT v3_deployment_jobs_kind_check CHECK(kind IN ('install','upgrade','recover','uninstall'));
CREATE TABLE v3_deployment_uninstalls(
 job text PRIMARY KEY REFERENCES v3_deployment_jobs(id),
 source text NOT NULL REFERENCES v3_deployment_jobs(id),
 key_id text NOT NULL,proof text NOT NULL,
 CHECK(job<>source),created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX v3_deployment_uninstalls_source ON v3_deployment_uninstalls(source);
CREATE TABLE v3_deployment_lifecycle_receipts(
 job text NOT NULL REFERENCES v3_deployment_jobs(id),
 kind text NOT NULL CHECK(kind IN ('removal','restoration')),
 evidence jsonb NOT NULL,recorded_epoch bigint NOT NULL CHECK(recorded_epoch>0),
 key_id text NOT NULL,proof text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(job,kind)
);
CREATE TABLE v3_node_lifecycle(
 node text PRIMARY KEY REFERENCES v3_nodes(id),
 job text NOT NULL REFERENCES v3_deployment_jobs(id),
 state text NOT NULL CHECK(state IN ('installed','uninstalled')),
 body jsonb NOT NULL,key_id text NOT NULL,proof text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE v3_deployment_lifecycle_authorizations(
 job text PRIMARY KEY REFERENCES v3_deployment_jobs(id),
 source text NOT NULL REFERENCES v3_deployment_jobs(id),
 key_id text NOT NULL,proof text NOT NULL
);
CREATE INDEX v3_deployment_lifecycle_authorizations_source ON v3_deployment_lifecycle_authorizations(source);
CREATE TABLE v3_web_uninstall_credentials(
 node text NOT NULL REFERENCES v3_nodes(id),
 source text NOT NULL REFERENCES v3_deployment_jobs(id),
 credential text NOT NULL REFERENCES v3_credentials(id),PRIMARY KEY(node,source)
);
INSERT INTO v3_schema(version) VALUES(41);
`
