package controlplane

// Failed/interrupted jobs retain the node reservation once the service may
// have changed. Read-only preflight failures do not require rollback.
const deploymentSchema = `
CREATE TABLE v3_credentials(
 id text PRIMARY KEY,node text NOT NULL REFERENCES v3_nodes(id),
 key_id text NOT NULL,revision bigint NOT NULL DEFAULT 1,
 nonce bytea NOT NULL,ciphertext bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX v3_credentials_node ON v3_credentials(node,id);
CREATE TABLE v3_deployment_jobs(
 id text PRIMARY KEY,node text NOT NULL REFERENCES v3_nodes(id),
 username text NOT NULL,kind text NOT NULL CHECK(kind IN ('install','upgrade')),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','failed','interrupted','succeeded','rolled_back')),
 direction text NOT NULL DEFAULT 'forward' CHECK(direction IN ('forward','rollback')),
 node_version bigint NOT NULL,credential text NOT NULL REFERENCES v3_credentials(id),
 plan jsonb NOT NULL,plan_digest text NOT NULL,
 step integer NOT NULL DEFAULT 0 CHECK(step>=0 AND step<=6),
 rollback_step integer NOT NULL DEFAULT 0 CHECK(rollback_step>=0 AND rollback_step<=2),
 lease_owner text,lease_epoch bigint NOT NULL DEFAULT 0,lease_until timestamptz,
 recovery_required boolean NOT NULL DEFAULT false,
 error_code text NOT NULL DEFAULT '',log_cursor bigint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),finished_at timestamptz
);
CREATE UNIQUE INDEX v3_deployment_node_reserved ON v3_deployment_jobs(node) WHERE status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required);
CREATE INDEX v3_deployment_due ON v3_deployment_jobs(created_at,id) WHERE status IN ('queued','running');
CREATE INDEX v3_deployment_history ON v3_deployment_jobs(created_at DESC,id DESC);
CREATE TABLE v3_deployment_logs(
 job text NOT NULL REFERENCES v3_deployment_jobs(id),cursor bigint NOT NULL,
 epoch bigint NOT NULL,phase text NOT NULL,code text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(job,cursor)
);
INSERT INTO v3_schema(version) VALUES(3);
`
