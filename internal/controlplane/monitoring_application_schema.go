package controlplane

const monitoringApplicationSchema = `
CREATE TABLE IF NOT EXISTS v3_monitoring_applications(
 id text PRIMARY KEY, username text NOT NULL REFERENCES v3_accounts(username), account_revision bigint NOT NULL,
 controller text NOT NULL, controller_revision bigint NOT NULL, global_generation text NOT NULL, manifest_sha256 text NOT NULL, release text NOT NULL,
 status text NOT NULL CHECK(status IN ('preview','queued','running','paused','succeeded','rolled_back','expired')),
 direction text NOT NULL DEFAULT 'forward' CHECK(direction IN ('forward','rollback')), version bigint NOT NULL DEFAULT 1,
 plan_digest text NOT NULL, key_id text NOT NULL, nonce bytea NOT NULL, ciphertext bytea NOT NULL, proof text NOT NULL,
 token_hash text NOT NULL, expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes',
 lease_owner text, lease_epoch bigint NOT NULL DEFAULT 0, lease_until timestamptz,
 recovery_hold boolean NOT NULL DEFAULT false, selected_node text NOT NULL DEFAULT '', error_code text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS v3_monitoring_applications_work ON v3_monitoring_applications(status,created_at);
CREATE TABLE IF NOT EXISTS v3_monitoring_application_nodes(
 application text NOT NULL REFERENCES v3_monitoring_applications(id), node text NOT NULL REFERENCES v3_nodes(id),
 ordinal integer NOT NULL CHECK(ordinal>=0), batch_index integer NOT NULL CHECK(batch_index>=0),
 reserved boolean NOT NULL DEFAULT false, state text NOT NULL DEFAULT 'pending', child text REFERENCES v3_deployment_jobs(id),
 child_plan_digest text NOT NULL DEFAULT '', parent_epoch bigint NOT NULL DEFAULT 0, proof text NOT NULL DEFAULT '',
 state_proof text NOT NULL DEFAULT '', state_epoch bigint NOT NULL DEFAULT 0, error_code text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(application,node), UNIQUE(application,ordinal), UNIQUE(child)
);
CREATE UNIQUE INDEX IF NOT EXISTS v3_monitoring_node_reservation ON v3_monitoring_application_nodes(node) WHERE reserved;
CREATE TABLE IF NOT EXISTS v3_monitoring_application_authorizations(
 id text PRIMARY KEY,application text NOT NULL REFERENCES v3_monitoring_applications(id),username text NOT NULL REFERENCES v3_accounts(username),
 account_revision bigint NOT NULL,parent_version bigint NOT NULL,state_digest text NOT NULL,token_hash text NOT NULL,
 expires_at timestamptz NOT NULL,consumed boolean NOT NULL DEFAULT false
);
INSERT INTO v3_schema(version) VALUES(39) ON CONFLICT DO NOTHING;`
