package controlplane

// Work requests contain only identities, versions and progress. Sensitive
// inputs and short-lived capabilities are in a separate encrypted registry.
const webDeploymentSchema = `
CREATE TABLE v3_deployment_preparations(
 id text PRIMARY KEY,node text NOT NULL REFERENCES v3_nodes(id),
 username text NOT NULL REFERENCES v3_accounts(username),account_revision bigint NOT NULL,
 node_version bigint NOT NULL,manifest_sha256 text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('fingerprint','credential','prepare','confirm')),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed','expired')),
 phase text NOT NULL DEFAULT 'queued',error_code text NOT NULL DEFAULT '',
 lease_owner text,lease_epoch bigint NOT NULL DEFAULT 0,lease_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes'
);
CREATE INDEX v3_deployment_preparations_due ON v3_deployment_preparations(created_at,id) WHERE status IN ('queued','running');
CREATE UNIQUE INDEX v3_deployment_preparations_node_busy ON v3_deployment_preparations(node) WHERE status IN ('queued','running');
CREATE TABLE v3_deployment_private_inputs(
 id text PRIMARY KEY REFERENCES v3_deployment_preparations(id) ON DELETE CASCADE,
 key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL,
 result_key_id text,result_nonce bytea,result_ciphertext bytea,
 CHECK(octet_length(ciphertext)<=131088),CHECK(octet_length(result_ciphertext)<=131088)
);
CREATE TABLE v3_web_node_credentials(
 node text PRIMARY KEY REFERENCES v3_nodes(id),credential text NOT NULL REFERENCES v3_credentials(id),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO v3_schema(version) VALUES(35);
`
