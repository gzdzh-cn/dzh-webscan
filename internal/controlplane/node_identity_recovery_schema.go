package controlplane

const nodeIdentityRecoverySchema = `
CREATE TABLE v3_node_identity_recoveries(
 id text PRIMARY KEY,node text NOT NULL REFERENCES v3_nodes(id),
 username text NOT NULL,actor_revision bigint NOT NULL CHECK(actor_revision>0),
 node_version bigint NOT NULL CHECK(node_version>0),config_sha256 text NOT NULL,
 snapshot text NOT NULL,runtime_epoch bigint NOT NULL CHECK(runtime_epoch>0),
 credential text NOT NULL,credential_proof text NOT NULL,
 authority text NOT NULL,parent_sha256 text NOT NULL,
 lifetime_hours integer NOT NULL CHECK(lifetime_hours BETWEEN 1 AND 2160),
 intent jsonb NOT NULL,expires_at timestamptz NOT NULL,
 status text NOT NULL CHECK(status IN ('prepared','requested','signed','completed','canceled')),
 request bytea CHECK(octet_length(request) BETWEEN 1 AND 65536),
 request_sha256 text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(length(config_sha256)=64 AND length(credential_proof)=64 AND length(authority)=64 AND length(parent_sha256)=64),
 CHECK((status='prepared' AND request IS NULL AND request_sha256='') OR status='canceled' OR (request IS NOT NULL AND length(request_sha256)=64)),
 FOREIGN KEY(node,snapshot) REFERENCES v3_node_configurations(node,id)
);
CREATE UNIQUE INDEX v3_node_identity_recoveries_active ON v3_node_identity_recoveries(node) WHERE status IN ('prepared','requested','signed');
CREATE INDEX v3_node_identity_recoveries_expiry ON v3_node_identity_recoveries(expires_at,node) WHERE status IN ('prepared','requested','signed');
INSERT INTO v3_schema(version) VALUES(32);
`
