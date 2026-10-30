package controlplane

const nodeNamePruningSchema = `
ALTER TABLE v3_node_certificate_renewals DROP CONSTRAINT v3_node_certificate_renewals_request_kind_check;
ALTER TABLE v3_node_certificate_renewals ADD CONSTRAINT v3_node_certificate_renewals_request_kind_check CHECK(request_kind IN ('renewal','name-change','name-pruning'));
CREATE TABLE v3_node_name_prunings(
 id text PRIMARY KEY,node text NOT NULL REFERENCES v3_nodes(id),
 username text NOT NULL,actor_revision bigint NOT NULL CHECK(actor_revision>0),
 node_version bigint NOT NULL CHECK(node_version>0),snapshot text NOT NULL,
 credential text NOT NULL REFERENCES v3_credentials(id),credential_proof text NOT NULL,
 authority text NOT NULL REFERENCES v3_pki_authorities(sha256),parent_sha256 text NOT NULL,
 lifetime_hours integer NOT NULL CHECK(lifetime_hours BETWEEN 1 AND 2160),
 certificate bytea NOT NULL CHECK(octet_length(certificate) BETWEEN 1 AND 16384),
 plan jsonb NOT NULL,intent jsonb NOT NULL,expires_at timestamptz NOT NULL,
 status text NOT NULL CHECK(status IN ('prepared','requested','signed','completed','canceled')),
 request bytea CHECK(octet_length(request) BETWEEN 1 AND 65536),
 request_sha256 text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(length(credential_proof)=64 AND length(authority)=64 AND length(parent_sha256)=64),
 CHECK((status='prepared' AND request IS NULL AND request_sha256='') OR status='canceled' OR (request IS NOT NULL AND length(request_sha256)=64)),
 FOREIGN KEY(node,snapshot) REFERENCES v3_node_configurations(node,id)
);
CREATE UNIQUE INDEX v3_node_name_prunings_active ON v3_node_name_prunings(node) WHERE status IN ('prepared','requested','signed');
CREATE INDEX v3_node_name_prunings_expiry ON v3_node_name_prunings(expires_at,node) WHERE status IN ('prepared','requested','signed');
INSERT INTO v3_schema(version) VALUES(34);
`
