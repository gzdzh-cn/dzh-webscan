package controlplane

// Renewed keys are generated on the node. This ledger intentionally has no
// ciphertext/key columns and is independent of the initial installation seed.
const nodeRenewalSchema = `
CREATE TABLE v3_node_certificate_renewals(
 node text NOT NULL REFERENCES v3_nodes(id),
 authority text NOT NULL REFERENCES v3_pki_authorities(sha256),
 parent_sha256 text NOT NULL,request_sha256 text NOT NULL,
 snapshot text NOT NULL,runtime_epoch bigint NOT NULL CHECK(runtime_epoch>0),
 lifetime_hours integer NOT NULL CHECK(lifetime_hours BETWEEN 1 AND 2160),
 certificate bytea NOT NULL,certificate_sha256 text NOT NULL,serial text NOT NULL,
 not_after timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(node,parent_sha256),
 UNIQUE(authority,serial),UNIQUE(authority,certificate_sha256),
 FOREIGN KEY(node,snapshot) REFERENCES v3_node_configurations(node,id),
 CHECK(length(authority)=64 AND length(parent_sha256)=64 AND length(request_sha256)=64 AND length(certificate_sha256)=64)
);
CREATE INDEX v3_node_certificate_renewals_expiry ON v3_node_certificate_renewals(not_after,node);
INSERT INTO v3_schema(version) VALUES(30);
`
