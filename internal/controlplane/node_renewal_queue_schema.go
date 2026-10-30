package controlplane

// Only canonical public CSR requests cross the collector/host boundary. The
// immutable issuance ledger retains its original runtime audit binding; this
// queue may be rebound to a newer, verified runtime without issuing a new key.
const nodeRenewalQueueSchema = `
CREATE TABLE v3_node_renewal_jobs(
 node text NOT NULL REFERENCES v3_nodes(id),parent_sha256 text NOT NULL,
 request_sha256 text NOT NULL,request bytea NOT NULL CHECK(octet_length(request) BETWEEN 1 AND 65536),
 snapshot text NOT NULL,runtime_epoch bigint NOT NULL CHECK(runtime_epoch>0),
 lifetime_hours integer NOT NULL CHECK(lifetime_hours BETWEEN 1 AND 2160),
 activated_at timestamptz,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),last_error text NOT NULL DEFAULT '',
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(node,parent_sha256),
 FOREIGN KEY(node,snapshot) REFERENCES v3_node_configurations(node,id),
 CHECK(length(parent_sha256)=64 AND length(request_sha256)=64)
);
CREATE INDEX v3_node_renewal_jobs_pending ON v3_node_renewal_jobs(next_attempt_at,node) WHERE activated_at IS NULL;
INSERT INTO v3_schema(version) VALUES(31);
`
