package controlplane

const pkiRegistrySchema = `
CREATE TABLE v3_pki_authorities(
 sha256 text PRIMARY KEY,
 singleton boolean NOT NULL DEFAULT true UNIQUE CHECK(singleton),
 certificate bytea NOT NULL,
 crl bytea NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE v3_node_certificates(
 id text PRIMARY KEY,
 node text NOT NULL REFERENCES v3_nodes(id),
 authority text NOT NULL REFERENCES v3_pki_authorities(sha256),
 node_version bigint NOT NULL,
 server_name text NOT NULL,
 serial text NOT NULL,
 certificate bytea NOT NULL,
 key_id text NOT NULL,
 nonce bytea NOT NULL,
 ciphertext bytea NOT NULL,
 not_before timestamptz NOT NULL,
 not_after timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(authority,serial)
);
CREATE INDEX v3_node_certificates_node ON v3_node_certificates(node,created_at DESC,id);
INSERT INTO v3_schema(version) VALUES(12);
`
