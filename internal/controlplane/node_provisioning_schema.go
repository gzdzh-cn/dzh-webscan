package controlplane

const nodeProvisioningSchema = `
CREATE TABLE v3_node_provisioning(
 node text PRIMARY KEY REFERENCES v3_nodes(id),
 id text NOT NULL UNIQUE,
 generation bigint NOT NULL CHECK(generation>0),
 key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(octet_length(ciphertext)<=1048592)
);
INSERT INTO v3_schema(version) VALUES(27);
`
