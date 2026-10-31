package controlplane

const rootRotationSchema = `
ALTER TABLE v3_pki_authorities DROP COLUMN singleton;
CREATE TABLE v3_root_rotations(
 id text PRIMARY KEY CHECK(length(id)=64),
 username text NOT NULL REFERENCES v3_accounts(username),
 revision bigint NOT NULL CHECK(revision>0),
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 33554432),
 key_id text NOT NULL,proof text NOT NULL CHECK(length(proof)=64),
 status text NOT NULL CHECK(status IN ('prepared','dual','ready','finalizing','completed','canceled')),
 restore_hold boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX v3_root_rotation_active ON v3_root_rotations((true)) WHERE status NOT IN ('completed','canceled');
CREATE TABLE v3_root_identity_issuances(
 task text NOT NULL REFERENCES v3_root_rotations(id),role text NOT NULL CHECK(role IN ('node','collector')),
 subject text NOT NULL,authority text NOT NULL REFERENCES v3_pki_authorities(sha256),
 parent_sha256 text NOT NULL CHECK(length(parent_sha256)=64),request_sha256 text NOT NULL CHECK(length(request_sha256)=64),
 certificate bytea NOT NULL,certificate_sha256 text NOT NULL CHECK(length(certificate_sha256)=64),
 serial text NOT NULL,not_after timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(task,role,subject),UNIQUE(role,subject,parent_sha256),UNIQUE(authority,serial),UNIQUE(authority,certificate_sha256)
);
CREATE FUNCTION v3_root_issuance_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'root identity issuance is immutable'; END $$;
CREATE TRIGGER v3_root_issuance_immutable BEFORE UPDATE OR DELETE ON v3_root_identity_issuances
 FOR EACH ROW EXECUTE FUNCTION v3_root_issuance_immutable();
INSERT INTO v3_schema(version) VALUES(38);
`
