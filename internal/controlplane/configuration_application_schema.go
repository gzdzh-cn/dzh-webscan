package controlplane

// An application is a durable coordination journal, distinct from a saved
// restore and from each node's remote deployment journal. Expired ownership
// never clears recovery responsibility or authorizes a new configuration.
const configurationApplicationSchema = `
CREATE TABLE v3_configuration_applications(
 id text PRIMARY KEY,stage text NOT NULL UNIQUE,member text NOT NULL,
 username text NOT NULL,account_revision bigint NOT NULL CHECK(account_revision>0),
 generation bigint NOT NULL CHECK(generation>0),source_proof text NOT NULL,plan_proof text NOT NULL,
 controller text NOT NULL,controller_revision bigint NOT NULL CHECK(controller_revision>0),
 status text NOT NULL CHECK(status IN ('queued','running','failed','succeeded','rolled_back','cancelled')),
 direction text NOT NULL CHECK(direction IN ('forward','rollback')),
 step integer NOT NULL DEFAULT 0 CHECK(step BETWEEN 0 AND 6),
 rollback_step integer NOT NULL DEFAULT 0 CHECK(rollback_step BETWEEN 0 AND 4),
 recovery_required boolean NOT NULL DEFAULT false,error_code text NOT NULL DEFAULT '',
 lease_owner text,lease_epoch bigint NOT NULL DEFAULT 0 CHECK(lease_epoch>=0),lease_until timestamptz,
 log_cursor bigint NOT NULL DEFAULT 0 CHECK(log_cursor>=0),state_proof text NOT NULL,
 recovery_hold boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),finished_at timestamptz,
 CHECK((status IN ('succeeded','rolled_back','cancelled'))=(finished_at IS NOT NULL)),
 CHECK(status NOT IN ('succeeded','rolled_back','cancelled') OR NOT recovery_required),
 CHECK((status='running')=(lease_owner IS NOT NULL AND lease_until IS NOT NULL))
);
CREATE UNIQUE INDEX v3_configuration_application_active ON v3_configuration_applications((true))
 WHERE status IN ('queued','running') OR recovery_required;
CREATE INDEX v3_configuration_application_claim ON v3_configuration_applications(member,status,created_at,id);
CREATE TABLE v3_configuration_application_logs(
 job text NOT NULL REFERENCES v3_configuration_applications(id),cursor bigint NOT NULL,
 direction text NOT NULL,phase text NOT NULL,code text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(job,cursor)
);
INSERT INTO v3_schema(version) VALUES(22);
`
