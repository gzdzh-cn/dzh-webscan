package controlplane

// New identities authorize historical restoration. A successful source job is
// never reopened, and foreign keys keep both immutable ancestors available.
const deploymentRecoverySchema = `
ALTER TABLE v3_deployment_jobs DROP CONSTRAINT v3_deployment_jobs_kind_check;
ALTER TABLE v3_deployment_jobs ADD CONSTRAINT v3_deployment_jobs_kind_check CHECK(kind IN ('install','upgrade','recover'));
CREATE TABLE v3_deployment_recoveries(
 job text PRIMARY KEY REFERENCES v3_deployment_jobs(id),
 source text NOT NULL UNIQUE REFERENCES v3_deployment_jobs(id),
 head text NOT NULL REFERENCES v3_deployment_jobs(id),
 key_id text NOT NULL,proof text NOT NULL,
 CHECK(job<>source AND job<>head AND source<>head),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO v3_schema(version) VALUES(29);
`
