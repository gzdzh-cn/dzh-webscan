package controlplane

const migrationCutoverSchema = `
ALTER TABLE v3_migration_sessions DROP CONSTRAINT v3_migration_sessions_phase_check;
ALTER TABLE v3_migration_sessions ADD CHECK(phase IN ('collecting','indexed','frozen','reconciled','active','rolled_back'));
CREATE TABLE v3_migration_cutovers(
 session text NOT NULL REFERENCES v3_migration_sessions(id),action text NOT NULL CHECK(action IN ('activate','rollback')),
 request_version bigint NOT NULL,finished_version bigint NOT NULL,evidence jsonb NOT NULL,key_id text NOT NULL,proof text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(session,action)
);
`
