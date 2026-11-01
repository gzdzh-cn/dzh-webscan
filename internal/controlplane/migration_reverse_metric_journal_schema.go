package controlplane

// Existing journals retain their real creation time. An old sealed journal has
// no authenticated seal timestamp; leave it unknown instead of inventing one
// during an upgrade or restore.
const migrationReverseMetricJournalSchema = `
ALTER TABLE v3_migration_target_journals ADD COLUMN began_at timestamptz;
ALTER TABLE v3_migration_target_journals ADD COLUMN sealed_at timestamptz;
UPDATE v3_migration_target_journals SET began_at=created_at;
`
