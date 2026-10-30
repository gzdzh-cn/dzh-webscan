package controlplane

// Domain imports are held until the full cutover, not made live by completing
// one mapper. Historical identities do not invent enabled nodes or endpoints.
const migrationSchema = `
CREATE TABLE v3_node_identities(id text PRIMARY KEY);
INSERT INTO v3_node_identities SELECT id FROM v3_nodes;
CREATE FUNCTION v3_register_node_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN INSERT INTO v3_node_identities(id) VALUES(NEW.id) ON CONFLICT DO NOTHING; RETURN NEW; END $$;
CREATE TRIGGER v3_register_node_identity BEFORE INSERT ON v3_nodes FOR EACH ROW EXECUTE FUNCTION v3_register_node_identity();
ALTER TABLE v3_health_rules DROP CONSTRAINT v3_health_rules_node_fkey;
ALTER TABLE v3_health_rules ADD FOREIGN KEY(node) REFERENCES v3_node_identities(id);
ALTER TABLE v3_health_events DROP CONSTRAINT v3_health_events_node_fkey;
ALTER TABLE v3_health_events ADD FOREIGN KEY(node) REFERENCES v3_node_identities(id);
ALTER TABLE v3_health_batches DROP CONSTRAINT v3_health_batches_node_fkey;
ALTER TABLE v3_health_batches ADD FOREIGN KEY(node) REFERENCES v3_node_identities(id);
ALTER TABLE v3_health_outbox DROP CONSTRAINT v3_health_outbox_node_fkey;
ALTER TABLE v3_health_outbox ADD FOREIGN KEY(node) REFERENCES v3_node_identities(id);
CREATE TABLE v3_migration_domains(
 domain text PRIMARY KEY,source text NOT NULL,related_source text NOT NULL DEFAULT '',
 pending boolean NOT NULL DEFAULT true,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX v3_legacy_task_links ON v3_legacy_records(source,table_name,((payload->'task_id')->>'value'));
CREATE INDEX v3_health_outbox_batch ON v3_health_outbox(batch) WHERE batch IS NOT NULL;
ALTER TABLE v3_notifications ADD COLUMN migration_source text NOT NULL DEFAULT '';
ALTER TABLE v3_notifications ADD COLUMN migration_task bigint;
ALTER TABLE v3_notifications ADD COLUMN migration_pending boolean NOT NULL DEFAULT false;
ALTER TABLE v3_notifications ADD COLUMN delivery_key text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX v3_notifications_origin ON v3_notifications(migration_source,migration_task,channel,recipient) WHERE migration_source<>'';
CREATE INDEX v3_notifications_origin_event ON v3_notifications(migration_source,event_id) WHERE migration_source<>'';
ALTER TABLE v3_notification_attempts ADD COLUMN migration_source text NOT NULL DEFAULT '';
ALTER TABLE v3_notification_attempts ADD COLUMN migration_table text NOT NULL DEFAULT '';
ALTER TABLE v3_notification_attempts ADD COLUMN migration_record bigint;
CREATE UNIQUE INDEX v3_notification_attempts_origin ON v3_notification_attempts(migration_source,migration_table,migration_record) WHERE migration_source<>'';
INSERT INTO v3_schema(version) VALUES(6);
`
