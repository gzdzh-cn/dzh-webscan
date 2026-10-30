package controlplane

const retentionSchema = `
CREATE TABLE v3_retention_jobs(
 id text PRIMARY KEY,slot bigint NOT NULL UNIQUE,settings_version bigint NOT NULL,
 policy jsonb NOT NULL,status text NOT NULL CHECK(status IN ('running','succeeded','cancelled')),
 stage integer NOT NULL DEFAULT 0,cursor_time timestamptz NOT NULL DEFAULT '1970-01-01',
 cursor_node text NOT NULL DEFAULT '',cursor_id text NOT NULL DEFAULT '',
 scanned bigint NOT NULL DEFAULT 0,deleted bigint NOT NULL DEFAULT 0,protected bigint NOT NULL DEFAULT 0,
 dependent_deleted bigint NOT NULL DEFAULT 0,
 message text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),finished_at timestamptz
);
CREATE UNIQUE INDEX v3_retention_one_running ON v3_retention_jobs(status) WHERE status='running';
CREATE INDEX v3_retention_history ON v3_retention_jobs(created_at DESC,id DESC);
-- A deleted Loki observation is not an Agent receipt. Keep only its identity
-- and digest so a subsequent actual Agent replay cannot recreate notices.
CREATE TABLE v3_event_history_tombstones(node text NOT NULL,event_id text NOT NULL,digest text NOT NULL,
 PRIMARY KEY(node,event_id,digest));
CREATE INDEX v3_notifications_completed ON v3_notifications(done_at,id) WHERE done_at IS NOT NULL;
CREATE INDEX v3_imported_events_cleanup ON v3_imported_events(security,received_at,node,id);
CREATE INDEX v3_events_cleanup ON v3_events(security,received_at,node,id);
CREATE INDEX v3_incidents_cleanup ON v3_website_incidents((to_timestamp(COALESCE(ended,started))),(id::text));
CREATE INDEX v3_health_events_cleanup ON v3_health_events((to_timestamp(time)),node,id);
CREATE INDEX v3_notifications_cleanup ON v3_notifications((COALESCE(done_at,created_at)),node,(id::text));
CREATE INDEX v3_website_outbox_cleanup ON v3_website_outbox((COALESCE(done_at,to_timestamp(created))),node,(id::text));
CREATE INDEX v3_health_batches_cleanup ON v3_health_batches((COALESCE(done_at,to_timestamp(created))),node,id);
INSERT INTO v3_schema(version) VALUES(9);
`
