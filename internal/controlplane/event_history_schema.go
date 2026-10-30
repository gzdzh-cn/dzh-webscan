package controlplane

const eventHistorySchema = `
ALTER TABLE v3_event_keys ADD COLUMN digest_format text NOT NULL DEFAULT 'v3-json-v1'
 CHECK(digest_format IN ('v3-json-v1','canonical-v1'));
CREATE TABLE v3_imported_events(
 id text PRIMARY KEY,node text NOT NULL,event_id text NOT NULL DEFAULT '',
 received_at timestamptz NOT NULL,operation text NOT NULL,security boolean NOT NULL DEFAULT false,
 payload jsonb NOT NULL,digest text NOT NULL DEFAULT '',migration_source text NOT NULL
);
CREATE INDEX v3_imported_events_time ON v3_imported_events(received_at DESC,node DESC,id DESC);
CREATE INDEX v3_imported_events_node ON v3_imported_events(node,received_at DESC,id DESC);
CREATE INDEX v3_imported_events_identity ON v3_imported_events(node,event_id,digest) WHERE event_id<>'';
INSERT INTO v3_schema(version) VALUES(7);
`
