package controlplane

const healthSchema = `
CREATE TABLE v3_health_cursors(
 node text PRIMARY KEY REFERENCES v3_nodes(id),
 observed bigint NOT NULL DEFAULT 0,node_version bigint NOT NULL DEFAULT 0,settings_version bigint NOT NULL DEFAULT 0
);
CREATE TABLE v3_health_samples(
 node text NOT NULL REFERENCES v3_nodes(id),time bigint NOT NULL,cpu double precision,
 PRIMARY KEY(node,time)
);
CREATE TABLE v3_health_rules(
 key text PRIMARY KEY,node text NOT NULL REFERENCES v3_nodes(id),kind text NOT NULL,
 phase text NOT NULL CHECK(phase IN ('normal','pending','firing','disabled')),
 since bigint NOT NULL,last bigint NOT NULL,recovery integer NOT NULL,reminder bigint NOT NULL,payload jsonb NOT NULL
);
CREATE INDEX v3_health_rules_current ON v3_health_rules(node,kind) WHERE phase IN ('pending','firing');
CREATE TABLE v3_health_events(
 id text PRIMARY KEY,node text NOT NULL REFERENCES v3_nodes(id),kind text NOT NULL,
 phase text NOT NULL CHECK(phase IN ('firing','resolved','reminder')),
 time bigint NOT NULL,message text NOT NULL,payload jsonb NOT NULL
);
CREATE INDEX v3_health_events_time ON v3_health_events(time DESC,id DESC);
CREATE INDEX v3_health_events_node ON v3_health_events(node,time DESC,id DESC);
CREATE TABLE v3_health_batches(
 id text PRIMARY KEY,node text NOT NULL REFERENCES v3_nodes(id),phase text NOT NULL,
 message text NOT NULL,created bigint NOT NULL,done_at timestamptz
);
CREATE INDEX v3_health_batches_interval ON v3_health_batches(node,phase,done_at DESC) WHERE done_at IS NOT NULL;
CREATE TABLE v3_health_outbox(
 id text PRIMARY KEY REFERENCES v3_health_events(id),node text NOT NULL REFERENCES v3_nodes(id),
 phase text NOT NULL,message text NOT NULL,created bigint NOT NULL,
 batch text REFERENCES v3_health_batches(id),done_at timestamptz,result text NOT NULL DEFAULT ''
);
CREATE INDEX v3_health_outbox_pending ON v3_health_outbox(created,id) WHERE done_at IS NULL;
INSERT INTO v3_schema(version) VALUES(5);
`
