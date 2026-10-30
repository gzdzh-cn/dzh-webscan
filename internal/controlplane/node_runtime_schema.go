package controlplane

// Runtime registration is separate from saved intent. Migration preserves the
// last v18 registration, without asserting that its Agent was ever installed.
// History is retained for job-bound rollback; it is not an event database copy.
const nodeRuntimeSchema = `
ALTER TABLE v3_nodes ADD COLUMN runtime_generation bigint NOT NULL DEFAULT 0 CHECK(runtime_generation>=0);
CREATE TABLE v3_node_configurations(
 id text PRIMARY KEY,node text NOT NULL REFERENCES v3_nodes(id),version bigint NOT NULL CHECK(version>0),
 name text NOT NULL,endpoint text NOT NULL,server_name text NOT NULL,enabled boolean NOT NULL,
 mode text NOT NULL CHECK(mode IN ('native','docker')),shard integer NOT NULL,config jsonb NOT NULL,
 UNIQUE(node,id)
);
CREATE INDEX v3_node_configurations_versions ON v3_node_configurations(node,version);
CREATE TABLE v3_node_runtime(
 node text PRIMARY KEY REFERENCES v3_nodes(id),snapshot text NOT NULL,
 epoch bigint NOT NULL CHECK(epoch>0),delivered_version bigint NOT NULL DEFAULT 0 CHECK(delivered_version>=0),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(node,snapshot) REFERENCES v3_node_configurations(node,id)
);
INSERT INTO v3_node_configurations SELECT 'migration-'||id,id,version,name,endpoint,server_name,enabled,mode,shard,config FROM v3_nodes;
UPDATE v3_nodes SET runtime_generation=1;
INSERT INTO v3_node_runtime(node,snapshot,epoch,delivered_version) SELECT id,'migration-'||id,1,applied_version FROM v3_nodes;
CREATE VIEW v3_active_nodes AS
 SELECT c.node AS id,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.version,n.applied_version,c.shard,c.config,r.epoch AS runtime_epoch
 FROM v3_node_runtime r JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot JOIN v3_nodes n ON n.id=c.node;
INSERT INTO v3_schema(version) VALUES(19);
`
