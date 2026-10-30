package controlplane

// Keep node identities and their foreign-key history after removing a console
// record. The runtime view also fences collectors holding an older snapshot.
const nodeRemovalSchema = `
ALTER TABLE v3_nodes ADD COLUMN IF NOT EXISTS removed_at timestamptz;
CREATE OR REPLACE VIEW v3_active_nodes AS
 SELECT c.node AS id,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.version,n.applied_version,c.shard,c.config,r.epoch AS runtime_epoch
 FROM v3_node_runtime r JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot JOIN v3_nodes n ON n.id=c.node
 WHERE n.removed_at IS NULL;
INSERT INTO v3_schema(version) VALUES(36);
`
