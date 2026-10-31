package controlplane

// Retirement removes a recovery dependency, never the immutable configuration
// or certificate audit. Runtime publication is fenced in PostgreSQL as well as
// before a remote deployment call. No application path can undo a tombstone.
const nodeHistoryRetirementSchema = `
CREATE TABLE v3_node_history_retirements(
 node text NOT NULL REFERENCES v3_nodes(id),snapshot text PRIMARY KEY,
 snapshot_sha256 text NOT NULL CHECK(length(snapshot_sha256)=64),
 username text NOT NULL,actor_revision bigint NOT NULL CHECK(actor_revision>0),
 node_version bigint NOT NULL CHECK(node_version>0),runtime_epoch bigint NOT NULL CHECK(runtime_epoch>0),
 preview_sha256 text NOT NULL CHECK(length(preview_sha256)=64),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(node,snapshot) REFERENCES v3_node_configurations(node,id)
);
CREATE INDEX v3_node_history_retirements_node ON v3_node_history_retirements(node,snapshot);
CREATE FUNCTION v3_retirement_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'node history retirement is immutable'; END $$;
CREATE TRIGGER v3_retirement_immutable BEFORE UPDATE OR DELETE ON v3_node_history_retirements
 FOR EACH ROW EXECUTE FUNCTION v3_retirement_immutable();
CREATE FUNCTION v3_retirement_runtime_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM 1 FROM v3_nodes WHERE id=NEW.node FOR UPDATE;
 IF EXISTS(SELECT 1 FROM v3_node_history_retirements WHERE node=NEW.node AND snapshot=NEW.snapshot) THEN
  RAISE EXCEPTION 'retired node configuration cannot become runtime';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER v3_retirement_runtime_guard BEFORE INSERT OR UPDATE ON v3_node_runtime
 FOR EACH ROW EXECUTE FUNCTION v3_retirement_runtime_guard();
CREATE FUNCTION v3_retirement_active_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- A same-value update also invalidates an older REPEATABLE READ publisher
 -- waiting on this node. Runtime generations and collection remain unchanged.
 UPDATE v3_nodes SET runtime_generation=runtime_generation WHERE id=NEW.node;
 IF EXISTS(SELECT 1 FROM v3_node_runtime WHERE node=NEW.node AND snapshot=NEW.snapshot) THEN
  RAISE EXCEPTION 'active node configuration cannot be retired';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER v3_retirement_active_guard BEFORE INSERT ON v3_node_history_retirements
 FOR EACH ROW EXECUTE FUNCTION v3_retirement_active_guard();
INSERT INTO v3_schema(version) VALUES(37);
`
