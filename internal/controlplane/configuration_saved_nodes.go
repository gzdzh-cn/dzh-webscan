package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"

	"webscan/internal/common"
)

type restoredNodeRow struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Endpoint   string          `json:"endpoint"`
	ServerName string          `json:"server_name"`
	Enabled    bool            `json:"enabled"`
	Mode       string          `json:"mode"`
	Config     json.RawMessage `json:"config"`
	Expected   int64           `json:"expected"`
	Snapshot   string          `json:"snapshot"`
	Shard      int             `json:"shard"`
}

// At most 100 rows / about 2 MiB per statement. A shared ruleset is serialized
// once per profile and only copied into the current bounded batch. One SQL
// statement saves desired rows and their immutable snapshots together; runtime
// registrations, cursors, current status and applied versions remain untouched.
func materializeRestoredNodesTx(ctx context.Context, tx *sql.Tx, plan configurationRestorePlan, shards int) (int, error) {
	if shards < 1 || shards > 4096 {
		return 0, errConfigurationSaved
	}
	profiles := map[string]json.RawMessage{}
	batch := make([]restoredNodeRow, 0, 100)
	size, total := 0, 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		var count int
		err := tx.QueryRowContext(ctx, `WITH parsed AS (
 SELECT * FROM jsonb_to_recordset($1::jsonb) AS r(id text,name text,endpoint text,server_name text,enabled boolean,mode text,config jsonb,expected bigint,snapshot text,shard integer)
 ), updated AS (
 UPDATE v3_nodes n SET name=p.name,endpoint=p.endpoint,server_name=p.server_name,enabled=p.enabled,mode=p.mode,config=p.config,version=n.version+1,updated_at=clock_timestamp()
 FROM parsed p WHERE p.expected>0 AND n.id=p.id AND n.version=p.expected
 RETURNING n.id,n.version,n.name,n.endpoint,n.server_name,n.enabled,n.mode,n.shard,n.config
 ), inserted AS (
 INSERT INTO v3_nodes(id,name,endpoint,server_name,enabled,mode,shard,config)
 SELECT id,name,endpoint,server_name,enabled,mode,shard,config FROM parsed WHERE expected=0 ON CONFLICT DO NOTHING
 RETURNING id,version,name,endpoint,server_name,enabled,mode,shard,config
 ), changed AS (SELECT * FROM updated UNION ALL SELECT * FROM inserted), snapshots AS (
 INSERT INTO v3_node_configurations(id,node,version,name,endpoint,server_name,enabled,mode,shard,config)
 SELECT p.snapshot,c.id,c.version,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.shard,c.config FROM changed c JOIN parsed p ON p.id=c.id RETURNING id
 ) SELECT count(*) FROM snapshots`, common.JSON(batch)).Scan(&count)
		if err != nil {
			return err
		}
		if count != len(batch) {
			return ErrConflict
		}
		total += count
		batch = batch[:0]
		size = 0
		return nil
	}
	for _, change := range plan.Summary.Nodes {
		if change.Action != "add" && change.Action != "update" {
			return 0, errConfigurationRestoreBlocked
		}
		n, ok := plan.Candidate.Nodes[change.Node]
		if !ok {
			return 0, errConfigurationSaved
		}
		raw, ok := profiles[n.Profile]
		if !ok {
			raw = common.JSON(plan.Candidate.Profiles[n.Profile].Config)
			profiles[n.Profile] = raw
		}
		row := restoredNodeRow{ID: change.Node, Name: n.Name, Endpoint: n.Endpoint, ServerName: n.ServerName, Enabled: n.Enabled, Mode: n.Mode, Config: raw, Expected: n.Version, Snapshot: token(), Shard: Shard(change.Node, shards)}
		if change.Action == "add" {
			row.Expected = 0
		}
		if err := (Node{ID: row.ID, Name: row.Name, Endpoint: row.Endpoint, ServerName: row.ServerName, Enabled: row.Enabled, Mode: row.Mode, Config: raw}).Validate(); err != nil {
			return 0, errConfigurationSaved
		}
		estimate := len(raw) + len(row.ID) + len(row.Name) + len(row.Endpoint) + len(row.ServerName) + 512
		if len(batch) > 0 && (len(batch) >= 100 || size+estimate > 2<<20) {
			if err := flush(); err != nil {
				return 0, err
			}
		}
		batch = append(batch, row)
		size += estimate
	}
	if err := flush(); err != nil {
		return 0, err
	}
	return total, nil
}
