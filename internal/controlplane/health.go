package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"

	"webscan/internal/common"
	"webscan/internal/telemetry"
)

// Monitoring settings use the existing health-policy keys. These are runtime
// preferences, not deployment settings; replayed samples never evaluate policy.
func healthSettings(ctx context.Context, tx *sql.Tx) (common.Map, int64, error) {
	var raw []byte
	var version int64
	if err := tx.QueryRowContext(ctx, "SELECT payload,version FROM v3_settings WHERE id=1").Scan(&raw, &version); err != nil {
		return nil, 0, err
	}
	var root common.Map
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, 0, err
	}
	config := common.M(root["monitoring"])
	for key, fallback := range map[string]int{"interval_seconds": 30, "repeat_hours": 4, "group_wait_seconds": 30, "group_interval_seconds": 300} {
		if _, exists := config[key]; !exists {
			config[key] = fallback
		}
	}
	return config, version, nil
}

// evaluateHealth runs after FenceNode and the node-status write in the same
// transaction. The cursor serializes success/failure observations, including
// concurrent workers from the same collector. All times here are observation
// times, not timestamps of historical samples replayed from the Agent.
func (s *Store) evaluateHealth(ctx context.Context, tx *sql.Tx, n Node, snap telemetry.Snapshot, observed int64, config common.Map, settingsVersion int64) error {
	if held, err := migrationHeld(ctx, tx); err != nil {
		return err
	} else if held {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO v3_health_cursors(node) VALUES($1) ON CONFLICT DO NOTHING", n.ID); err != nil {
		return err
	}
	var last int64
	if err := tx.QueryRowContext(ctx, "SELECT observed FROM v3_health_cursors WHERE node=$1 FOR UPDATE", n.ID).Scan(&last); err != nil {
		return err
	}
	if observed <= last {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "UPDATE v3_health_cursors SET observed=$2,node_version=$3,settings_version=$4 WHERE node=$1", n.ID, observed, n.Version, settingsVersion); err != nil {
		return err
	}
	snap.Time = observed / 1000
	if snap.Values == nil {
		snap.Values = map[string]float64{}
	}
	var maintenance bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status='running' AND recovery_required AND lease_until>clock_timestamp())`, n.ID).Scan(&maintenance); err != nil {
		return err
	}
	maintenance = maintenance || common.Contains(common.SS(config["maintenance_nodes"]), n.ID)
	rows, err := tx.QueryContext(ctx, "SELECT payload,phase FROM v3_health_rules WHERE node=$1 ORDER BY key", n.ID)
	if err != nil {
		return err
	}
	states := map[string]telemetry.RuleState{}
	for rows.Next() {
		var raw []byte
		var phase string
		var st telemetry.RuleState
		if err = rows.Scan(&raw, &phase); err != nil {
			break
		}
		if err = json.Unmarshal(raw, &st); err != nil {
			break
		}
		st.Phase = phase
		states[st.Key] = st
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	changes := []telemetry.RuleState{}
	for key, st := range states {
		if (st.Kind == "cpu" || st.Kind == "memory") && !common.B(common.M(config["alerts"])[st.Kind+"_enabled"]) {
			st.Phase = "disabled"
			st.Recovery = 0
			states[key] = st
			changes = append(changes, st)
		}
	}
	if maintenance {
		// Maintenance does not resolve firing alerts or carry pending time forward.
		for _, st := range states {
			if st.Phase == "pending" {
				st.Phase = "normal"
				st.Since = 0
			}
			st.Last = snap.Time
			st.Recovery = 0
			changes = append(changes, st)
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM v3_health_samples WHERE node=$1", n.ID); err != nil {
			return err
		}
		return saveHealthRules(ctx, tx, changes)
	}
	if cpu, ok := snap.Values["cpu_percent"]; snap.OK && ok {
		avg, known, e := healthCPUAverage(ctx, tx, n.ID, snap.Time, cpu, common.I(config["interval_seconds"]))
		if e != nil {
			return e
		}
		if known {
			snap.Values["cpu_5m_percent"] = avg
		}
	} else {
		// Missing samples break the averaging window, including counter resets.
		if _, err = tx.ExecContext(ctx, "INSERT INTO v3_health_samples VALUES($1,$2,NULL) ON CONFLICT DO NOTHING", n.ID, snap.Time); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM v3_health_samples WHERE node=$1 AND time<$2", n.ID, snap.Time-300); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(n.Endpoint)
	legacy := telemetry.Node{ID: n.ID, Name: n.Name, Host: host, Active: true}
	for _, r := range telemetry.RulesFor(legacy, snap, config) {
		if !r.Known {
			continue
		}
		st, ok := states[r.Key]
		if !ok {
			st = telemetry.RuleState{Key: r.Key, Node: n.ID, Kind: r.Kind, Phase: "normal"}
		}
		st, phase := telemetry.AdvanceRule(st, r, snap.Time, common.I(config["interval_seconds"]), common.I(config["repeat_hours"]))
		if phase != "" {
			id := common.Hash([]byte(fmt.Sprintf("%s:%d:%s:%d", r.Key, st.Since, phase, snap.Time)))
			message := telemetry.RuleMessage(legacy, r, st, phase, snap.Time)
			if _, err = tx.ExecContext(ctx, "INSERT INTO v3_health_events VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING", id, n.ID, r.Kind, phase, snap.Time, message, common.JSON(st)); err != nil {
				return err
			}
			if !telemetry.RuleInhibited(r, snap, config) {
				if _, err = tx.ExecContext(ctx, "INSERT INTO v3_health_outbox(id,node,phase,message,created) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING", id, n.ID, phase, message, snap.Time); err != nil {
					return err
				}
			}
			st.Reminder = snap.Time
		}
		changes = append(changes, st)
	}
	return saveHealthRules(ctx, tx, changes)
}

func saveHealthRules(ctx context.Context, tx *sql.Tx, states []telemetry.RuleState) error {
	// Disabling a rule can overlap maintenance resetting it. The last value wins.
	unique := map[string]telemetry.RuleState{}
	for _, st := range states {
		unique[st.Key] = st
	}
	states = states[:0]
	for _, st := range unique {
		states = append(states, st)
	}
	if len(states) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO v3_health_rules(key,node,kind,phase,since,last,recovery,reminder,payload)
 SELECT r->>'key',r->>'node',r->>'kind',r->>'phase',(r->>'since')::bigint,(r->>'last')::bigint,(r->>'recovery')::integer,(r->>'reminder')::bigint,r
 FROM jsonb_array_elements($1::jsonb) r ORDER BY r->>'key'
 ON CONFLICT(key) DO UPDATE SET phase=excluded.phase,since=excluded.since,last=excluded.last,recovery=excluded.recovery,reminder=excluded.reminder,payload=excluded.payload`, common.JSON(states))
	return err
}

func healthCPUAverage(ctx context.Context, tx *sql.Tx, node string, now int64, current float64, interval int) (float64, bool, error) {
	rows, err := tx.QueryContext(ctx, "SELECT time,cpu FROM v3_health_samples WHERE node=$1 AND time>=$2 AND time<$3 ORDER BY time", node, now-300, now)
	if err != nil {
		return 0, false, err
	}
	first, last := int64(0), int64(0)
	total, weight := 0.0, 0.0
	valid := true
	for rows.Next() {
		var at int64
		var value sql.NullFloat64
		if err = rows.Scan(&at, &value); err != nil {
			break
		}
		if !value.Valid {
			valid = false
		}
		if first == 0 {
			first, last = at, at
			continue
		}
		dt := at - last
		if dt <= 0 || dt > int64(max(10, interval)*2) {
			valid = false
		}
		total += value.Float64 * float64(dt)
		weight += float64(dt)
		last = at
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return 0, false, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_health_samples VALUES($1,$2,$3) ON CONFLICT DO NOTHING", node, now, current); err != nil {
		return 0, false, err
	}
	dt := now - last
	if !valid || first == 0 || now-first < 240 || dt <= 0 || dt > int64(max(10, interval)*2) {
		return 0, false, nil
	}
	total += current * float64(dt)
	weight += float64(dt)
	return total / weight, true, nil
}

func healthFresh(sample, observed int64, config common.Map) bool {
	return sample <= observed+5000 && observed-sample <= int64(max(60, 3*common.I(config["interval_seconds"]))*1000)
}

// observeMetricHealth must follow the status-row lock, matching the failure
// path. Reading errors here prevents protocol failures from becoming recovery.
func (s *Store) observeMetricHealth(ctx context.Context, tx *sql.Tx, n Node, snap telemetry.Snapshot, sample int64, interval int) error {
	config, version, err := healthSettings(ctx, tx)
	if err != nil {
		return err
	}
	if interval >= 10 && interval <= 3600 {
		config["interval_seconds"] = interval
	}
	var now int64
	var protocol, events string
	if err = tx.QueryRowContext(ctx, "SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint,protocol_error,events_error FROM v3_node_status WHERE node=$1", n.ID).Scan(&now, &protocol, &events); err != nil {
		return err
	}
	if !healthFresh(sample, now, config) {
		return nil
	}
	snap.OK = protocol == ""
	snap.Values["webscan_transport_up"] = 1
	if events != "" {
		snap.Values["webscan_transport_up"] = 0
	}
	return s.evaluateHealth(ctx, tx, n, snap, now, config, version)
}
