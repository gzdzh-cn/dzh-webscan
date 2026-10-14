package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

const schema = `CREATE TABLE IF NOT EXISTS samples(node TEXT NOT NULL,time INTEGER NOT NULL,resolution INTEGER NOT NULL,payload TEXT NOT NULL,source TEXT NOT NULL DEFAULT 'native',PRIMARY KEY(node,time,resolution));
CREATE INDEX IF NOT EXISTS samples_time ON samples(time);
CREATE TABLE IF NOT EXISTS baselines(node TEXT PRIMARY KEY,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS migrations(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS import_guards(id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS health_rules(key TEXT PRIMARY KEY,node TEXT NOT NULL,kind TEXT NOT NULL,phase TEXT NOT NULL,since INTEGER NOT NULL,last INTEGER NOT NULL,recovery INTEGER NOT NULL DEFAULT 0,reminder INTEGER NOT NULL DEFAULT 0,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS health_events(id TEXT PRIMARY KEY,node TEXT NOT NULL,kind TEXT NOT NULL,phase TEXT NOT NULL,time INTEGER NOT NULL,message TEXT NOT NULL,payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS health_events_filter ON health_events(node,time);
CREATE TABLE IF NOT EXISTS alert_outbox(id TEXT PRIMARY KEY,node TEXT NOT NULL,kind TEXT NOT NULL,message TEXT NOT NULL,created INTEGER NOT NULL,done INTEGER);
CREATE TABLE IF NOT EXISTS alert_batches(id TEXT PRIMARY KEY,node TEXT,kind TEXT,message TEXT,created INTEGER,done INTEGER);
CREATE TABLE IF NOT EXISTS alert_members(event TEXT PRIMARY KEY,batch TEXT);`

type Node struct {
	CanRemove       bool     `json:"can_remove"`
	RemoveReason    string   `json:"remove_reason"`
	DeploymentState string   `json:"deployment_state,omitempty"`
	ConfiguredMode  string   `json:"configured_mode,omitempty"`
	ActualMode      string   `json:"actual_mode,omitempty"`
	AgentVersion    string   `json:"agent_version,omitempty"`
	PendingMode     bool     `json:"pending_mode"`
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Host            string   `json:"host"`
	URL             string   `json:"-"`
	Central         bool     `json:"central"`
	Active          bool     `json:"active"`
	Snapshot        Snapshot `json:"snapshot"`
	Status          string   `json:"status"`
}
type Store struct {
	DB       *sql.DB
	mu       sync.Mutex
	alertsMu sync.Mutex
	nodes    []Node
	config   common.Map
}

func Open(dir string, nodes []Node, config common.Map) (*Store, error) {
	db, e := persist.OpenDB(filepath.Join(dir, "metrics-v1.sqlite3"))
	if e != nil {
		return nil, e
	}
	if _, e = db.Exec(schema); e != nil {
		db.Close()
		return nil, e
	}
	s := &Store{DB: db, nodes: nodes, config: common.Clone(config)}
	if e = s.Configure(config, nodes); e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Settings() common.Map {
	s.mu.Lock()
	defer s.mu.Unlock()
	return common.Clone(s.config)
}
func (s *Store) Configure(c common.Map, nodes []Node) error {
	s.alertsMu.Lock()
	defer s.alertsMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, n := range nodes {
		if !n.Active {
			for _, q := range []string{"UPDATE health_rules SET phase='disabled' WHERE node=?", "UPDATE alert_outbox SET done=strftime('%s','now') WHERE node=? AND done IS NULL", "UPDATE alert_batches SET done=strftime('%s','now') WHERE node=? AND done IS NULL"} {
				if _, e = tx.Exec(q, n.ID); e != nil {
					return e
				}
			}
		}
	}
	known := map[string]bool{}
	for _, n := range nodes {
		known[n.ID] = true
	}
	rows, err := tx.Query("SELECT DISTINCT node FROM health_rules WHERE phase IN ('pending','firing')")
	if err != nil {
		return err
	}
	removed := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if !known[id] {
			removed = append(removed, id)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range removed {
		if _, e = tx.Exec("UPDATE health_rules SET phase='disabled' WHERE node=?", id); e != nil {
			return e
		}
	}
	for _, kind := range []string{"cpu", "memory"} {
		if !common.B(common.M(c["alerts"])[kind+"_enabled"]) {
			if _, e = tx.Exec("UPDATE health_rules SET phase='disabled' WHERE kind=?", kind); e != nil {
				return e
			}
			// A batch can contain several rules. Cancel its old message, release
			// unaffected members for regrouping, and retain all event history.
			if _, e = tx.Exec("UPDATE alert_batches SET done=strftime('%s','now') WHERE done IS NULL AND id IN(SELECT m.batch FROM alert_members m JOIN health_events h ON h.id=m.event WHERE h.kind=?)", kind); e != nil {
				return e
			}
			if _, e = tx.Exec("DELETE FROM alert_members WHERE batch IN(SELECT id FROM alert_batches WHERE done IS NOT NULL) AND event IN(SELECT id FROM alert_outbox WHERE done IS NULL)"); e != nil {
				return e
			}
			if _, e = tx.Exec("UPDATE alert_outbox SET done=strftime('%s','now') WHERE done IS NULL AND id IN(SELECT id FROM health_events WHERE kind=?)", kind); e != nil {
				return e
			}

		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.config = common.Clone(c)
	s.nodes = append([]Node(nil), nodes...)
	return nil
}
func (s *Store) Nodes(ctx context.Context) ([]Node, error) {
	s.mu.Lock()
	nodes := append([]Node(nil), s.nodes...)
	interval := max(10, common.I(s.config["interval_seconds"]))
	s.mu.Unlock()
	for i := range nodes {
		var raw string
		e := s.DB.QueryRowContext(ctx, "SELECT payload FROM samples WHERE node=? AND resolution=0 ORDER BY time DESC LIMIT 1", nodes[i].ID).Scan(&raw)
		if e != nil && e != sql.ErrNoRows {
			return nil, e
		}
		nodes[i].Status = "unknown"
		if e == nil {
			if e = json.Unmarshal([]byte(raw), &nodes[i].Snapshot); e != nil {
				return nil, e
			}
			if time.Now().Unix()-nodes[i].Snapshot.Time > int64(interval*3) {
				nodes[i].Status = "stale"
			} else if nodes[i].Snapshot.OK {
				nodes[i].Status = "normal"
			} else {
				nodes[i].Status = "unreachable"
			}
		}
		if !nodes[i].Active {
			nodes[i].Status = "disabled"
		}
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Central != nodes[j].Central {
			return nodes[i].Central
		}
		return nodes[i].ID < nodes[j].ID
	})
	return nodes, nil
}
func (s *Store) Save(ctx context.Context, id string, snap Snapshot, baseline *Baseline) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "INSERT OR REPLACE INTO samples(node,time,resolution,payload) VALUES(?,?,0,?)", id, snap.Time, string(common.JSON(snap))); e != nil {
		return e
	}
	if baseline != nil {
		if _, e = tx.ExecContext(ctx, "INSERT INTO baselines VALUES(?,?) ON CONFLICT(node) DO UPDATE SET payload=excluded.payload", id, string(common.JSON(baseline))); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) Baseline(ctx context.Context, id string) (Baseline, error) {
	var b Baseline
	var raw string
	e := s.DB.QueryRowContext(ctx, "SELECT payload FROM baselines WHERE node=?", id).Scan(&raw)
	if e == sql.ErrNoRows {
		return b, nil
	}
	if e == nil {
		e = json.Unmarshal([]byte(raw), &b)
	}
	return b, e
}

type Point struct {
	Time   int64              `json:"time"`
	Values map[string]float64 `json:"values"`
	Min    map[string]float64 `json:"min,omitempty"`
	Max    map[string]float64 `json:"max,omitempty"`
	Count  map[string]int     `json:"count,omitempty"`
	OK     bool               `json:"ok"`
}
type Trend struct {
	Points     []Point `json:"points"`
	Resolution int     `json:"resolution_seconds"`
	Start      int64   `json:"start"`
	End        int64   `json:"end"`
}

func (s *Store) Trend(ctx context.Context, id string, start, end int64) (Trend, error) {
	out := Trend{Points: []Point{}, Start: start, End: end}
	if end <= start || end-start > 90*86400 {
		return out, errors.New("查询时间范围应在 90 天以内")
	}
	resolution := 0
	if start < time.Now().Unix()-int64(max(1, common.I(s.Settings()["raw_hours"]))*3600) || end-start > 1200*30 {
		resolution = 300
	}
	out.Resolution = max(30, resolution)
	width := int64(out.Resolution)
	if end/width-start/width+1 > 1200 {
		width = ((end-start+1197)/1198 + int64(out.Resolution) - 1) / int64(out.Resolution) * int64(out.Resolution)
		out.Resolution = int(width)
	}
	query := "SELECT time,payload FROM samples WHERE node=? AND resolution=0 AND time>=? AND time<=? ORDER BY time"
	args := []any{id, start, end}
	if resolution == 300 {
		var latest sql.NullInt64
		if e := s.DB.QueryRowContext(ctx, "SELECT max(time) FROM samples WHERE node=? AND resolution=300", id).Scan(&latest); e != nil {
			return out, e
		}
		cutoff := start
		if latest.Valid {
			cutoff = latest.Int64 + 300
		}
		query = "SELECT time,payload FROM samples WHERE node=? AND time>=? AND time<=? AND (resolution=300 OR (resolution=0 AND time>=?)) ORDER BY time"
		args = []any{id, start, end, cutoff}
	}
	rows, e := s.DB.QueryContext(ctx, query, args...)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	var current *Point
	for rows.Next() {
		var raw string
		var tm int64
		if e = rows.Scan(&tm, &raw); e != nil {
			return out, e
		}
		var p Point
		if e = json.Unmarshal([]byte(raw), &p); e != nil {
			return out, e
		}
		bucket := tm / width * width
		if current == nil || current.Time != bucket {
			if current != nil {
				out.Points = append(out.Points, *current)
			}
			current = &Point{Time: bucket, Values: map[string]float64{}, Min: map[string]float64{}, Max: map[string]float64{}, Count: map[string]int{}}
		}
		if !p.OK {
			continue
		}
		current.OK = true
		for key, v := range p.Values {
			count := max(1, p.Count[key])
			oldCount := current.Count[key]
			current.Values[key] = (current.Values[key]*float64(oldCount) + v*float64(count)) / float64(oldCount+count)
			lo, hi := v, v
			if m, ok := p.Min[key]; ok {
				lo = m
			}
			if m, ok := p.Max[key]; ok {
				hi = m
			}
			if oldCount == 0 || lo < current.Min[key] {
				current.Min[key] = lo
			}
			if oldCount == 0 || hi > current.Max[key] {
				current.Max[key] = hi
			}
			current.Count[key] = oldCount + count
		}
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	if current != nil {
		out.Points = append(out.Points, *current)
	}
	// Preserve gaps even when there were no rows at all in a time bucket.
	filled := []Point{}
	idx := 0
	for tm := start / width * width; tm <= end; tm += width {
		if idx < len(out.Points) && out.Points[idx].Time == tm {
			filled = append(filled, out.Points[idx])
			idx++
		} else {
			filled = append(filled, Point{Time: tm, Values: map[string]float64{}, OK: false})
		}
	}
	out.Points = filled

	return out, nil
}
func Aggregate(points []Point, width int64) []Point {
	out := []Point{}
	var p *Point
	sum := map[string]float64{}
	for _, v := range points {
		bucket := v.Time / width * width
		if p == nil || p.Time != bucket {
			if p != nil {
				for k, total := range sum {
					p.Values[k] = total / float64(p.Count[k])
				}
				out = append(out, *p)
			}
			p = &Point{Time: bucket, Values: map[string]float64{}, Min: map[string]float64{}, Max: map[string]float64{}, Count: map[string]int{}}
			sum = map[string]float64{}
		}
		if !v.OK {
			continue
		}
		p.OK = true
		for k, value := range v.Values {
			count := v.Count[k]
			if count == 0 {
				count = 1
			}
			sum[k] += value * float64(count)
			lo, hi := value, value
			if v.Min != nil {
				lo = v.Min[k]
				hi = v.Max[k]
			}
			if p.Count[k] == 0 || lo < p.Min[k] {
				p.Min[k] = lo
			}
			if p.Count[k] == 0 || hi > p.Max[k] {
				p.Max[k] = hi
			}
			p.Count[k] += count
		}
	}
	if p != nil {
		for k, total := range sum {
			p.Values[k] = total / float64(p.Count[k])
		}
		out = append(out, *p)
	}
	return out
}

// Compact commits aggregates before deleting raw records, in bounded time windows.
func (s *Store) Compact(ctx context.Context) error {
	settings := s.Settings()
	cutoff := (time.Now().Unix()/300 - 1) * 300
	// Delete only complete buckets. A partial raw bucket would replace its
	// previous full aggregate on the next pass and lose the peak/count.
	rawCutoff := (time.Now().Unix() - int64(max(1, common.I(settings["raw_hours"]))*3600)) / 300 * 300
	var oldest sql.NullInt64
	if e := s.DB.QueryRowContext(ctx, "SELECT min(time) FROM samples WHERE resolution=0 AND time<?", cutoff).Scan(&oldest); e != nil {
		return e
	}
	if oldest.Valid {
		for start := oldest.Int64 / 300 * 300; start < cutoff; start += 3600 {
			end := min(start+3600, cutoff)
			// Serialize guard inspection, raw reads and aggregate writes across the
			// manager and receiver processes. Incomplete imports must never be
			// compacted, including after a manager interruption.
			tx, e := persist.BeginWrite(ctx, s.DB)
			if e != nil {
				return e
			}
			var guarded int
			if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM import_guards").Scan(&guarded); e != nil {
				tx.Rollback()
				return e
			}
			if guarded > 0 {
				tx.Rollback()
				return nil
			}
			rows, e := tx.QueryContext(ctx, "SELECT node,payload,source FROM samples WHERE resolution=0 AND time>=? AND time<? ORDER BY node,time", start, end)
			if e != nil {
				tx.Rollback()
				return e
			}
			groups := map[string][]Point{}
			sources := map[string]string{}
			for rows.Next() {
				var node, raw, source string
				if e = rows.Scan(&node, &raw, &source); e != nil {
					break
				}
				var p Point
				if e = json.Unmarshal([]byte(raw), &p); e != nil {
					break
				}
				groups[node] = append(groups[node], p)
				if sources[node] == "" || source != "legacy" {
					sources[node] = source
				}
			}
			if e == nil {
				e = rows.Err()
			}
			rows.Close()
			if e != nil {
				tx.Rollback()
				return e
			}
			for node, points := range groups {
				for _, p := range Aggregate(points, 300) {
					_, e = tx.ExecContext(ctx, "INSERT OR REPLACE INTO samples(node,time,resolution,payload,source) VALUES(?,?,300,?,?)", node, p.Time, string(common.JSON(p)), sources[node])
					if e != nil {
						break
					}
				}
				if e != nil {
					break
				}
			}
			if e == nil {
				_, e = tx.ExecContext(ctx, "DELETE FROM samples WHERE resolution=0 AND time>=? AND time<? AND time<?", start, end, rawCutoff)
			}
			if e != nil {
				tx.Rollback()
				return e
			}
			if e = tx.Commit(); e != nil {
				return e
			}
		}
	}
	tx, e := persist.BeginWrite(ctx, s.DB)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var guarded int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM import_guards").Scan(&guarded); e != nil {
		return e
	}
	if guarded > 0 {
		return nil
	}
	_, e = tx.ExecContext(ctx, "DELETE FROM samples WHERE resolution=300 AND time<?", time.Now().Unix()-int64(max(1, common.I(settings["history_days"]))*86400))
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Error(err error) string { return fmt.Sprint("监控数据读取失败：", err) }
