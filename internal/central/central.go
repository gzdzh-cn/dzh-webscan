package central

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"webscan/internal/persist"

	"github.com/gogf/gf/v2/net/ghttp"
	"webscan/internal/common"
)

type Store struct {
	Config  common.Map
	DB      *sql.DB
	HTTP    *http.Client
	mu      sync.Mutex
	slots   chan struct{}
	history []float64
}

const Schema = `
CREATE TABLE IF NOT EXISTS events(node TEXT NOT NULL,id TEXT NOT NULL,digest TEXT NOT NULL,payload TEXT NOT NULL,received REAL NOT NULL,PRIMARY KEY(node,id));
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY,node TEXT NOT NULL,event_id TEXT NOT NULL,target TEXT NOT NULL,payload TEXT NOT NULL,created REAL NOT NULL,next_try REAL NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,lease REAL NOT NULL DEFAULT 0,done REAL,result TEXT,priority INTEGER NOT NULL DEFAULT 0,UNIQUE(node,event_id,target));
CREATE INDEX IF NOT EXISTS tasks_ready ON tasks(target,done,next_try,lease);

CREATE TABLE IF NOT EXISTS delivery_records(id INTEGER PRIMARY KEY,task_id INTEGER,target TEXT,time REAL,status TEXT);
CREATE TABLE IF NOT EXISTS probes(node TEXT PRIMARY KEY,received REAL,loki REAL DEFAULT 0,event_id TEXT);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY,value TEXT NOT NULL);`

func New(config common.Map) (*Store, error) {
	d, e := persist.OpenDB(filepath.Join(common.S(config["data_dir"]), "events-v1.sqlite3"))
	if e != nil {
		return nil, e
	}
	if _, e = d.Exec(Schema); e != nil {
		d.Close()
		return nil, e
	}

	rows, err := d.Query("PRAGMA table_info(tasks)")
	if err != nil {
		d.Close()
		return nil, err
	}
	hasPriority := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var defaultValue any
		if err = rows.Scan(&cid, &name, &kind, &notnull, &defaultValue, &pk); err != nil {
			rows.Close()
			d.Close()
			return nil, err
		}
		hasPriority = hasPriority || name == "priority"
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		d.Close()
		return nil, err
	}
	if !hasPriority {
		if _, err = d.Exec("ALTER TABLE tasks ADD COLUMN priority INTEGER NOT NULL DEFAULT 0"); err != nil {
			d.Close()
			return nil, err
		}
	}
	if _, err = d.Exec("CREATE INDEX IF NOT EXISTS tasks_order ON tasks(target,done,priority DESC,id)"); err != nil {
		d.Close()
		return nil, err
	}
	h, e := common.HTTPClient("", time.Duration(max(common.I(common.M(config["feishu"])["timeout_seconds"]), 10))*time.Second)
	if e != nil {
		d.Close()
		return nil, e
	}
	s := &Store{Config: config, DB: d, HTTP: h, slots: make(chan struct{}, 8)}
	var history string
	if e = d.QueryRow("SELECT value FROM kv WHERE key='feishu_rate_history'").Scan(&history); e == nil {
		if v, e := common.Decode([]byte(history)); e == nil {
			for _, n := range common.A(v) {
				if common.F(n) > common.Now()-60 {
					s.history = append(s.history, common.F(n))
				}
			}
		}
	}
	return s, nil
}
func (s *Store) Notify(node string, e common.Map) bool {
	f := common.M(s.Config["feishu"])
	if !common.B(f["enabled"]) || !common.Contains(common.SS(s.Config["active_nodes"]), node) {
		return false
	}
	switches := common.M(f["notifications"])
	op := common.S(e["operation"])
	if common.DeploymentPHPTest(common.S(e["path"])) && op != "scan" {
		// The registered modify event is explicitly queued by Ingest. Creating
		// and cleaning up this fixture must not produce extra file alerts.
		return false
	}
	switch op {
	case "probe":
		return false
	case "scan":
		switch common.S(common.M(e["scan"])["status"]) {
		case "matched":
			return common.B(switches["scan_matches"])
		case "error":
			return common.B(switches["scan_errors"])
		}
		return false
	case "health":
		return common.B(switches["health_failures"])
	case "test":
		return true
	}
	if common.B(e["important_config"]) {
		return common.B(switches["important_config_changes"])
	}
	return common.B(switches["file_changes"])
}

var eventID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var errEvent = errors.New("invalid_event_or_conflicting_id")

func (s *Store) Ingest(ctx context.Context, node string, events []any) ([]string, error) {
	if len(events) == 0 || len(events) > common.I(s.Config["max_batch_events"]) {
		return nil, errEvent
	}
	stamp := common.Now()
	normalized := make([]common.Map, 0, len(events))
	digests := make([]string, 0, len(events))
	ids := make([]string, 0, len(events))
	info := common.M(common.M(s.Config["nodes"])[node])
	for _, value := range events {
		original, ok := value.(common.Map)
		if !ok {
			return nil, errEvent
		}
		e := common.Clone(original)
		id := common.S(e["event_id"])
		op := common.S(e["operation"])
		if !eventID.MatchString(id) || !common.Contains([]string{"create", "modify", "delete", "move", "probe", "scan", "health", "test"}, op) {
			return nil, errEvent
		}
		for _, k := range []string{"path", "site", "time", "risk"} {
			if v, ok := e[k]; ok {
				str, valid := v.(string)
				if !valid || len(str) > 8192 {
					return nil, errEvent
				}
			}
		}
		if v, ok := e["node_id"]; ok && common.S(v) != node {
			return nil, errEvent
		}
		if _, err := time.Parse(time.RFC3339Nano, common.S(e["time"])); err != nil {
			return nil, errEvent
		}
		e["node_id"] = node
		for _, k := range []string{"server_ip", "server_name", "received_time"} {
			delete(e, k)
		}
		canonical, err := common.Canonical(e, false)
		if err != nil {
			return nil, errEvent
		}
		digests = append(digests, common.Hash(canonical))
		e["server_ip"], e["server_name"] = info["host"], info["name"]
		normalized = append(normalized, e)
		ids = append(ids, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for i, e := range normalized {
		var old string
		err = tx.QueryRowContext(ctx, "SELECT digest FROM events WHERE node=? AND id=?", node, ids[i]).Scan(&old)
		if err == nil {
			if old != digests[i] {
				return nil, errEvent
			}
			continue
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
		e["received_time"] = common.Stamp()
		payload := string(common.JSON(e))
		if _, err = tx.ExecContext(ctx, "INSERT INTO events VALUES(?,?,?,?,?)", node, ids[i], digests[i], payload, stamp); err != nil {
			return nil, err
		}
		deploymentTest, err := deploymentModify(ctx, tx, node, e)
		if err != nil {
			return nil, err
		}
		deploymentTest = deploymentTest && common.B(common.M(s.Config["feishu"])["enabled"]) && common.Contains(common.SS(s.Config["active_nodes"]), node)
		acceptance, err := acceptanceEvent(ctx, tx, node, e)
		if err != nil {
			return nil, err
		}
		for _, target := range []string{"loki", "feishu"} {
			if target == "feishu" && acceptance && !deploymentTest {
				continue
			}
			if target == "feishu" && !deploymentTest && !s.Notify(node, e) {
				continue
			}
			priority := 0
			if target == "feishu" && deploymentTest {
				priority = 100
			}
			if target == "feishu" {
				switch common.S(e["operation"]) {
				case "health", "test":
					priority = 100
				case "scan":
					priority = 90
				}
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO tasks(node,event_id,target,payload,created,next_try,priority) VALUES(?,?,?,?,?,?,?)", node, ids[i], target, payload, stamp, stamp, priority); err != nil {
				return nil, err
			}
		}
		if common.S(e["operation"]) == "probe" {
			if _, err = tx.ExecContext(ctx, "INSERT INTO probes(node,received,event_id) VALUES(?,?,?) ON CONFLICT(node) DO UPDATE SET received=excluded.received,event_id=excluded.event_id", node, stamp, ids[i]); err != nil {
				return nil, err
			}
		}
	}
	return ids, tx.Commit()
}
func (s *Store) Notice(ctx context.Context, id, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, e := s.DB.ExecContext(ctx, "INSERT OR IGNORE INTO tasks(node,event_id,target,payload,created,next_try,priority) VALUES(?,?,?,?,?,?,100)", "central", id, "feishu", string(common.JSON(common.Map{"message": message})), common.Now(), common.Now())
	return e
}
func (s *Store) identity(r *http.Request) string {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	for node, v := range common.M(s.Config["nodes"]) {
		if token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(common.S(common.M(v)["token"]))) == 1 {
			return node
		}
	}
	return ""
}
func write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(common.JSON(v))
}
func (s *Store) Handler(w http.ResponseWriter, r *http.Request) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		write(w, 503, common.Map{"error": "overloaded"})
		return
	}
	public := r.TLS != nil
	path := r.URL.Path
	if public {
		ipstr, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil {
			write(w, 403, common.Map{})
			return
		}
		ip := net.ParseIP(ipstr)
		allowed := false
		for _, cidr := range common.SS(common.M(s.Config["https"])["allowed_sources"]) {
			_, network, e := net.ParseCIDR(cidr)
			if e == nil && network.Contains(ip) {
				allowed = true
			}
		}
		if !allowed {
			write(w, 403, common.Map{})
			return
		}
		if path != "/webscan/v1/events" && path != "/webscan/v1/receipts" {
			write(w, 404, common.Map{})
			return
		}
		path = strings.TrimPrefix(path, "/webscan/v1")
	}
	if r.Method == http.MethodGet && !public {
		switch path {
		case "/ready":
			var n int
			if s.DB.QueryRowContext(r.Context(), "SELECT 1").Scan(&n) != nil {
				write(w, 503, common.Map{})
				return
			}
			write(w, 200, common.Map{"ready": true, "event_protocol": 1, "deployment_acceptance": true})
			return
		case "/metrics":
			v, e := s.Metrics(r.Context())
			if e != nil {
				write(w, 503, common.Map{})
				return
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = io.WriteString(w, v)
			return
		}
	}
	if r.Method != http.MethodPost {
		write(w, 404, common.Map{})
		return
	}
	node := s.identity(r)
	admin := common.S(s.Config["alert_token"]) != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+common.S(s.Config["alert_token"]))) == 1
	deployment := path == "/deployment-notices" || path == "/deployment-tests" || path == "/deployment-acceptance"
	if deployment && !admin || node == "" && !(admin && (path == "/alerts" || deployment)) {
		write(w, 401, common.Map{})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(common.I(s.Config["max_request_mib"]))*1048576)
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		write(w, 413, common.Map{"error": "request_size"})
		return
	}
	value, e := common.Decode(raw)
	if e != nil {
		write(w, 400, common.Map{"error": "invalid_json"})
		return
	}
	if deployment {
		s.deploymentRequest(w, r, path, common.M(value))
		return
	}
	switch path {
	case "/events":
		events, ok := value.([]any)
		if !ok {
			events = []any{value}
		}
		ids, e := s.Ingest(r.Context(), node, events)
		if e != nil {
			if errors.Is(e, errEvent) {
				write(w, 400, common.Map{"error": e.Error()})
			} else {
				write(w, 503, common.Map{"error": "persistence_unavailable"})
			}
			return
		}
		write(w, 200, common.Map{"accepted": ids})
	case "/receipts":
		values, ok := common.M(value)["event_ids"].([]any)
		if !ok || len(values) > 1000 {
			write(w, 400, common.Map{})
			return
		}
		ids := []string{}
		for _, v := range values {
			id, ok := v.(string)
			if !ok {
				write(w, 400, common.Map{})
				return
			}
			var n int
			e := s.DB.QueryRowContext(r.Context(), "SELECT 1 FROM events WHERE node=? AND id=?", node, id).Scan(&n)
			if e == nil {
				ids = append(ids, id)
			} else if e != sql.ErrNoRows {
				write(w, 503, common.Map{})
				return
			}
		}
		write(w, 200, common.Map{"accepted": ids})
	case "/alerts":
		if !admin {
			write(w, 401, common.Map{})
			return
		}
		for _, v := range common.A(common.M(value)["alerts"]) {
			a := common.M(v)
			resolved := common.S(a["status"]) == "resolved"
			key := "health_failures"
			if resolved {
				key = "health_recoveries"
			}
			if !common.B(common.M(common.M(s.Config["feishu"])["notifications"])[key]) {
				continue
			}
			id := "alert:" + common.Hash(common.JSON(a)) + ":" + strconv.FormatInt(time.Now().Unix()/60, 10)
			if e = s.Notice(r.Context(), id, s.alertNotice(a)); e != nil {
				write(w, 503, common.Map{})
				return
			}
		}
		write(w, 200, common.Map{})
	default:
		write(w, 404, common.Map{})
	}
}

type Task struct {
	ID                             int64
	Node, EventID, Target, Payload string
	Attempts                       int
}

func (s *Store) claim(ctx context.Context, target string) (*Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	t := &Task{}
	e = tx.QueryRowContext(ctx, "SELECT id,node,event_id,target,payload,attempts FROM tasks WHERE target=? AND done IS NULL AND next_try<=? AND lease<=? ORDER BY priority DESC,id LIMIT 1", target, common.Now(), common.Now()).Scan(&t.ID, &t.Node, &t.EventID, &t.Target, &t.Payload, &t.Attempts)
	if e == sql.ErrNoRows {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE tasks SET lease=? WHERE id=?", common.Now()+120, t.ID); e != nil {
		return nil, e
	}
	return t, tx.Commit()
}
func (s *Store) finish(ctx context.Context, t *Task, result string, failed bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	now := common.Now()
	if _, e = tx.ExecContext(ctx, "INSERT INTO delivery_records(task_id,target,time,status) VALUES(?,?,?,?)", t.ID, t.Target, now, result); e != nil {
		return e
	}
	if t.Target == "feishu" {
		record := common.Map{"operation": "delivery", "node_id": t.Node, "related_event_id": t.EventID, "time": common.Stamp(), "target": "feishu", "attempt": t.Attempts + 1, "status": result}
		if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO tasks(node,event_id,target,payload,created,next_try) VALUES(?,?,?,?,?,?)", t.Node, fmt.Sprintf("delivery:%d:%d", t.ID, t.Attempts), "loki", string(common.JSON(record)), now, now); e != nil {
			return e
		}
	}
	if failed {
		retry := common.M(common.M(s.Config["feishu"])["retry"])
		delay := min(common.F(retry["max_delay_seconds"]), common.F(retry["initial_delay_seconds"])*float64(int64(1)<<min(t.Attempts, 16)))
		if common.B(retry["jitter"]) {
			delay *= 0.8 + float64(time.Now().UnixNano()%4000)/10000
		}
		_, e = tx.ExecContext(ctx, "UPDATE tasks SET attempts=attempts+1,lease=0,next_try=?,result=? WHERE id=?", now+max(delay, 1), result, t.ID)
	} else {
		_, e = tx.ExecContext(ctx, "UPDATE tasks SET done=?,lease=0,result=? WHERE id=?", now, result, t.ID)
		if e == nil {
			_, e = tx.ExecContext(ctx, "INSERT INTO kv VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", "last_success_"+t.Target, strconv.FormatFloat(now, 'f', 6, 64))
		}
		if t.Target == "loki" {
			v, err := common.Decode([]byte(t.Payload))
			if err == nil && common.S(common.M(v)["operation"]) == "probe" && e == nil {
				_, e = tx.ExecContext(ctx, "INSERT INTO kv VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", "probe_query_"+t.Node, t.Payload)
			}
		}
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}

var mention = regexp.MustCompile(`(?i)<\s*/?\s*at\b`)

func FeishuPayload(f common.Map, message string, stamp int64) common.Map {
	message = mention.ReplaceAllStringFunc(common.S(f["message_prefix"])+"\n"+message, func(m string) string { return "＜" + m[1:] })
	out := common.Map{"msg_type": "text", "content": common.Map{"text": message}}
	if common.B(f["signing_enabled"]) {
		timestamp := strconv.FormatInt(stamp, 10)
		mac := hmac.New(sha256.New, []byte(timestamp+"\n"+common.S(f["signing_secret"])))
		out["timestamp"], out["sign"] = timestamp, base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	return out
}
func (s *Store) send(ctx context.Context, t *Task) (string, error) {
	v, e := common.Decode([]byte(t.Payload))
	if e != nil {
		return "", e
	}
	event := common.M(v)
	if t.Target == "loki" {
		event["log_index_time"] = common.Stamp()
		payload := common.Map{"streams": []any{common.Map{"stream": common.Map{"job": "webscan-v1", "node_id": t.Node, "operation": common.S(event["operation"])}, "values": [][]string{{strconv.FormatInt(time.Now().UnixNano(), 10), string(common.JSON(event))}}}}}
		status, _, e := common.Request(ctx, s.HTTP, "POST", common.S(s.Config["loki_url"])+"/loki/api/v1/push", payload, nil)
		if e != nil {
			return "", e
		}
		return fmt.Sprintf("http=%d", status), nil
	}
	f := common.M(s.Config["feishu"])
	message := common.S(event["message"])
	if message == "" {
		message = eventNotice(event)
	}
	status, response, e := common.Request(ctx, s.HTTP, "POST", common.S(f["webhook_url"]), FeishuPayload(f, message, time.Now().Unix()), nil)
	if e != nil {
		return "", e
	}
	m := common.M(response)
	code, ok := m["code"]
	if !ok {
		code, ok = m["StatusCode"]
	}
	if !ok {
		return "", errors.New("feishu_missing_business_code")
	}
	if common.I(code) != 0 {
		return "", fmt.Errorf("feishu_business_code_%d", common.I(code))
	}
	return fmt.Sprintf("http=%d,business=0", status), nil
}
func (s *Store) worker(ctx context.Context, target string) {
	for ctx.Err() == nil {
		if target == "feishu" {
			f := common.M(common.M(s.Config["feishu"])["rate_limit"])
			now := common.Now()
			for len(s.history) > 0 && s.history[0] < now-60 {
				s.history = s.history[1:]
			}
			delay := 0.0
			if len(s.history) > 0 {
				delay = s.history[len(s.history)-1] + 1/max(common.F(f["max_per_second"]), 0.01) - now
				if len(s.history) >= max(common.I(f["max_per_minute"]), 1) {
					delay = max(delay, s.history[0]+60-now)
				}
			}
			if delay > 0 {
				common.Sleep(ctx, time.Duration(min(delay, 1)*float64(time.Second)))
				continue
			}
		}
		t, e := s.claim(ctx, target)
		if e != nil {
			fmt.Println("delivery_claim_error=" + common.SecretFree(e))
			common.Sleep(ctx, time.Second)
			continue
		}
		if t == nil {
			common.Sleep(ctx, 500*time.Millisecond)
			continue
		}
		if target == "feishu" {
			s.history = append(s.history, common.Now())
			if _, e = s.DB.ExecContext(ctx, "INSERT INTO kv VALUES('feishu_rate_history',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", string(common.JSON(s.history))); e != nil {
				fmt.Println("rate_history_error=" + common.SecretFree(e))
			}
		}
		result, e := s.send(ctx, t)
		if ctx.Err() != nil {
			return
		}
		if e != nil {
			result = common.SecretFree(e)
			if strings.HasPrefix(e.Error(), "feishu_business_code_") {
				result = e.Error()
			}
		}
		if err := s.finish(ctx, t, result, e != nil); err != nil {
			fmt.Println("delivery_finish_error=" + common.SecretFree(err))
			common.Sleep(ctx, time.Second)
		}
	}
}
func (s *Store) Metrics(ctx context.Context) (string, error) {
	var out strings.Builder
	for _, target := range []string{"loki", "feishu"} {
		var n int
		var oldest sql.NullFloat64
		if e := s.DB.QueryRowContext(ctx, "SELECT COUNT(*),MIN(created) FROM tasks WHERE target=? AND done IS NULL", target).Scan(&n, &oldest); e != nil {
			return "", e
		}
		age := 0.0
		if oldest.Valid {
			age = max(common.Now()-oldest.Float64, 0)
		}
		fmt.Fprintf(&out, "webscan_pending_tasks{target=%q} %d\nwebscan_oldest_pending_seconds{target=%q} %g\n", target, n, target, age)
		var val string
		s.DB.QueryRowContext(ctx, "SELECT value FROM kv WHERE key=?", "last_success_"+target).Scan(&val)
		f, _ := strconv.ParseFloat(val, 64)
		fmt.Fprintf(&out, "webscan_delivery_last_success_seconds{target=%q} %g\n", target, f)
	}
	for node, v := range common.M(s.Config["nodes"]) {
		fmt.Fprintf(&out, "webscan_node_registered{node_id=%q,server_name=%q} 1\n", node, common.S(common.M(v)["name"]))
		var received, loki float64
		s.DB.QueryRowContext(ctx, "SELECT received,loki FROM probes WHERE node=?", node).Scan(&received, &loki)
		fmt.Fprintf(&out, "webscan_probe_received_seconds{node_id=%q} %g\nwebscan_probe_loki_seconds{node_id=%q} %g\n", node, received, node, loki)
	}
	out.WriteString("webscan_central_up 1\n")
	return out.String(), nil
}
func (s *Store) QueryProbes(ctx context.Context) error {
	rows, e := s.DB.QueryContext(ctx, "SELECT key,value FROM kv WHERE key LIKE 'probe_query_%'")
	if e != nil {
		return e
	}
	pending := [][2]string{}
	for rows.Next() {
		var key, value string
		if e = rows.Scan(&key, &value); e != nil {
			rows.Close()
			return e
		}
		pending = append(pending, [2]string{key, value})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, row := range pending {
		v, e := common.Decode([]byte(row[1]))
		if e != nil {
			return e
		}
		event := common.M(v)
		query := fmt.Sprintf("{job=\"webscan-v1\",node_id=%q} |= %q", common.S(event["node_id"]), common.S(event["event_id"]))
		params := url.Values{"query": {query}, "limit": {"1"}, "start": {strconv.FormatInt(time.Now().Add(-24*time.Hour).UnixNano(), 10)}}
		_, response, e := common.Request(ctx, s.HTTP, "GET", common.S(s.Config["loki_url"])+"/loki/api/v1/query_range?"+params.Encode(), nil, nil)
		if e != nil {
			return e
		}
		if len(common.A(common.M(common.M(response)["data"])["result"])) > 0 {
			s.mu.Lock()
			tx, e := s.DB.BeginTx(ctx, nil)
			if e == nil {
				_, e = tx.ExecContext(ctx, "UPDATE probes SET loki=received WHERE node=? AND event_id=?", event["node_id"], event["event_id"])
				if e == nil {
					_, e = tx.ExecContext(ctx, "DELETE FROM kv WHERE key=? AND value=?", row[0], row[1])
				}
				if e == nil {
					e = tx.Commit()
				} else {
					tx.Rollback()
				}
			}
			s.mu.Unlock()
			if e != nil {
				return e
			}
		}
	}
	return nil
}
func Run(ctx context.Context, configPath string) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	config, e := common.ReadJSON(configPath)
	if e != nil {
		return e
	}
	s, e := New(config)
	if e != nil {
		return e
	}
	defer func() { cancel(); workers.Wait(); s.DB.Close() }()
	if _, e = s.DB.Exec("UPDATE tasks SET lease=0 WHERE done IS NULL"); e != nil {
		return e
	}
	var heartbeat string
	if s.DB.QueryRow("SELECT value FROM kv WHERE key='heartbeat'").Scan(&heartbeat) == nil {
		n, _ := strconv.ParseFloat(heartbeat, 64)
		if common.Now()-n > 180 {
			if e = s.Notice(ctx, "resume:"+common.ID(), "中央服务恢复；停机期间将补传已记录事件。"); e != nil {
				return e
			}
		}
	}
	for _, target := range []string{"loki", "feishu"} {
		workers.Add(1)
		go func(target string) { defer workers.Done(); s.worker(ctx, target) }(target)
	}
	workers.Add(1)
	go func() { defer workers.Done(); s.maintenance(ctx) }()
	cfg := ghttp.ServerConfig{Name: "webscan-central", Address: fmt.Sprintf("%s:%d", common.S(config["bind"]), common.I(config["port"])), ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384, KeepAlive: true, LogLevel: "error", LogStdout: false, AccessLogEnabled: false, ErrorLogEnabled: false, DumpRouterMap: false, Handler: s.Handler}
	https := common.M(config["https"])
	if common.I(https["port"]) > 0 {
		pair, err := tls.LoadX509KeyPair(common.S(https["cert_file"]), common.S(https["key_file"]))
		if err != nil {
			return errors.New("invalid_server_certificate")
		}
		cfg.HTTPSAddr = fmt.Sprintf("%s:%d", common.S(https["bind"]), common.I(https["port"]))
		cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	}
	server := ghttp.GetServer("webscan-central")
	if e = server.SetConfig(cfg); e != nil {
		return e
	}
	if e = server.Start(); e != nil {
		return e
	}
	fmt.Println("central_ready=goframe-v2.10.3")
	<-ctx.Done()
	return server.Shutdown()
}
