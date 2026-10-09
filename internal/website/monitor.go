package website

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"webscan/internal/common"
)

//go:embed ui
var UI embed.FS

const schema = `
CREATE TABLE IF NOT EXISTS websites(id INTEGER PRIMARY KEY,name TEXT NOT NULL,url TEXT NOT NULL,node TEXT NOT NULL DEFAULT '',keyword TEXT NOT NULL DEFAULT '',slow INTEGER NOT NULL DEFAULT 0,paused INTEGER NOT NULL DEFAULT 0,deleted INTEGER NOT NULL DEFAULT 0,version INTEGER NOT NULL DEFAULT 1,state TEXT NOT NULL DEFAULT '{}');
CREATE UNIQUE INDEX IF NOT EXISTS websites_url ON websites(url) WHERE deleted=0;
CREATE TABLE IF NOT EXISTS website_incidents(id INTEGER PRIMARY KEY,site INTEGER NOT NULL,kind TEXT NOT NULL,started INTEGER NOT NULL,ended INTEGER,reason TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS website_incidents_site ON website_incidents(site,started);
CREATE TABLE IF NOT EXISTS website_outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,site INTEGER NOT NULL,node TEXT NOT NULL,kind TEXT NOT NULL,message TEXT NOT NULL,created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS website_outbox_ready ON website_outbox(created);
CREATE INDEX IF NOT EXISTS tasks_website_pending ON tasks(target,id) WHERE node='central' AND done IS NULL AND event_id LIKE 'website:%';
`

type Site struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Node    string `json:"node"`
	Keyword string `json:"keyword"`
	Slow    bool   `json:"slow_alert"`
	Paused  bool   `json:"paused"`
	Version int64  `json:"version"`
	State   State  `json:"state"`
}
type State struct {
	Status       string `json:"status"`
	Last         Result `json:"last"`
	Next         int64  `json:"next"`
	Failures     int    `json:"failures"`
	Successes    int    `json:"successes"`
	Checks       int64  `json:"checks"`
	Passed       int64  `json:"passed"`
	Incident     int64  `json:"incident"`
	DownSince    int64  `json:"down_since"`
	Reminder     int64  `json:"reminder"`
	CertExpired  bool   `json:"cert_expired"`
	CertWarn     bool   `json:"cert_warn"`
	CertIncident int64  `json:"cert_incident"`
	CertReminder int64  `json:"cert_reminder"`
	SlowSince    int64  `json:"slow_since"`
	SlowIncident int64  `json:"slow_incident"`
	Fast         int    `json:"fast"`
}
type session struct {
	Revision int64
	CSRF     string
	Expires  time.Time
}
type attempt struct {
	Count int
	Until time.Time
}
type Monitor struct {
	DB             *sql.DB
	Config         common.Map
	Nodes          common.Map
	WriteMu        *sync.Mutex
	mu             sync.Mutex
	active         map[int64]context.CancelFunc
	sessions       map[string]session
	attempts       map[string]attempt
	probe          *prober
	pulse          atomic.Int64
	backlogSince   atomic.Int64
	healthNotified bool
	workers        sync.WaitGroup
	PasswordHash   string
	Username       string
	ConsoleURL     string
	Notify         bool
}

func New(db *sql.DB, config, nodes common.Map, writeMu *sync.Mutex, notify bool) (*Monitor, error) {
	if writeMu == nil {
		writeMu = &sync.Mutex{}
	}
	m := &Monitor{DB: db, Config: config, Nodes: nodes, WriteMu: writeMu, active: map[int64]context.CancelFunc{}, sessions: map[string]session{}, attempts: map[string]attempt{}, probe: newProber(), PasswordHash: common.S(config["password_hash"]), Username: common.S(config["admin_username"]), ConsoleURL: common.S(config["console_url"]), Notify: notify}
	if e := m.migrate(); e != nil {
		return nil, e
	}
	return m, nil
}
func scanSite(row interface{ Scan(...any) error }) (s Site, e error) {
	var raw string
	e = row.Scan(&s.ID, &s.Name, &s.URL, &s.Node, &s.Keyword, &s.Slow, &s.Paused, &s.Version, &raw)
	if e == nil {
		e = json.Unmarshal([]byte(raw), &s.State)
		if s.State.Status == "" {
			s.State.Status = "pending"
		}
	}
	return
}

const columns = "id,name,url,node,keyword,slow,paused,version,state"

func (m *Monitor) sites(ctx context.Context) ([]Site, error) {
	rows, e := m.DB.QueryContext(ctx, "SELECT "+columns+" FROM websites WHERE deleted=0 ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Site{}
	for rows.Next() {
		s, e := scanSite(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
func (m *Monitor) cancel(id int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f := m.active[id]; f != nil {
		f()
	}
}
func (m *Monitor) Run(ctx context.Context) {
	m.pulse.Store(time.Now().Unix())
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		warned := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stalled := time.Now().Unix()-m.pulse.Load() > 90
				if stalled && !warned {
					if m.healthNotice(ctx, "网站检测调度超过 90 秒没有运行，请检查主服务器监控服务") == nil {
						warned = true
					}
				}
				if !stalled && warned {
					if m.healthNotice(ctx, "网站检测调度已恢复运行") == nil {
						warned = false
					}
				}
			}
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	defer m.workers.Wait()
	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			for _, f := range m.active {
				f()
			}
			m.mu.Unlock()
			return
		case <-tick.C:
			now := time.Now().Unix()
			m.pulse.Store(now)
			sites, e := m.sites(ctx)
			if e != nil {
				continue
			}
			pending := 0
			for _, s := range sites {
				if s.Paused {
					continue
				}
				if s.State.Next > now {
					continue
				}
				pending++
				m.start(ctx, s, now)
			}
			if pending > max(1, common.I(m.Config["max_concurrent"])) {
				if m.backlogSince.Load() == 0 {
					m.backlogSince.Store(now)
				}
			} else {
				m.backlogSince.Store(0)
			}
			if m.backlogSince.Load() > 0 && now-m.backlogSince.Load() >= 180 && !m.healthNotified {
				if m.healthNotice(ctx, "网站检测任务持续积压超过 3 分钟，请检查主服务器负载及检测并发限制") == nil {
					m.healthNotified = true
				}
			}
			if m.backlogSince.Load() == 0 && m.healthNotified {
				if m.healthNotice(ctx, "网站检测调度已恢复，积压任务已消退") == nil {
					m.healthNotified = false
				}
			}
			if e := m.flush(ctx, now); e != nil {
				fmt.Println("website_notification_flush_failed")
			}
			if now%3600 == 0 {
				m.WriteMu.Lock()
				_, _ = m.DB.ExecContext(ctx, "DELETE FROM website_incidents WHERE ended IS NOT NULL AND ended<?", now-30*86400)
				m.WriteMu.Unlock()
			}
		}
	}
}

// Reserve the due time under the shared database writer lock. A scheduler
// snapshot can be older than a completed task; rereading prevents duplicate checks.
func (m *Monitor) start(ctx context.Context, s Site, now int64) {
	m.mu.Lock()
	_, busy := m.active[s.ID]
	full := len(m.active) >= max(1, common.I(m.Config["max_concurrent"]))
	m.mu.Unlock()
	if busy || full {
		return
	}
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	current, e := scanSite(m.DB.QueryRowContext(ctx, "SELECT "+columns+" FROM websites WHERE id=? AND deleted=0", s.ID))
	if e != nil || current.Paused || current.State.Next > now {
		return
	}
	current.State.Next = now + int64(max(1, common.I(m.Config["interval_seconds"])))
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, busy = m.active[s.ID]; busy || len(m.active) >= max(1, common.I(m.Config["max_concurrent"])) {
		return
	}
	if _, e = m.DB.ExecContext(ctx, "UPDATE websites SET state=? WHERE id=?", string(common.JSON(current.State)), s.ID); e != nil {
		return
	}
	task, cancel := context.WithCancel(ctx)
	m.active[s.ID] = cancel
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		defer func() { m.mu.Lock(); delete(m.active, s.ID); m.mu.Unlock(); cancel() }()
		r := m.probe.check(task, current, time.Duration(max(1, common.I(m.Config["timeout_seconds"])))*time.Second)
		if task.Err() == nil {
			if e := m.apply(task, current, r); e != nil {
				fmt.Println("website_result_persist_failed")
			}
		}
	}()
}
func (m *Monitor) healthNotice(ctx context.Context, message string) error {
	if !m.Notify {
		return nil
	}
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	_, e := m.DB.ExecContext(ctx, "INSERT INTO tasks(node,event_id,target,payload,created,next_try) VALUES('central',?,'feishu',?,?,?)", "website:health:"+common.ID(), string(common.JSON(common.Map{"message": message})), common.Now(), common.Now())
	return e
}
func (m *Monitor) apply(ctx context.Context, s Site, r Result) error {
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	tx, e := m.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	current, e := scanSite(tx.QueryRowContext(ctx, "SELECT "+columns+" FROM websites WHERE id=? AND deleted=0", s.ID))
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	if current.Version != s.Version || current.Paused {
		return nil
	}
	st := current.State
	// Network failures retain the last certificate without claiming it was
	// checked or renewed. A successful plain-HTTP check is explicitly N/A.
	if r.CertExpires == 0 && !r.OK && st.Last.CertExpires > 0 {
		r.CertExpires = st.Last.CertExpires
		r.CertHost = st.Last.CertHost
		r.CertChecked = st.Last.CertChecked
		r.CertApplicable = true
		if r.CertError == "" {
			r.CertError = "本次证书检查失败，保留最近证书信息"
		}
	}
	freshCertificate := r.CertExpires > 0 && (r.CertError == "" || r.CertObserved)
	st.Last = r
	st.Checks++
	now := r.Time
	st.Next = now + int64(max(1, common.I(m.Config["interval_seconds"])))
	notice := func(kind, message string) error {
		if !m.Notify {
			return nil
		}
		_, e := tx.ExecContext(ctx, "INSERT INTO website_outbox(site,node,kind,message,created) VALUES(?,?,?,?,?)", s.ID, s.Node, kind, m.message(s, message, r), now)
		return e
	}
	incident := func(kind string) (int64, error) {
		reason := r.Reason
		if kind == "slow" {
			reason = "网站响应超过 3 秒并持续 5 分钟"
		}
		if kind == "certificate" {
			reason = "HTTPS 证书剩余有效期不超过 7 天"
		}
		v, e := tx.ExecContext(ctx, "INSERT INTO website_incidents(site,kind,started,reason) VALUES(?,?,?,?)", s.ID, kind, now, reason)
		if e != nil {
			return 0, e
		}
		return v.LastInsertId()
	}
	closeIncident := func(id int64) error {
		_, e := tx.ExecContext(ctx, "UPDATE website_incidents SET ended=? WHERE id=? AND ended IS NULL", now, id)
		return e
	}
	if r.OK {
		st.Passed++
		st.Successes++
		st.Failures = 0
		if st.Incident != 0 && st.Successes >= 2 {
			if e = closeIncident(st.Incident); e != nil {
				return e
			}
			if e = notice("recovery", fmt.Sprintf("网站已恢复访问；故障持续 %s", time.Duration(now-st.DownSince)*time.Second)); e != nil {
				return e
			}
			st.Incident = 0
			st.DownSince = 0
			st.Status = "normal"
		} else if st.Incident == 0 {
			st.Status = "normal"
		}
	} else {
		st.Failures++
		st.Successes = 0
		if st.Failures >= 3 && st.Incident == 0 {
			st.Status = "down"
			st.DownSince = now
			st.Reminder = now
			st.Incident, e = incident("outage")
			if e != nil {
				return e
			}
			if e = notice("outage", "网站连续 3 次检查失败，无法正常访问；原因："+r.Reason); e != nil {
				return e
			}
		}
		if st.Incident != 0 && now-st.Reminder >= 4*3600 {
			st.Reminder = now
			if e = notice("outage_reminder", "网站仍无法正常访问；原因："+r.Reason); e != nil {
				return e
			}
		}
	}
	if r.CertExpires > 0 {
		remaining := r.CertExpires - now
		expired := remaining <= 0
		days := int64(0)
		if remaining > 0 {
			days = (remaining + 86399) / 86400
		}
		if remaining <= 7*86400 && (!st.CertWarn || now-st.CertReminder >= 86400 || expired && !st.CertExpired) {
			if !st.CertWarn {
				st.CertIncident, e = incident("certificate")
				if e != nil {
					return e
				}
			}
			st.CertWarn = true
			st.CertReminder = now
			text := fmt.Sprintf("HTTPS 证书将在 %d 天内到期，请及时续签", days)
			if expired {
				text = "HTTPS 证书已过期，请立即续签"
			}
			if !freshCertificate {
				text += "；本次证书检查失败，以上为最近一次取得的证书信息"
			}
			if e = notice("certificate", text); e != nil {
				return e
			}
		}
		if remaining > 7*86400 && freshCertificate && r.CertError == "" && st.CertWarn {
			if st.CertIncident != 0 {
				if e = closeIncident(st.CertIncident); e != nil {
					return e
				}
				st.CertIncident = 0
			}
			st.CertWarn = false
			if e = notice("certificate_recovery", "HTTPS 证书已更新，有效期恢复正常"); e != nil {
				return e
			}
		}
		st.CertExpired = expired
	}
	if s.Slow && !r.OK {
		st.SlowSince = 0
		st.Fast = 0
	}
	if s.Slow && r.OK {
		if r.Latency > 3 {
			st.Fast = 0
			if st.SlowSince == 0 {
				st.SlowSince = now
			}
			if now-st.SlowSince >= 300 && st.SlowIncident == 0 {
				st.SlowIncident, e = incident("slow")
				if e != nil {
					return e
				}
				if e = notice("slow", "网站响应超过 3 秒并持续 5 分钟，请检查网站负载"); e != nil {
					return e
				}
			}
		} else {
			st.Fast++
			st.SlowSince = 0
			if st.SlowIncident != 0 && st.Fast >= 2 {
				if e = closeIncident(st.SlowIncident); e != nil {
					return e
				}
				if e = notice("slow_recovery", "网站响应速度已恢复正常"); e != nil {
					return e
				}
				st.SlowIncident = 0
			}
		}
	}
	_, e = tx.ExecContext(ctx, "UPDATE websites SET state=? WHERE id=?", string(common.JSON(st)), s.ID)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (m *Monitor) message(s Site, text string, r Result) string {
	node := "主服务器检测"
	if n := common.M(m.Nodes[s.Node]); len(n) > 0 {
		node = common.S(n["name"]) + "（" + common.S(n["host"]) + "）"
	}
	return fmt.Sprintf("网站可用性提醒\n网站：%s\n地址：%s\n关联服务器：%s\n情况：%s\n发生时间：%s（北京时间）", s.Name, s.URL, node, text, time.Unix(r.Time, 0).In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05"))
}
func (m *Monitor) flush(ctx context.Context, now int64) error {
	if !m.Notify {
		return nil
	}
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	tx, e := m.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var first int64
	e = tx.QueryRowContext(ctx, "SELECT MIN(created) FROM website_outbox HAVING MIN(created)<=?", now-15).Scan(&first)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, "SELECT id,node,kind,message,site FROM website_outbox WHERE created<=? ORDER BY id", first+14)
	if e != nil {
		return e
	}
	type group struct {
		node, kind string
		ids        []int64
		messages   []string
	}
	groups := []group{}
	index := map[string]int{}
	lastGroup := map[int64]int{}
	for rows.Next() {
		var id, site int64
		var node, kind, msg string
		if e = rows.Scan(&id, &node, &kind, &msg, &site); e != nil {
			rows.Close()
			return e
		}
		key := node + "\x00" + kind
		idx, ok := index[key]
		previous, seen := lastGroup[site]
		if !ok || (seen && idx < previous) {
			idx = len(groups)
			index[key] = idx
			groups = append(groups, group{node: node, kind: kind})
		}
		lastGroup[site] = idx
		groups[idx].ids = append(groups[idx].ids, id)
		groups[idx].messages = append(groups[idx].messages, msg)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, g := range groups {
		messages := g.messages
		if len(messages) > 5 {
			messages = []string{fmt.Sprintf("网站可用性批量提醒：共 %d 个网站\n%s\n其余网站请查看管理后台：%s", len(g.ids), strings.Join(messages[:5], "\n\n"), m.ConsoleURL)}
		}
		for i, msg := range messages {
			if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO tasks(node,event_id,target,payload,created,next_try) VALUES('central',?,'feishu',?,?,?)", fmt.Sprintf("website:%d:%d", g.ids[0], i), string(common.JSON(common.Map{"message": msg})), float64(now), float64(now)); e != nil {
				return e
			}
		}
		for _, id := range g.ids {
			if _, e = tx.ExecContext(ctx, "DELETE FROM website_outbox WHERE id=?", id); e != nil {
				return e
			}
		}
	}
	return tx.Commit()
}
func (m *Monitor) Metrics(ctx context.Context) string {
	sites, e := m.sites(ctx)
	if e != nil {
		return "webscan_website_scheduler_up 0\n"
	}
	var b strings.Builder
	healthy := 0
	if time.Now().Unix()-m.pulse.Load() < 10 {
		healthy = 1
	}
	fmt.Fprintf(&b, "webscan_website_scheduler_up %d\nwebscan_website_backlog_seconds %d\n", healthy, max(0, time.Now().Unix()-m.backlog()))
	for _, s := range sites {
		if s.Paused {
			continue
		}
		st := s.State
		available := -1
		if st.Status == "normal" {
			available = 1
		} else if st.Status == "down" {
			available = 0
		}
		rate := 0.0
		if st.Checks > 0 {
			rate = float64(st.Passed) / float64(st.Checks)
		}
		label := fmt.Sprintf("site_id=%q,website=%q,node_id=%q", fmt.Sprint(s.ID), s.Name, s.Node)
		known := 0
		days := "NaN"
		if st.Last.CertExpires > 0 {
			known = 1
			days = fmt.Sprint(float64(st.Last.CertExpires-time.Now().Unix()) / 86400)
		}
		fmt.Fprintf(&b, "webscan_website_certificate_known{%s} %d\nwebscan_website_certificate_remaining_days{%s} %s\n", label, known, label, days)
		fmt.Fprintf(&b, "webscan_website_available{%s} %d\nwebscan_website_latency_seconds{%s} %g\nwebscan_website_http_status{%s} %d\nwebscan_website_certificate_expiry_seconds{%s} %d\nwebscan_website_success_ratio{%s} %g\nwebscan_website_last_check_seconds{%s} %d\n", label, available, label, st.Last.Latency, label, st.Last.HTTP, label, st.Last.CertExpires, label, rate, label, st.Last.Time)
	}
	return b.String()
}
func (m *Monitor) backlog() int64 {
	if m.backlogSince.Load() == 0 {
		return time.Now().Unix()
	}
	return m.backlogSince.Load()
}
