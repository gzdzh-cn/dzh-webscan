// Package pull implements the durable Agent side of the v3 pull protocol.
package pull

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	agentv1 "webscan/sdk/agent/v1"
)

const MaxBytes = agentv1.MaxBytes
const MaxEvents = agentv1.MaxEvents
const schema = `CREATE TABLE IF NOT EXISTS pull_state(id INTEGER PRIMARY KEY,epoch INTEGER NOT NULL);
INSERT OR IGNORE INTO pull_state VALUES(1,0);
CREATE TABLE IF NOT EXISTS pull_receipts(token TEXT PRIMARY KEY,epoch INTEGER NOT NULL,ids TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pull_metrics(sampled INTEGER PRIMARY KEY,payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_failures(id TEXT PRIMARY KEY,error TEXT NOT NULL,created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_status(id INTEGER PRIMARY KEY,error TEXT NOT NULL,updated REAL NOT NULL);`

type Source struct {
	DB              *sql.DB
	NodeID, Version string
	WriteMu         *sync.Mutex
	fetch           chan struct{}
	configuration   Configuration
}

// Configuration is fixed for the lifetime of a Source/listener. Updating a
// desired config in PostgreSQL cannot change this running Agent's receipt.
type Configuration struct {
	Version int64
	SHA256  string
}

// Caller must take a consistent backup before upgrading an existing database.
func New(db *sql.DB, node, version string, mu *sync.Mutex, configurations ...Configuration) (*Source, error) {
	if node == "" {
		return nil, errors.New("节点身份不能为空")
	}
	configuration := Configuration{}
	if len(configurations) > 1 {
		return nil, errors.New("无效生效配置版本")
	}
	if len(configurations) == 1 {
		configuration = configurations[0]
		raw, err := hex.DecodeString(configuration.SHA256)
		if configuration.Version < 1 || err != nil || len(raw) != 32 || hex.EncodeToString(raw) != configuration.SHA256 {
			return nil, errors.New("无效生效配置版本")
		}
	}
	if mu == nil {
		mu = new(sync.Mutex)
	}
	mu.Lock()
	_, e := db.Exec(schema)
	mu.Unlock()
	if e != nil {
		return nil, e
	}
	return &Source{DB: db, NodeID: node, Version: version, WriteMu: mu, fetch: make(chan struct{}, 1), configuration: configuration}, nil
}

func (s *Source) Capabilities() *agentv1.CapabilitiesResponse {
	return &agentv1.CapabilitiesResponse{NodeId: s.NodeID, Version: s.Version, Protocol: agentv1.ProtocolVersion, MaxEvents: MaxEvents, MaxBytes: MaxBytes, ConfigurationVersion: s.configuration.Version, ConfigurationSha256: s.configuration.SHA256}
}

func (s *Source) fence(ctx context.Context, tx *sql.Tx, epoch uint64) error {
	if epoch == 0 || epoch > 1<<63-1 {
		return errors.New("无效采集代次")
	}
	r, e := tx.ExecContext(ctx, "UPDATE pull_state SET epoch=? WHERE id=1 AND epoch<=?", epoch, epoch)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return errors.New("采集代次已失效")
	}
	return nil
}

func (s *Source) Fetch(ctx context.Context, epoch uint64, limit int, wait time.Duration) (*agentv1.EventBatch, error) {
	if limit < 1 || limit > MaxEvents || wait < 0 || wait > 25*time.Second {
		return nil, errors.New("事件批次或等待时间不正确")
	}
	select {
	case s.fetch <- struct{}{}:
		defer func() { <-s.fetch }()
	default:
		return nil, errors.New("已有事件读取请求")
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		b, e := s.batch(ctx, epoch, limit)
		if e != nil || len(b.Events) > 0 || wait == 0 {
			return b, e
		}
		t := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-timer.C:
			t.Stop()
			return b, nil
		case <-t.C:
		}
	}
}

func (s *Source) batch(ctx context.Context, epoch uint64, limit int) (*agentv1.EventBatch, error) {
	s.WriteMu.Lock()
	defer s.WriteMu.Unlock()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = s.fence(ctx, tx, epoch); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT id,payload FROM events WHERE accepted IS NULL AND NOT EXISTS(SELECT 1 FROM delivery_failures f WHERE f.id=events.id) ORDER BY created,id LIMIT ?", limit)
	if e != nil {
		return nil, e
	}
	b := &agentv1.EventBatch{NodeId: s.NodeID}
	ids := []string{}
	bad := map[string]string{}
	size := 0
	for rows.Next() {
		var id string
		var raw []byte
		if e = rows.Scan(&id, &raw); e != nil {
			break
		}
		if !json.Valid(raw) {
			bad[id] = "invalid_local_json"
			continue
		}
		if len(raw) > MaxBytes-4096 {
			bad[id] = "event_exceeds_request_limit"
			continue
		}
		if size+len(raw)+len(id)+32 > MaxBytes-4096 {
			break
		}
		size += len(raw) + len(id) + 32
		ids = append(ids, id)
		b.Events = append(b.Events, &agentv1.Event{Id: id, Json: raw})
	}
	re := rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if re != nil {
		return nil, re
	}
	now := time.Now()
	for id, code := range bad {
		if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO delivery_failures VALUES(?,?,?)", id, code, float64(now.UnixMilli())/1000); e != nil {
			return nil, e
		}
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM pull_receipts WHERE expires<=?", now.Unix()); e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT OR REPLACE INTO delivery_status VALUES(1,'',?)", float64(now.UnixMilli())/1000); e != nil {
		return nil, e
	}
	if len(ids) > 0 {
		r := make([]byte, 32)
		if _, e = rand.Read(r); e != nil {
			return nil, e
		}
		b.Receipt = hex.EncodeToString(r)
		raw, _ := json.Marshal(ids)
		if _, e = tx.ExecContext(ctx, "INSERT INTO pull_receipts VALUES(?,?,?,?)", b.Receipt, epoch, string(raw), now.Add(10*time.Minute).Unix()); e != nil {
			return nil, e
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return b, nil
}

func (s *Source) Ack(ctx context.Context, r *agentv1.AckEventsRequest) (uint32, error) {
	if len(r.Accepted)+len(r.Rejected) > MaxEvents || len(r.Receipt) != 64 {
		return 0, errors.New("确认参数不正确")
	}
	s.WriteMu.Lock()
	defer s.WriteMu.Unlock()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	if e = s.fence(ctx, tx, r.Epoch); e != nil {
		return 0, e
	}
	var raw string
	e = tx.QueryRowContext(ctx, "SELECT ids FROM pull_receipts WHERE token=? AND epoch=? AND expires>?", r.Receipt, r.Epoch, time.Now().Unix()).Scan(&raw)
	if e != nil {
		return 0, errors.New("确认凭据已失效，请重新读取事件")
	}
	var ids []string
	if e = json.Unmarshal([]byte(raw), &ids); e != nil {
		return 0, e
	}
	allowed := map[string]bool{}
	for _, id := range ids {
		allowed[id] = true
	}
	seen := map[string]bool{}
	for _, id := range r.Accepted {
		if !allowed[id] || seen[id] {
			return 0, errors.New("确认包含未提供或重复的事件")
		}
		seen[id] = true
	}
	for _, v := range r.Rejected {
		if v == nil || !allowed[v.Id] || seen[v.Id] || !validCode(v.Code) {
			return 0, errors.New("拒绝记录参数不正确")
		}
		seen[v.Id] = true
	}
	now := float64(time.Now().UnixMilli()) / 1000
	for _, id := range r.Accepted {
		if _, e = tx.ExecContext(ctx, "UPDATE events SET accepted=COALESCE(accepted,?) WHERE id=?", now, id); e != nil {
			return 0, e
		}
	}
	for _, v := range r.Rejected {
		if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO delivery_failures VALUES(?,?,?)", v.Id, v.Code, now); e != nil {
			return 0, e
		}
	}
	if _, e = tx.ExecContext(ctx, "INSERT OR REPLACE INTO delivery_status VALUES(1,'',?)", now); e != nil {
		return 0, e
	}
	if e = tx.Commit(); e != nil {
		return 0, e
	}
	return uint32(len(r.Accepted)), nil
}
func validCode(v string) bool {
	switch v {
	case "invalid_event", "identity_mismatch", "event_too_large", "event_id_conflict":
		return true
	}
	return false
}

func (s *Source) RecordMetrics(ctx context.Context, at time.Time, raw []byte) error {
	if len(raw) > MaxBytes-4096 || len(raw) == 0 {
		return errors.New("指标大小超限或为空")
	}
	s.WriteMu.Lock()
	defer s.WriteMu.Unlock()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "INSERT OR REPLACE INTO pull_metrics VALUES(?,?)", at.UnixMilli(), raw); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM pull_metrics WHERE sampled<?", at.Add(-time.Hour).UnixMilli()); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Source) Metrics(ctx context.Context, after int64) (*agentv1.MetricsBatch, error) {
	if after < 0 {
		return nil, fmt.Errorf("指标游标不能为负数")
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT sampled,payload FROM pull_metrics WHERE sampled>? ORDER BY sampled LIMIT 120", after)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	b := &agentv1.MetricsBatch{NodeId: s.NodeID}
	size := 0
	for rows.Next() {
		p := new(agentv1.MetricsSample)
		if e = rows.Scan(&p.UnixMillis, &p.PrometheusText); e != nil {
			return nil, e
		}
		if size+len(p.PrometheusText) > MaxBytes-4096 {
			break
		}
		size += len(p.PrometheusText)
		b.Samples = append(b.Samples, p)
	}
	return b, rows.Err()
}
