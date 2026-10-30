package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"webscan/internal/telemetry"
)

type HealthRecord struct {
	ID           string              `json:"id"`
	Node         string              `json:"node"`
	Kind         string              `json:"kind"`
	Phase        string              `json:"phase"`
	Time         int64               `json:"time"`
	Message      string              `json:"message"`
	State        telemetry.RuleState `json:"state"`
	RecordKey    string              `json:"record_key"`
	CanDelete    bool                `json:"can_delete"`
	DeleteReason string              `json:"delete_reason"`
}
type healthCursor struct {
	Time int64  `json:"time"`
	ID   string `json:"id"`
}

func (c healthCursor) encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}
func decodeHealthCursor(raw string) (healthCursor, error) {
	var c healthCursor
	if raw == "" {
		return c, nil
	}
	if len(raw) > 512 {
		return c, errors.New("游标超限")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(b, &c) != nil || c.Time < 1 || c.ID == "" || len(c.ID) > 256 || !utf8.ValidString(c.ID) || strings.ContainsRune(c.ID, 0) {
		return c, errors.New("分页游标不正确")
	}
	return c, nil
}
func (s *Store) CurrentHealth(ctx context.Context, node, after string, limit int) ([]telemetry.RuleState, error) {
	if limit < 1 || limit > 200 {
		return nil, errors.New("每页数量须为 1～200")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT r.payload FROM v3_health_rules r JOIN v3_active_nodes n ON n.id=r.node WHERE n.enabled AND r.phase='firing' AND ($1='' OR r.node=$1) AND r.key>$2 ORDER BY r.key LIMIT $3`, node, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []telemetry.RuleState{}
	for rows.Next() {
		var raw []byte
		var st telemetry.RuleState
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &st); err != nil {
			return nil, err
		}
		result = append(result, st)
	}
	return result, rows.Err()
}
func (s *Store) HealthHistory(ctx context.Context, node, phase string, start, end time.Time, before healthCursor, limit int) ([]HealthRecord, error) {
	if limit < 1 || limit > 200 || !end.After(start) || end.Sub(start) > 31*24*time.Hour || (phase != "" && phase != "firing" && phase != "resolved" && phase != "reminder") {
		return nil, errors.New("告警查询参数不正确")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT e.id,e.node,e.kind,e.phase,e.time,e.message,e.payload,`+historyDeleteReasonSQL(5, "e")+`
 FROM v3_health_events e WHERE time>=$1 AND time<=$2 AND ($3='' OR node=$3) AND ($4='' OR phase=$4)
 AND ($5::bigint=0 OR (time,id)<($5,$6)) ORDER BY time DESC,id DESC LIMIT $7`, start.Unix(), end.Unix(), node, phase, before.Time, before.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []HealthRecord{}
	for rows.Next() {
		var v HealthRecord
		var raw []byte
		if err = rows.Scan(&v.ID, &v.Node, &v.Kind, &v.Phase, &v.Time, &v.Message, &raw, &v.DeleteReason); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &v.State); err != nil {
			return nil, err
		}
		v.RecordKey = "server-health:" + v.ID
		v.CanDelete = v.DeleteReason == ""
		result = append(result, v)
	}
	return result, rows.Err()
}

func (a *API) healthRoutes(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if path != "/api/v3/alerts/current" && path != "/api/v3/alerts/history" {
		return false
	}
	if r.Method != "GET" {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	limit, err := pageSize(r, 20)
	if err != nil {
		failure(w, 400, "invalid_limit", err.Error())
		return true
	}
	q := r.URL.Query()
	node := q.Get("node")
	if node != "" && !identifier.MatchString(node) {
		failure(w, 400, "invalid_node", "节点编号不正确")
		return true
	}
	if path == "/api/v3/alerts/current" {
		after := ""
		if v := q.Get("cursor"); v != "" {
			if len(v) > 1024 {
				failure(w, 400, "invalid_cursor", "分页游标不正确")
				return true
			}
			b, e := base64.RawURLEncoding.DecodeString(v)
			if e != nil || len(b) == 0 || len(b) > 512 || !utf8.Valid(b) || strings.ContainsRune(string(b), 0) {
				failure(w, 400, "invalid_cursor", "分页游标不正确")
				return true
			}
			after = string(b)
		}
		items, e := a.Store.CurrentHealth(ctx, node, after, limit)
		if e != nil {
			failure(w, 503, "query_failed", "当前异常暂时不可用")
			return true
		}
		next := ""
		if len(items) == limit {
			next = base64.RawURLEncoding.EncodeToString([]byte(items[len(items)-1].Key))
		}
		reply(w, 200, map[string]any{"items": items, "next_cursor": next, "limit": limit})
		return true
	}
	start, end, err := timeRange(r)
	if err != nil {
		failure(w, 400, "invalid_time", "时间范围不正确，最多 31 天")
		return true
	}
	before, err := decodeHealthCursor(q.Get("cursor"))
	if err != nil {
		failure(w, 400, "invalid_cursor", err.Error())
		return true
	}
	phase := q.Get("phase")
	if phase != "" && phase != "firing" && phase != "resolved" && phase != "reminder" {
		failure(w, 400, "invalid_phase", "告警阶段不正确")
		return true
	}
	items, err := a.Store.HealthHistory(ctx, node, phase, start, end, before, limit)
	if err != nil {
		failure(w, 503, "query_failed", "告警历史暂时不可用")
		return true
	}
	next := ""
	if len(items) == limit {
		last := items[len(items)-1]
		next = (healthCursor{last.Time, last.ID}).encode()
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next, "limit": limit, "start": start, "end": end})
	return true
}
