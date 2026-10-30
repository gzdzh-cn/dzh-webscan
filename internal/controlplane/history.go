package controlplane

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"webscan/internal/common"
)

var ErrHistoryInput = errors.New("历史操作参数不正确")
var ErrHistoryPreview = errors.New("清理预览已失效或配置已变化，请重新预览")
var ErrHistoryExport = errors.New("历史导出暂不可用，请检查受控导出目录及剩余空间")

type HistoryScope struct {
	Categories    []string  `json:"categories"`
	Node          string    `json:"node,omitempty"`
	Before        time.Time `json:"before,omitempty"`
	Records       []string  `json:"records,omitempty"`
	IncludeProbes bool      `json:"include_probes"`
}
type HistoryPreview struct {
	Token     string       `json:"token"`
	Scope     HistoryScope `json:"scope"`
	Version   int64        `json:"settings_version"`
	Eligible  int64        `json:"eligible"`
	Protected int64        `json:"protected"`
	Expires   time.Time    `json:"expires_at"`
}
type historySelector struct {
	Source string `json:"source"`
	Node   string `json:"node"`
	ID     string `json:"id"`
}

func historySelectorFor(key string) (historySelector, error) {
	var v historySelector
	if strings.HasPrefix(key, "event:") && len(key) <= 2048 {
		raw, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, "event:"))
		var fields []string
		if e != nil || json.Unmarshal(raw, &fields) != nil || len(fields) != 3 || (fields[0] != "events" && fields[0] != "migrated_events") || !eventText(fields[1], 512) || !eventText(fields[2], 256) {
			return v, ErrHistoryInput
		}
		if eventRecordKey(fields[0], fields[1], fields[2]) != key {
			return v, ErrHistoryInput
		}
		return historySelector{fields[0], fields[1], fields[2]}, nil
	}
	if strings.HasPrefix(key, "server-health:") && eventText(strings.TrimPrefix(key, "server-health:"), 256) {
		return historySelector{Source: "server_health", ID: strings.TrimPrefix(key, "server-health:")}, nil
	}
	for prefix, source := range map[string]string{"website-incident:": "website_incidents", "notification:": "notifications"} {
		if strings.HasPrefix(key, prefix) {
			id := strings.TrimPrefix(key, prefix)
			n, e := strconv.ParseInt(id, 10, 64)
			if e != nil || n < 1 || strconv.FormatInt(n, 10) != id {
				return v, ErrHistoryInput
			}
			return historySelector{Source: source, ID: id}, nil
		}
	}
	return v, ErrHistoryInput
}

func (v *HistoryScope) validate(now time.Time) ([]historySelector, error) {
	if len(v.Categories) < 1 || len(v.Categories) > 6 || len(v.Records) > 200 || (v.Records != nil && len(v.Records) == 0) || (v.Node != "" && !eventText(v.Node, 512)) {
		return nil, ErrHistoryInput
	}
	allowed := map[string]bool{"events": true, "security-events": true, "website-incidents": true, "server-alerts": true, "feishu": true, "email": true}
	seen := map[string]bool{}
	for _, c := range v.Categories {
		if !allowed[c] || seen[c] {
			return nil, ErrHistoryInput
		}
		seen[c] = true
	}
	sort.Strings(v.Categories)
	if v.Before.IsZero() {
		v.Before = now.Add(-30 * 24 * time.Hour)
		if len(v.Records) > 0 {
			v.Before = now.Add(-24 * time.Hour)
		}
	}
	v.Before = v.Before.UTC()
	if v.Before.Before(time.Unix(0, 0)) || v.Before.After(now.Add(-24*time.Hour)) {
		return nil, fmt.Errorf("%w：禁止清理最近 24 小时记录", ErrHistoryInput)
	}
	selectors := []historySelector{}
	seen = map[string]bool{}
	for _, key := range v.Records {
		sel, err := historySelectorFor(key)
		if err != nil || seen[key] {
			return nil, ErrHistoryInput
		}
		seen[key] = true
		selectors = append(selectors, sel)
	}
	return selectors, nil
}

func historyCategory(scope HistoryScope, stage int) (string, string, bool) {
	category, source := "", ""
	switch stage {
	case 0, 2:
		category = "events"
	case 1, 3:
		category = "security-events"
	case 4:
		category = "website-incidents"
	case 5:
		category = "server-alerts"
	case 6:
		category = "notifications"
	}
	switch stage {
	case 0, 1:
		source = "events"
	case 2, 3:
		source = "migrated_events"
	case 4:
		source = "website_incidents"
	case 5:
		source = "server_health"
	case 6:
		source = "notifications"
	}
	for _, c := range scope.Categories {
		if c == category || stage == 6 && (c == "feishu" || c == "email") {
			return category, source, true
		}
	}
	return category, source, false
}

func (s *Store) PreviewHistory(ctx context.Context, user string, scope HistoryScope) (HistoryPreview, error) {
	var out HistoryPreview
	scope.Categories = append([]string(nil), scope.Categories...)
	if !identifier.MatchString(user) {
		return out, ErrHistoryInput
	}
	// The materialization uses one database snapshot; a later cleanup cannot
	// silently expand to newly matching records or all current filter results.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if held, e := migrationHeld(ctx, tx); e != nil {
		return out, e
	} else if held {
		return out, ErrMigrationPending
	}
	// The write gate forces a repeatable-read serialization failure instead
	// of letting simultaneous previews use an old snapshot to exceed quotas.
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_history_gates(username,version) VALUES($1,1) ON CONFLICT(username) DO UPDATE SET version=v3_history_gates.version+1", user); err != nil {
		return out, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return out, err
	}
	selectors, err := scope.validate(now)
	if err != nil {
		return out, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM v3_history_previews WHERE username=$1 AND NOT used AND expires_at>clock_timestamp()", user).Scan(&count); err != nil {
		return out, err
	}
	if count >= 100 {
		return out, fmt.Errorf("%w：有效预览过多，请等待旧预览过期", ErrHistoryInput)
	}
	_, out.Version, err = retentionTxSettings(ctx, tx)
	if err != nil {
		return out, err
	}
	out.Token = token()
	id := digest([]byte(out.Token))
	out.Scope = scope
	if err = tx.QueryRowContext(ctx, "INSERT INTO v3_history_previews(id,username,settings_version,scope,cutoff) VALUES($1,$2,$3,$4,$5) RETURNING expires_at", id, user, out.Version, common.JSON(scope), scope.Before).Scan(&out.Expires); err != nil {
		return HistoryPreview{}, err
	}
	for stage := 0; stage <= 6; stage++ {
		_, source, include := historyCategory(scope, stage)
		if !include {
			continue
		}
		x, _ := retentionSourceFor(stage)
		condition := x.condition
		if stage < 4 && !scope.IncludeProbes {
			condition += " AND t.operation<>'probe'"
		}
		if stage == 2 || stage == 3 {
			condition += " AND (t.event_id='' OR NOT EXISTS(SELECT 1 FROM v3_event_keys k WHERE k.node=t.node AND k.id=t.event_id))"
		}
		if stage == 6 {
			channels := []string{}
			for _, c := range scope.Categories {
				if c == "email" || c == "feishu" {
					channels = append(channels, c)
				}
			}
			condition += " AND t.channel IN ("
			for i, c := range channels {
				if i > 0 {
					condition += ","
				}
				condition += "'" + c + "'"
			}
			condition += ")"
		}
		nodeFilter := x.node + "=$3"
		if stage == 4 {
			nodeFilter = "EXISTS(SELECT 1 FROM v3_websites w WHERE w.id=t.site AND w.node=$3)"
		}
		keys := `jsonb_to_recordset($4::jsonb) AS k(source text,node text,id text)`
		selected := `EXISTS(SELECT 1 FROM ` + keys + ` WHERE k.source='` + source + `' AND k.id=` + x.id
		if stage < 4 {
			selected += ` AND k.node=` + x.node
		}
		selected += `)`
		filter := x.tm + `<$2`
		if len(selectors) > 0 {
			filter = selected
		}
		q := `INSERT INTO v3_history_items(preview,stage,node,id,stamp,eligible) SELECT $1,` + strconv.Itoa(stage) + `,` + x.node + `,` + x.id + `,` + x.tm + `,` + x.tm + `<$2 AND NOT COALESCE((` + strings.ReplaceAll(x.protected, "__cutoff__", "$2") + `),false) FROM ` + x.table + ` t WHERE ` + condition + ` AND ($3='' OR ` + nodeFilter + `) AND ` + filter
		// Keep the parameter shape constant for range and selected-record queries.
		q += ` AND jsonb_typeof($4::jsonb)='array'`
		if _, err = tx.ExecContext(ctx, q, id, scope.Before, scope.Node, common.JSON(selectors)); err != nil {
			return HistoryPreview{}, err
		}
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FILTER(WHERE eligible),count(*) FILTER(WHERE NOT eligible) FROM v3_history_items WHERE preview=$1", id).Scan(&out.Eligible, &out.Protected); err != nil {
		return HistoryPreview{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_history_previews SET eligible=$2,protected=$3 WHERE id=$1", id, out.Eligible, out.Protected); err != nil {
		return HistoryPreview{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'retention-preview',$2,$3)", user, id, common.JSON(common.Map{"scope": scope, "eligible": out.Eligible, "protected": out.Protected})); err != nil {
		return HistoryPreview{}, err
	}
	return out, tx.Commit()
}

type HistoryJob struct {
	ID               string     `json:"id"`
	Username         string     `json:"username"`
	Kind             string     `json:"kind"`
	ExportFirst      bool       `json:"export_first"`
	Version          int64      `json:"settings_version"`
	Cutoff           time.Time  `json:"cutoff"`
	Phase            string     `json:"phase"`
	Status           string     `json:"status"`
	Cursor           int64      `json:"-"`
	ExportCursor     int64      `json:"-"`
	Scanned          int64      `json:"scanned"`
	Deleted          int64      `json:"deleted"`
	Skipped          int64      `json:"skipped"`
	DependentDeleted int64      `json:"dependent_deleted"`
	Exported         int64      `json:"exported"`
	ExportBytes      int64      `json:"export_bytes"`
	ExportReady      bool       `json:"export_ready"`
	ExportExpires    *time.Time `json:"export_expires_at"`
	Message          string     `json:"message"`
	Created          time.Time  `json:"created_at"`
	Updated          time.Time  `json:"updated_at"`
	Finished         *time.Time `json:"finished_at"`
	Preview          string     `json:"-"`
}

const historyJobColumns = `id,username,kind,export_first,settings_version,cutoff,phase,status,cursor,export_cursor,scanned,deleted,skipped,dependent_deleted,exported,export_bytes,export_ready,export_expires_at,message,created_at,updated_at,finished_at,preview`

func scanHistoryJob(row interface{ Scan(...any) error }) (HistoryJob, error) {
	var j HistoryJob
	err := row.Scan(&j.ID, &j.Username, &j.Kind, &j.ExportFirst, &j.Version, &j.Cutoff, &j.Phase, &j.Status, &j.Cursor, &j.ExportCursor, &j.Scanned, &j.Deleted, &j.Skipped, &j.DependentDeleted, &j.Exported, &j.ExportBytes, &j.ExportReady, &j.ExportExpires, &j.Message, &j.Created, &j.Updated, &j.Finished, &j.Preview)
	return j, err
}

func (s *Store) SubmitHistory(ctx context.Context, user, key, preview, kind string, exportFirst, confirm bool) (json.RawMessage, error) {
	if !validArchiveSource(preview) || kind != "export" && kind != "cleanup" || kind == "cleanup" && !exportFirst && !confirm {
		return nil, fmt.Errorf("%w：请确认永久删除，或选择先导出再清理", ErrHistoryInput)
	}
	hash := digest([]byte(preview))
	return s.mutation(ctx, user, key, "retention-"+kind, "history", []any{hash, exportFirst, confirm}, func(tx *sql.Tx) (any, error) {
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,773376013))", user); err != nil {
			return nil, err
		}
		var version int64
		var cutoff time.Time
		if err := tx.QueryRowContext(ctx, "SELECT settings_version,cutoff FROM v3_history_previews WHERE id=$1 AND username=$2 AND NOT used AND expires_at>clock_timestamp() FOR UPDATE", hash, user).Scan(&version, &cutoff); err == sql.ErrNoRows {
			return nil, ErrHistoryPreview
		} else if err != nil {
			return nil, err
		}
		_, current, err := retentionTxSettings(ctx, tx)
		if err != nil {
			return nil, err
		}
		if current != version {
			return nil, ErrHistoryPreview
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM v3_history_jobs WHERE username=$1 AND status IN ('queued','running')", user).Scan(&count); err != nil {
			return nil, err
		}
		if count >= 5 {
			return nil, fmt.Errorf("%w：请等待已有历史操作结束", ErrHistoryInput)
		}
		phase := "cleanup"
		if kind == "export" || exportFirst {
			phase = "export"
		}
		j, err := scanHistoryJob(tx.QueryRowContext(ctx, "INSERT INTO v3_history_jobs(id,username,preview,kind,export_first,settings_version,cutoff,phase,message) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'等待分批处理；任务创建不代表清理完成') RETURNING "+historyJobColumns, token(), user, hash, kind, exportFirst, version, cutoff, phase))
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, "UPDATE v3_history_previews SET used=true WHERE id=$1", hash)
		return j, err
	})
}

func (s *Store) HistoryJob(ctx context.Context, user, id string) (HistoryJob, error) {
	if !validArchiveSource(id) {
		return HistoryJob{}, sql.ErrNoRows
	}
	return scanHistoryJob(s.DB.QueryRowContext(ctx, "SELECT "+historyJobColumns+" FROM v3_history_jobs WHERE id=$1 AND username=$2", id, user))
}
func (s *Store) HistoryJobs(ctx context.Context, user string, before retentionCursor, limit int) ([]HistoryJob, error) {
	if limit < 1 || limit > 200 {
		return nil, ErrHistoryInput
	}
	if before.Time.IsZero() {
		before.Time = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+historyJobColumns+" FROM v3_history_jobs WHERE username=$1 AND (created_at,id)<($2,$3) ORDER BY created_at DESC,id DESC LIMIT $4", user, before.Time, before.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HistoryJob{}
	for rows.Next() {
		j, e := scanHistoryJob(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
