package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func historyFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrHistoryInput):
		failure(w, 400, "invalid_history_request", err.Error())
	case errors.Is(err, ErrHistoryPreview):
		failure(w, 409, "history_preview_expired", err.Error())
	case errors.Is(err, sql.ErrNoRows):
		failure(w, 404, "history_job_not_found", "任务不存在或不属于当前账号")
	case errors.Is(err, ErrHistoryExport):
		failure(w, 503, "history_export_unavailable", ErrHistoryExport.Error())
	default:
		mutationReply(w, nil, err)
	}
}

func (a *API) historyRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	const base = "/api/v3/retention/"
	path := strings.TrimPrefix(r.URL.Path, base)
	if !strings.HasPrefix(r.URL.Path, base) {
		return false
	}
	if path != "preview" && path != "export" && path != "cleanup" && !(path == "jobs" && r.URL.Query().Get("kind") == "manual") && !strings.HasPrefix(path, "jobs/") {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if path == "preview" || path == "export" || path == "cleanup" {
		if r.Method != "POST" {
			failure(w, 405, "method_not_allowed", "请使用 POST")
			return true
		}
		if path == "preview" {
			var scope HistoryScope
			if decode(w, r, &scope) != nil {
				failure(w, 400, "invalid_history_request", "请提供有效的历史类别、服务器、截止日期或明确记录列表")
				return true
			}
			out, err := a.Store.PreviewHistory(ctx, id.Username, scope)
			if err != nil {
				historyFailure(w, err)
			} else {
				reply(w, 200, out)
			}
			return true
		}
		var in struct {
			Token       string `json:"token"`
			ExportFirst bool   `json:"export_first"`
			Confirm     bool   `json:"confirm_without_export"`
		}
		if decode(w, r, &in) != nil {
			failure(w, 400, "invalid_history_request", "历史操作请求格式不正确")
			return true
		}
		key, ok := mutationKey(w, r)
		if !ok {
			return true
		}
		raw, err := a.Store.SubmitHistory(ctx, id.Username, key, in.Token, path, in.ExportFirst, in.Confirm)
		if err != nil {
			historyFailure(w, err)
		} else {
			mutationReply(w, raw, nil)
		}
		return true
	}
	if r.Method != "GET" {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return true
	}
	if path == "jobs" {
		limit, err := pageSize(r, 20)
		if err != nil {
			historyFailure(w, ErrHistoryInput)
			return true
		}
		cursor, err := decodeRetentionCursor(r.URL.Query().Get("cursor"))
		if err != nil {
			historyFailure(w, ErrHistoryInput)
			return true
		}
		jobs, err := a.Store.HistoryJobs(ctx, id.Username, cursor, limit)
		if err != nil {
			historyFailure(w, err)
			return true
		}
		next := ""
		if len(jobs) == limit {
			last := jobs[len(jobs)-1]
			next = (retentionCursor{last.Created, last.ID}).encode()
		}
		reply(w, 200, map[string]any{"items": jobs, "next_cursor": next, "kind": "manual"})
		return true
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 || len(parts) > 3 || len(parts) == 3 && parts[2] != "download" {
		failure(w, 404, "not_found", "历史操作接口不存在")
		return true
	}
	job, err := a.Store.HistoryJob(ctx, id.Username, parts[1])
	if errors.Is(err, sql.ErrNoRows) && len(parts) == 2 && validArchiveSource(parts[1]) {
		auto, e := scanRetentionJob(a.Store.DB.QueryRowContext(ctx, "SELECT "+retentionJobColumns+" FROM v3_retention_jobs WHERE id=$1", parts[1]))
		if e == nil {
			reply(w, 200, map[string]any{"kind": "automatic", "job": auto})
			return true
		}
		if !errors.Is(e, sql.ErrNoRows) {
			historyFailure(w, e)
			return true
		}
	}
	if err != nil {
		historyFailure(w, err)
		return true
	}
	if len(parts) == 3 {
		a.downloadHistory(w, r, job)
		return true
	}
	var scope []byte
	if err = a.Store.DB.QueryRowContext(ctx, "SELECT scope FROM v3_history_previews WHERE id=$1", job.Preview).Scan(&scope); err != nil {
		historyFailure(w, err)
		return true
	}
	reply(w, 200, map[string]any{"job": job, "scope": json.RawMessage(scope)})
	return true
}

// An explicit content length lets a client detect a later missing/corrupt part
// as an incomplete download instead of accepting a truncated successful JSONL.
func (a *API) downloadHistory(w http.ResponseWriter, r *http.Request, j HistoryJob) {
	ctx := r.Context()
	var valid bool
	if err := a.Store.DB.QueryRowContext(ctx, "SELECT export_ready AND export_expires_at>clock_timestamp() FROM v3_history_jobs WHERE id=$1 AND username=$2", j.ID, j.Username).Scan(&valid); err != nil {
		historyFailure(w, err)
		return
	}
	if !valid {
		failure(w, 409, "history_export_not_ready", "导出未完成或已过期，请重新预览并导出")
		return
	}
	d, err := a.Store.historyDirectory()
	if err != nil {
		historyFailure(w, err)
		return
	}
	defer d.Close()
	// Load metadata by cursor; the download does not keep all parts or FDs in RAM.
	cursor := int64(0)
	written := int64(0)
	started := false
	completed := false
	if _, err = a.Store.DB.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'retention-download-started',$2,jsonb_build_object('expected_bytes',$3::bigint))", j.Username, j.ID, j.ExportBytes); err != nil {
		historyFailure(w, err)
		return
	}
	defer func() {
		op, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = a.Store.DB.ExecContext(op, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'retention-download-result',$2,jsonb_build_object('written_bytes',$3::bigint,'completed',$4::boolean))", j.Username, j.ID, written, completed)
	}()
	for {
		rows, e := a.Store.DB.QueryContext(ctx, "SELECT id,ordinal,bytes,sha256 FROM v3_history_export_parts WHERE job=$1 AND ready AND ordinal>$2 ORDER BY ordinal LIMIT 100", j.ID, cursor)
		if e != nil {
			if !started {
				historyFailure(w, e)
			}
			return
		}
		batch := []historyPart{}
		for rows.Next() {
			var p historyPart
			if e = rows.Scan(&p.ID, &p.Ordinal, &p.Bytes, &p.SHA256); e != nil {
				break
			}
			batch = append(batch, p)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			if !started {
				historyFailure(w, e)
			}
			return
		}
		if len(batch) == 0 {
			if written != j.ExportBytes {
				if !started {
					historyFailure(w, ErrHistoryExport)
				}
				return
			}
			if !started {
				w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
				w.Header().Set("Content-Length", "0")
				w.Header().Set("Content-Disposition", `attachment; filename="history-`+j.ID+`.jsonl"`)
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(200)
			}
			completed = true
			return
		}
		for _, p := range batch {
			raw, e := readHistoryPart(ctx, d, p)
			if e != nil {
				if !started {
					historyFailure(w, e)
				}
				return
			}
			if written+int64(len(raw)) > j.ExportBytes {
				if !started {
					historyFailure(w, ErrHistoryExport)
				}
				return
			}
			if !started {
				_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Minute))
				w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
				w.Header().Set("Content-Length", strconv.FormatInt(j.ExportBytes, 10))
				w.Header().Set("Content-Disposition", `attachment; filename="history-`+j.ID+`.jsonl"`)
				w.Header().Set("Cache-Control", "no-store")
				started = true
			}
			n, e := w.Write(raw)
			written += int64(n)
			if e != nil || n != len(raw) {
				return
			}
			cursor = p.Ordinal
		}
	}
}
