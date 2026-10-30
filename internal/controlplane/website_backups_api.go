package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

func websiteBackupFailure(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, sql.ErrNoRows):
		failure(w, 404, "backup_not_found", "备份不存在")
	case errors.Is(err, ErrBackupPreview):
		failure(w, 409, "preview_expired", err.Error())
	case errors.Is(err, ErrWebsiteBackupInput):
		failure(w, 400, "invalid_backup", err.Error())
	default:
		mutationReply(w, nil, err)
	}
}

func (a *API) websiteBackupRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	const prefix = "/api/v3/website-backups"
	if r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/") {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if path == "" && r.Method == "GET" {
		limit, err := pageSize(r, 20)
		if err != nil {
			failure(w, 400, "invalid_limit", err.Error())
			return true
		}
		before, err := decodeRetentionCursor(r.URL.Query().Get("cursor"))
		if err != nil {
			failure(w, 400, "invalid_cursor", err.Error())
			return true
		}
		items, err := a.Store.WebsiteBackups(ctx, before, limit)
		if err != nil {
			failure(w, 503, "query_failed", "备份列表暂时不可用")
			return true
		}
		next := ""
		if len(items) == limit {
			last := items[len(items)-1]
			next = (retentionCursor{last.Created, last.ID}).encode()
		}
		reply(w, 200, map[string]any{"items": items, "next_cursor": next})
		return true
	}
	if path == "/import" && r.Method == "POST" {
		key, ok := mutationKey(w, r)
		if !ok {
			return true
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, websiteBackupImportLimit))
		if err != nil {
			failure(w, 400, "invalid_backup", "备份读取失败或超过 2 MiB")
			return true
		}
		data, err := a.Store.ImportWebsiteBackup(ctx, id.Username, key, raw)
		if err != nil {
			websiteBackupFailure(w, err)
		} else {
			mutationReply(w, data, nil)
		}
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 2 && parts[1] == "export" && r.Method == "GET" {
		doc, err := a.Store.ExportWebsiteBackup(ctx, parts[0])
		if err != nil {
			websiteBackupFailure(w, err)
			return true
		}
		w.Header().Set("Content-Disposition", `attachment; filename="website-config-`+parts[0]+`.json"`)
		reply(w, 200, doc)
		return true
	}
	if r.Method != "POST" {
		failure(w, 405, "method_not_allowed", "请求方法不正确")
		return true
	}
	if path == "/delete" {
		var in struct {
			IDs []string `json:"records"`
		}
		if err := decode(w, r, &in); err != nil {
			failure(w, 400, "invalid_request", err.Error())
			return true
		}
		key, ok := mutationKey(w, r)
		if !ok {
			return true
		}
		data, err := a.Store.DeleteWebsiteBackups(ctx, id.Username, key, in.IDs)
		if err != nil {
			websiteBackupFailure(w, err)
		} else {
			mutationReply(w, data, nil)
		}
		return true
	}
	if len(parts) == 2 && parts[1] == "restore" {
		var in struct {
			Token string `json:"token"`
		}
		if err := decode(w, r, &in); err != nil {
			failure(w, 400, "invalid_request", err.Error())
			return true
		}
		key, ok := mutationKey(w, r)
		if !ok {
			return true
		}
		data, err := a.Store.RestoreWebsiteBackup(ctx, id.Username, key, parts[0], in.Token)
		if err != nil {
			websiteBackupFailure(w, err)
		} else {
			mutationReply(w, data, nil)
		}
		return true
	}
	if path == "" || len(parts) == 2 && parts[1] == "preview" {
		var in struct{}
		if err := decode(w, r, &in); err != nil {
			failure(w, 400, "invalid_request", err.Error())
			return true
		}
		if path == "" {
			key, ok := mutationKey(w, r)
			if !ok {
				return true
			}
			data, err := a.Store.CreateWebsiteBackup(ctx, id.Username, key)
			if err != nil {
				websiteBackupFailure(w, err)
			} else {
				mutationReply(w, data, nil)
			}
		} else {
			out, err := a.Store.PreviewWebsiteBackup(ctx, id.Username, parts[0])
			if err != nil {
				websiteBackupFailure(w, err)
			} else {
				reply(w, 200, out)
			}
		}
		return true
	}
	failure(w, 404, "not_found", "备份接口不存在")
	return true
}
