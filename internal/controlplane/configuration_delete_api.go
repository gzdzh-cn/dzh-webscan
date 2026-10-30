package controlplane

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
)

// Authentication, admin role and CSRF are checked by the parent route. Store
// methods repeat authorization and bind both capabilities and jobs to owner.
func (a *API) configurationDeleteRoutes(w http.ResponseWriter, r *http.Request, id identity, path string) bool {
	if path != "/delete-preview" && path != "/delete" && path != "/delete-jobs" && !strings.HasPrefix(path, "/delete-jobs/") {
		return false
	}
	if path == "/delete-jobs" && r.Method == "GET" {
		limit, err := pageSize(r, 20)
		if err != nil {
			failure(w, 400, "invalid_limit", err.Error())
			return true
		}
		cursor, err := decodeRetentionCursor(r.URL.Query().Get("cursor"))
		if err != nil {
			failure(w, 400, "invalid_cursor", "分页游标不正确")
			return true
		}
		items, err := a.Store.configurationDeleteJobs(r.Context(), id.Username, cursor, limit)
		if err != nil {
			configurationBackupFailure(w, err)
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
	if strings.HasPrefix(path, "/delete-jobs/") && r.Method == "GET" {
		job, items, err := a.Store.configurationDeleteJob(r.Context(), id.Username, strings.TrimPrefix(path, "/delete-jobs/"))
		if errors.Is(err, sql.ErrNoRows) {
			failure(w, 404, "delete_job_not_found", "删除任务不存在或不属于当前账号")
		} else if err != nil {
			configurationBackupFailure(w, err)
		} else {
			reply(w, 200, map[string]any{"job": job, "items": items})
		}
		return true
	}
	if (path == "/delete-preview" || path == "/delete") && r.Method == "POST" {
		if path == "/delete-preview" {
			var in struct {
				Records []string `json:"records"`
			}
			if decode(w, r, &in) != nil {
				configurationBackupFailure(w, errConfigurationDeleteInput)
				return true
			}
			out, err := a.Store.previewConfigurationDelete(r.Context(), id.Username, in.Records)
			if err != nil {
				configurationBackupFailure(w, err)
			} else {
				reply(w, 200, out)
			}
			return true
		}
		var in struct {
			Token   string `json:"token"`
			Confirm bool   `json:"confirm"`
		}
		if decode(w, r, &in) != nil {
			configurationBackupFailure(w, errConfigurationDeleteInput)
			return true
		}
		key, ok := mutationKey(w, r)
		if !ok {
			return true
		}
		out, err := a.Store.submitConfigurationDelete(r.Context(), id.Username, key, in.Token, in.Confirm)
		if err != nil {
			configurationBackupFailure(w, err)
		} else {
			mutationReply(w, out, nil)
		}
		return true
	}
	failure(w, 405, "method_not_allowed", "请求方法不正确")
	return true
}
