package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

func deploymentHistoryDeleteFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errDeploymentHistoryDeleteInput):
		failure(w, 400, "invalid_request", errDeploymentHistoryDeleteInput.Error())
	case errors.Is(err, sql.ErrNoRows):
		failure(w, 404, "not_found", "删除任务不存在或不属于当前账号")
	case errors.Is(err, ErrDeploymentPreview):
		failure(w, 403, "permission_denied", "需要有效管理员权限")
	case errors.Is(err, errDeploymentHistoryDeleteQuota):
		failure(w, 429, "history_delete_quota", errDeploymentHistoryDeleteQuota.Error())
	case errors.Is(err, errDeploymentHistoryDeletePreview), errors.Is(err, ErrConflict), errors.Is(err, ErrRequestConflict), errors.Is(err, ErrDeploymentBusy), errors.Is(err, ErrMigrationPending):
		failure(w, 409, "history_delete_conflict", "删除预览或当前状态已变化，请重新预览；原任务资料保留")
	default:
		failure(w, 503, "history_delete_unavailable", "部署历史操作暂不可用，请稍后重试；原任务资料保留")
	}
}

// Shared authentication and CSRF run before this router. This router must be
// registered before the generic /deployments/:id recovery/detail router.
func (a *API) deploymentHistoryDeleteRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	const base = "/api/v3/deployments/"
	path := strings.TrimPrefix(r.URL.Path, base)
	if !strings.HasPrefix(r.URL.Path, base) || path != "history-delete-preview" && path != "history-delete" && !strings.HasPrefix(path, "history-delete-jobs/") {
		return false
	}
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "需要管理员权限")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if strings.HasPrefix(path, "history-delete-jobs/") {
		jobID := strings.TrimPrefix(path, "history-delete-jobs/")
		if r.Method != http.MethodGet {
			failure(w, 405, "method_not_allowed", "请使用GET查询删除任务")
			return true
		}
		if !identifier.MatchString(jobID) {
			failure(w, 404, "not_found", "删除任务不存在")
			return true
		}
		job, err := a.Store.deploymentHistoryDeleteJob(ctx, id.Username, jobID)
		if err != nil {
			deploymentHistoryDeleteFailure(w, err)
		} else {
			reply(w, 200, job)
		}
		return true
	}
	if r.Method != http.MethodPost {
		failure(w, 405, "method_not_allowed", "请使用POST预览或确认历史删除")
		return true
	}
	if !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "历史删除需要可信HTTPS连接")
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if !identifier.MatchString(key) {
		failure(w, 400, "invalid_idempotency_key", "请提供有效幂等键")
		return true
	}
	if path == "history-delete-preview" {
		var in struct {
			Records []string `json:"records"`
		}
		if decodeStrictDeployment(w, r, &in, 65536, "records") != nil {
			deploymentHistoryDeleteFailure(w, errDeploymentHistoryDeleteInput)
			return true
		}
		out, err := a.Store.previewDeploymentHistoryDelete(ctx, id.Username, key, in.Records)
		if err != nil {
			deploymentHistoryDeleteFailure(w, err)
		} else {
			reply(w, 200, out)
		}
		return true
	}
	var in struct {
		Token   string `json:"token"`
		Confirm bool   `json:"confirm"`
	}
	if decodeStrictDeployment(w, r, &in, 16384, "token", "confirm") != nil {
		deploymentHistoryDeleteFailure(w, errDeploymentHistoryDeleteInput)
		return true
	}
	out, err := a.Store.submitDeploymentHistoryDelete(ctx, id.Username, key, in.Token, in.Confirm)
	if err != nil {
		deploymentHistoryDeleteFailure(w, err)
	} else {
		reply(w, http.StatusAccepted, out)
	}
	return true
}
