package controlplane

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *API) deploymentRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	path := r.URL.Path
	if path != "/api/v3/deployments" && !strings.HasPrefix(path, "/api/v3/deployments/") {
		return false
	}
	if r.Method != "GET" {
		if r.Method == "POST" {
			a.deploymentRecoveryWrite(w, r, id)
		} else {
			failure(w, 405, "method_not_allowed", "请使用 GET 或规定的恢复操作")
		}
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if path == "/api/v3/deployments" {
		limit, err := pageSize(r, 20)
		if err != nil {
			failure(w, 400, "invalid_limit", err.Error())
			return true
		}
		var cursor struct {
			Time time.Time `json:"time"`
			ID   string    `json:"id"`
		}
		if value := r.URL.Query().Get("cursor"); value != "" {
			raw, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil || len(raw) > 1024 || json.Unmarshal(raw, &cursor) != nil || cursor.Time.IsZero() || !identifier.MatchString(cursor.ID) {
				failure(w, 400, "invalid_cursor", "分页游标不正确")
				return true
			}
		}
		node := r.URL.Query().Get("node")
		if node != "" && !identifier.MatchString(node) {
			failure(w, 400, "invalid_node", "节点编号不正确")
			return true
		}
		items, err := a.Store.Deployments(ctx, cursor.Time, cursor.ID, node, limit)
		if err != nil {
			failure(w, 503, "query_failed", "部署任务查询失败")
			return true
		}
		next := ""
		if len(items) == limit {
			last := items[len(items)-1]
			raw, _ := json.Marshal(struct {
				Time time.Time `json:"time"`
				ID   string    `json:"id"`
			}{last.CreatedAt, last.ID})
			next = base64.RawURLEncoding.EncodeToString(raw)
		}
		reply(w, 200, map[string]any{"items": items, "next_cursor": next, "limit": limit})
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/api/v3/deployments/"), "/")
	if len(parts) > 2 || !identifier.MatchString(parts[0]) || len(parts) == 2 && parts[1] != "logs" {
		failure(w, 404, "not_found", "接口不存在")
		return true
	}
	job, err := a.Store.Deployment(ctx, parts[0])
	if err == sql.ErrNoRows {
		failure(w, 404, "not_found", "部署任务不存在")
		return true
	}
	if err != nil {
		failure(w, 503, "query_failed", "部署任务读取失败")
		return true
	}
	if len(parts) == 1 {
		resume, rollback, reason := a.deploymentRecoveryActions(ctx, job, id)
		reply(w, 200, map[string]any{"job": job, "phase": job.Phase(), "can_resume": resume, "can_rollback": rollback, "recovery_required": job.CanRecover(), "recovery_reason": reason})
		return true
	}
	limit, err := pageSize(r, 100)
	if err != nil {
		failure(w, 400, "invalid_limit", err.Error())
		return true
	}
	after := int64(0)
	if value := r.URL.Query().Get("after"); value != "" {
		after, err = strconv.ParseInt(value, 10, 64)
		if err != nil || after < 0 {
			failure(w, 400, "invalid_cursor", "日志游标不正确")
			return true
		}
	}
	logs, err := a.Store.DeploymentLogs(ctx, job.ID, after, limit)
	if err != nil {
		failure(w, 503, "query_failed", "部署日志读取失败")
		return true
	}
	next := after
	if len(logs) > 0 {
		next = logs[len(logs)-1].Cursor
	}
	reply(w, 200, map[string]any{"items": logs, "next_cursor": next, "status": job.Status})
	return true
}

func (a *API) deploymentRecoveryActions(ctx context.Context, j DeploymentJob, id identity) (bool, bool, string) {
	if id.Role != "admin" {
		return false, false, "需要管理员权限"
	}
	if !j.CanRecover() {
		return false, false, "当前任务不需要恢复"
	}
	ready := a.deploymentAvailability(ctx)
	if !ready.Available {
		return false, false, ready.Reason
	}
	if !ready.Trust.release.matches(j) {
		return false, false, "宿主发布资料与原任务不同，请恢复原任务资料"
	}
	tx, err := a.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, false, "任务状态暂不可用"
	}
	defer tx.Rollback()
	if err = checkDeploymentConfigurationTx(ctx, tx, j); err != nil {
		return false, false, "配置或任务状态已变化，请核对原任务"
	}
	return j.Direction != "rollback", true, ""
}
func (a *API) deploymentRecoveryWrite(w http.ResponseWriter, r *http.Request, id identity) {
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "需要管理员权限")
		return
	}
	if !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "恢复操作需要可信 HTTPS 连接")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v3/deployments/"), "/")
	if len(parts) != 2 || !identifier.MatchString(parts[0]) || (parts[1] != "resume" && parts[1] != "rollback") {
		failure(w, 404, "not_found", "接口不存在")
		return
	}
	if !identifier.MatchString(r.Header.Get("Idempotency-Key")) {
		failure(w, 400, "invalid_idempotency_key", "请提供有效幂等键")
		return
	}
	var in struct {
		Plan   string `json:"plan_digest"`
		Cursor int64  `json:"log_cursor"`
	}
	if decodeStrictDeployment(w, r, &in, 16384, "plan_digest", "log_cursor") != nil || !releaseDigest(in.Plan) || in.Cursor < 1 {
		failure(w, 400, "invalid_request", "请刷新任务后重试")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	j, err := a.Store.Deployment(ctx, parts[0])
	if err != nil {
		webDeploymentFailure(w, err)
		return
	}
	ready := a.deploymentAvailability(ctx)
	if !ready.Available {
		failure(w, 503, "executor_unavailable", ready.Reason)
		return
	}
	if !ready.Trust.release.matches(j) {
		failure(w, 409, "recovery_protected", "宿主发布资料与原任务不同，请恢复原任务资料")
		return
	}
	direction := "forward"
	if parts[1] == "rollback" {
		direction = "rollback"
	}
	response, err := a.Store.recoverDeployment(ctx, id.Username, r.Header.Get("Idempotency-Key"), j.ID, direction, in.Plan, in.Cursor, true)
	if err != nil {
		webDeploymentFailure(w, err)
	} else {
		reply(w, 200, response)
	}
}
