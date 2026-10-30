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

func applicationReadFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrConfigurationBackupPermission):
		failure(w, 403, "permission_denied", "只有管理员可以查看配置应用任务")
	case errors.Is(err, sql.ErrNoRows):
		failure(w, 404, "application_not_found", "配置应用任务不存在")
	case errors.Is(err, errApplicationCursor):
		failure(w, 400, "invalid_cursor", errApplicationCursor.Error())
	default:
		failure(w, 503, "application_query_failed", "配置应用任务或日志暂时无法读取，请保留页面后重试")
	}
}

func applicationWriteFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errConfigurationRestoreRequest), errors.Is(err, errApplicationCursor):
		failure(w, 400, "invalid_application_request", "请求不正确，请确认已保存配置及任务版本")
	case errors.Is(err, errApplicationActor):
		failure(w, 403, "application_actor_forbidden", errApplicationActor.Error())
	case errors.Is(err, ErrConfigurationBackupPermission):
		failure(w, 403, "permission_denied", "只有管理员可以管理配置应用")
	case errors.Is(err, ErrConflict), errors.Is(err, ErrRequestConflict), errors.Is(err, errConfigurationSaved), errors.Is(err, errConfigurationRevision), errors.Is(err, errConfigurationApplicationBusy), errors.Is(err, ErrDeploymentBusy):
		failure(w, 409, "application_conflict", "配置或任务状态已变化，请重新读取并确认；未重复执行")
	case errors.Is(err, sql.ErrNoRows):
		failure(w, 404, "application_not_found", "配置应用或已保存恢复不存在")
	case errors.Is(err, ErrMigrationPending):
		failure(w, 503, "migration_pending", ErrMigrationPending.Error())
	default:
		failure(w, 503, "application_unavailable", "配置应用结果暂时无法确认，请保留原请求重试并查看任务；未将未知状态标记为成功")
	}
}

func (a *API) applicationWritesEnabled() bool {
	return a.bootstrapConfig != nil && a.bootstrapConfig.Executor.Enabled && a.bootstrapConfig.Executor.ApplicationsEnabled
}

func applicationDecimal(fields map[string]json.RawMessage, name string) (int64, error) {
	var value string
	if json.Unmarshal(fields[name], &value) != nil {
		return 0, errConfigurationRestoreRequest
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != value {
		return 0, errConfigurationRestoreRequest
	}
	return n, nil
}

func (a *API) configurationApplicationWrite(w http.ResponseWriter, r *http.Request, id identity) {
	if !a.applicationWritesEnabled() {
		failure(w, 503, "application_executor_unavailable", "配置应用工作器未启用，请检查中心执行器配置；未创建或控制任务")
		return
	}
	if !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "配置应用需要可信 HTTPS 连接")
		return
	}
	key, ok := mutationKey(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	before, err := a.configurationEditBackup()
	if err != nil {
		applicationWriteFailure(w, err)
		return
	}
	var raw json.RawMessage
	if r.URL.Path == "/api/v3/configuration-applications" {
		fields, e := decodeConfigurationRestore(w, r, "stage", "generation", "confirm")
		if e != nil || !configurationRestoreConfirmed(fields) {
			applicationWriteFailure(w, errConfigurationRestoreRequest)
			return
		}
		stage, e := configurationRestoreString(fields, "stage")
		generation, gerr := applicationDecimal(fields, "generation")
		if e != nil || gerr != nil || !validArchiveSource(stage) {
			applicationWriteFailure(w, errConfigurationRestoreRequest)
			return
		}
		raw, err = a.Store.queueConfigurationApplication(ctx, before.vault, before.bootstrap, id.Username, key, stage, generation)
	} else {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v3/configuration-applications/"), "/")
		if len(parts) != 2 || !validArchiveSource(parts[0]) || parts[1] != "resume" && parts[1] != "rollback" && parts[1] != "cancel" {
			failure(w, 404, "not_found", "接口不存在")
			return
		}
		fields, e := decodeConfigurationRestore(w, r, "expected_log_cursor", "confirm")
		if e != nil || !configurationRestoreConfirmed(fields) {
			applicationWriteFailure(w, errConfigurationRestoreRequest)
			return
		}
		expected, e := applicationDecimal(fields, "expected_log_cursor")
		if e != nil {
			applicationWriteFailure(w, e)
			return
		}
		raw, err = a.Store.controlConfigurationApplicationRequest(ctx, before.vault, id.Username, key, parts[0], parts[1], &expected, before.bootstrap.Central.Instance)
	}
	if err != nil {
		applicationWriteFailure(w, err)
		return
	}
	mutationReply(w, raw, nil)
}

func (a *API) configurationApplicationRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	const prefix = "/api/v3/configuration-applications"
	if r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/") {
		return false
	}
	if id.Role != "admin" {
		applicationReadFailure(w, ErrConfigurationBackupPermission)
		return true
	}
	if r.Method != "GET" {
		if r.Method == "POST" {
			a.configurationApplicationWrite(w, r, id)
		} else {
			failure(w, 405, "method_not_allowed", "请使用 GET")
		}
		return true
	}
	ctx, stop := context.WithTimeout(r.Context(), 10*time.Second)
	defer stop()
	if r.URL.Path == prefix {
		limit, err := pageSize(r, 20)
		if err != nil {
			failure(w, 400, "invalid_limit", "分页数量不正确")
			return true
		}
		cursor, err := decodeRetentionCursor(r.URL.Query().Get("cursor"))
		if err != nil {
			failure(w, 400, "invalid_cursor", "分页游标不正确")
			return true
		}
		stage := r.URL.Query().Get("stage")
		if stage != "" && !validArchiveSource(stage) {
			failure(w, 400, "invalid_stage", "恢复编号不正确")
			return true
		}
		jobs, err := a.Store.configurationApplications(ctx, id.Username, cursor, stage, limit, a.configurationApplicationVault)
		if err != nil {
			applicationReadFailure(w, err)
			return true
		}
		next := ""
		if len(jobs) == limit {
			last := jobs[len(jobs)-1]
			next = (retentionCursor{last.Created, last.ID}).encode()
		}
		reply(w, 200, map[string]any{"items": jobs, "next_cursor": next})
		return true
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix+"/"), "/")
	if len(parts) > 2 || !validArchiveSource(parts[0]) || len(parts) == 2 && parts[1] != "logs" {
		failure(w, 404, "not_found", "接口不存在")
		return true
	}
	v, err := a.configurationApplicationVault()
	if err != nil {
		applicationReadFailure(w, err)
		return true
	}
	if len(parts) == 1 {
		view, err := a.Store.configurationApplicationDetail(ctx, v, id.Username, parts[0], a.bootstrapConfig)
		if err != nil {
			applicationReadFailure(w, err)
		} else {
			reply(w, 200, view)
		}
		return true
	}
	limit, err := pageSize(r, 100)
	if err != nil {
		failure(w, 400, "invalid_limit", "分页数量不正确")
		return true
	}
	after := int64(0)
	if value := r.URL.Query().Get("after"); value != "" {
		after, err = strconv.ParseInt(value, 10, 64)
		if err != nil || after < 0 || strconv.FormatInt(after, 10) != value {
			applicationReadFailure(w, errApplicationCursor)
			return true
		}
	}
	view, logs, err := a.Store.configurationApplicationLogView(ctx, v, id.Username, parts[0], after, limit, a.bootstrapConfig)
	if err != nil {
		applicationReadFailure(w, err)
		return true
	}
	next := after
	if len(logs) > 0 {
		next = logs[len(logs)-1].Cursor
	}
	reply(w, 200, struct {
		configurationApplicationView
		Items []configurationApplicationLog `json:"items"`
		Next  string                        `json:"next_cursor"`
	}{view, logs, strconv.FormatInt(next, 10)})
	return true
}
