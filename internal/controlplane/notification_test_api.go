package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

func (a *API) notificationTestAvailability(ctx context.Context) featureAvailability {
	unavailable := featureAvailability{Reason: "通知测试工作器或共享 Vault 密钥未就绪"}
	v, err := OpenVault(a.Config.DeploymentTrust.VaultKeyFile, a.Config.DeploymentTrust.PreviousKeyFiles...)
	if err != nil || a.Store.vaultAvailable(ctx, v) != nil {
		return unavailable
	}
	var ready bool
	err = a.Store.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_role_status WHERE role='notification-tests' AND heartbeat>clock_timestamp()-interval '30 seconds' AND error='' AND details->>'vault_key_id'=$1)`, v.active).Scan(&ready)
	if err != nil || !ready {
		return unavailable
	}
	return featureAvailability{Available: true}
}
func notificationTestFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNotificationTestInput):
		failure(w, 400, "invalid_request", errNotificationTestInput.Error())
	case errors.Is(err, sql.ErrNoRows):
		failure(w, 404, "not_found", "测试任务不存在或不属于当前账号")
	case errors.Is(err, ErrDeploymentPreview):
		failure(w, 403, "permission_denied", "需要有效管理员权限")
	case errors.Is(err, errNotificationTestRate), errors.Is(err, errNotificationTestQuota):
		failure(w, 429, "notification_test_rate", err.Error())
	case errors.Is(err, errNotificationTestPreview), errors.Is(err, ErrRequestConflict), errors.Is(err, ErrMigrationPending), errors.Is(err, ErrConflict):
		failure(w, 409, "notification_test_conflict", "测试预览或实际配置已变化，请重新预览")
	default:
		failure(w, 503, "notification_test_unavailable", errNotificationTestUnavailable.Error())
	}
}

// Authentication and CSRF are enforced by the shared API router first.
func (a *API) notificationTestRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	const base = "/api/v3/notifications/"
	if !strings.HasPrefix(r.URL.Path, base) {
		return false
	}
	path := strings.TrimPrefix(r.URL.Path, base)
	if path != "test-preview" && path != "tests" && !strings.HasPrefix(path, "tests/") {
		return false
	}
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "需要管理员权限")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if strings.HasPrefix(path, "tests/") {
		jobID := strings.TrimPrefix(path, "tests/")
		if r.Method != http.MethodGet {
			failure(w, 405, "method_not_allowed", "请使用GET查询测试任务")
			return true
		}
		if !identifier.MatchString(jobID) {
			failure(w, 404, "not_found", "测试任务不存在")
			return true
		}
		job, err := a.Store.notificationTestJob(ctx, id.Username, jobID)
		if err != nil {
			notificationTestFailure(w, err)
		} else {
			reply(w, 200, job)
		}
		return true
	}
	if r.Method != http.MethodPost {
		failure(w, 405, "method_not_allowed", "请使用POST预览或创建测试任务")
		return true
	}
	if !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "通知测试需要可信HTTPS连接")
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if !identifier.MatchString(key) {
		failure(w, 400, "invalid_idempotency_key", "请提供有效幂等键")
		return true
	}
	if ready := a.notificationTestAvailability(ctx); !ready.Available {
		notificationTestFailure(w, errNotificationTestUnavailable)
		return true
	}
	v, err := OpenVault(a.Config.DeploymentTrust.VaultKeyFile, a.Config.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		notificationTestFailure(w, errNotificationTestUnavailable)
		return true
	}
	if path == "test-preview" {
		var in struct {
			Channel string `json:"channel"`
			Runtime int64  `json:"expected_runtime_version"`
		}
		if decodeStrictDeployment(w, r, &in, 16384, "channel", "expected_runtime_version") != nil {
			notificationTestFailure(w, errNotificationTestInput)
			return true
		}
		out, err := a.Store.previewNotificationTest(ctx, v, id.Username, key, in.Channel, in.Runtime)
		if err != nil {
			notificationTestFailure(w, err)
		} else {
			reply(w, 200, out)
		}
		return true
	}
	var in struct {
		Preview string `json:"preview"`
		Confirm bool   `json:"confirm"`
	}
	if decodeStrictDeployment(w, r, &in, 16384, "preview", "confirm") != nil {
		notificationTestFailure(w, errNotificationTestInput)
		return true
	}
	out, err := a.Store.submitNotificationTest(ctx, v, id.Username, key, in.Preview, in.Confirm)
	if err != nil {
		notificationTestFailure(w, err)
	} else {
		reply(w, http.StatusAccepted, out)
	}
	return true
}
