package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"
)

func (a *API) removeServerRecords(w http.ResponseWriter, r *http.Request, id identity) {
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "需要管理员权限")
		return
	}
	if !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "移除服务器记录需要可信 HTTPS 连接")
		return
	}
	var in struct {
		Records []nodeRemovalRecord `json:"records"`
		Confirm bool                `json:"confirm"`
	}
	if decodeStrictDeployment(w, r, &in, 64<<10, "records", "confirm") != nil {
		failure(w, 400, "invalid_request", errNodeRemovalInput.Error())
		return
	}
	key, ok := mutationKey(w, r)
	if !ok {
		return
	}
	before, err := a.configurationEditBackup()
	if err != nil {
		failure(w, 503, "before_edit_backup_failed", errConfigurationBeforeEdit.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := a.Store.removeNodes(ctx, id.Username, key, in.Records, in.Confirm, before)
	var blocked *nodeRemovalBlocked
	switch {
	case err == nil:
		reply(w, 200, out)
	case errors.Is(err, errNodeRemovalInput):
		failure(w, 400, "invalid_request", err.Error())
	case errors.As(err, &blocked):
		failure(w, 409, "server_removal_protected", blocked.Error())
	case errors.Is(err, ErrConflict), errors.Is(err, ErrRequestConflict):
		failure(w, 409, "config_conflict", err.Error())
	case errors.Is(err, ErrConfigurationBackupPermission):
		failure(w, 403, "permission_denied", "需要管理员权限")
	case errors.Is(err, ErrMigrationPending), errors.Is(err, errConfigurationApplicationBusy):
		failure(w, 409, "configuration_busy", "配置迁移或应用正在进行，请完成原任务后重试")
	case errors.Is(err, errConfigurationBeforeEdit):
		failure(w, 503, "before_edit_backup_failed", errConfigurationBeforeEdit.Error())
	default:
		failure(w, 503, "server_removal_failed", "移除失败，原记录保留，请稍后重试")
	}
}
