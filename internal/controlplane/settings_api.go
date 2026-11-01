package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// Settings bodies can contain notification credentials. Decode only bounded
// memory, reject duplicate keys before typed decoding, and never echo input.
func decodeSettingsEditor(w http.ResponseWriter, r *http.Request) (settingsEditorRequest, error) {
	var in settingsEditorRequest
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	defer clear(raw)
	if e != nil || len(raw) == 0 || !utf8.Valid(raw) || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return in, errSettingsEdit
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	check.UseNumber()
	if uniqueBackupJSON(check, 0) != nil {
		return in, errSettingsEdit
	}
	var required map[string]json.RawMessage
	if json.Unmarshal(raw, &required) != nil {
		return in, errSettingsEdit
	}
	// encoding/json matches struct names case-insensitively. Enforce exact
	// protocol keys before typed decoding so aliases cannot override a field.
	for name := range required {
		if name != "action" && name != "expected_generation" && name != "expected_runtime_version" && name != "edit" && name != "preview" {
			return in, errSettingsEdit
		}
	}

	for _, name := range []string{"action", "expected_generation", "expected_runtime_version", "edit"} {
		v := bytes.TrimSpace(required[name])
		if len(v) == 0 || bytes.Equal(v, []byte("null")) {
			return in, errSettingsEdit
		}
	}
	var generation string
	if json.Unmarshal(required["expected_generation"], &generation) != nil || generation == "" || (len(generation) > 1 && generation[0] == '0') {
		return in, errSettingsEdit
	}
	for _, c := range generation {
		if c < '0' || c > '9' {
			return in, errSettingsEdit
		}
	}
	var edit map[string]json.RawMessage
	if !bytes.HasPrefix(bytes.TrimSpace(required["edit"]), []byte("{")) || json.Unmarshal(required["edit"], &edit) != nil {
		return in, errSettingsEdit
	}
	for name := range edit {
		if name != "values" && name != "secrets" {
			return in, errSettingsEdit
		}
	}
	if rawSecrets, ok := edit["secrets"]; ok {
		var secrets map[string]json.RawMessage
		if json.Unmarshal(rawSecrets, &secrets) != nil {
			return in, errSettingsEdit
		}
		for _, rawSecret := range secrets {
			var secret map[string]json.RawMessage
			if !bytes.HasPrefix(bytes.TrimSpace(rawSecret), []byte("{")) || json.Unmarshal(rawSecret, &secret) != nil {
				return in, errSettingsEdit
			}
			for name := range secret {
				if name != "action" && name != "value" {
					return in, errSettingsEdit
				}
			}
		}
	}
	for _, name := range []string{"values", "secrets"} {
		if v, ok := edit[name]; ok && !bytes.HasPrefix(bytes.TrimSpace(v), []byte("{")) {
			return in, errSettingsEdit
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
		return settingsEditorRequest{}, errSettingsEdit
	}
	return in, nil
}

func settingsEditorFailure(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, errMetricsRetentionRuntime):
		failure(w, 503, "metrics_retention_unavailable", errMetricsRetentionRuntime.Error())
	case errors.Is(e, errSettingsEdit):
		failure(w, 400, "invalid_settings", errSettingsEdit.Error())
	case errors.Is(e, ErrConfigurationBackupPermission):
		failure(w, 403, "permission_denied", "只有管理员可以管理运行设置")
	case errors.Is(e, errSettingsPreview) || errors.Is(e, errSettingsDraft) || errors.Is(e, ErrConflict) || errors.Is(e, ErrRequestConflict):
		failure(w, 409, "settings_conflict", errSettingsPreview.Error())
	case errors.Is(e, ErrDeploymentBusy):
		failure(w, 409, "deployment_busy", "存在未完成部署，请先继续或回退原任务")
	case errors.Is(e, errConfigurationApplicationBusy):
		failure(w, 409, "configuration_application_busy", errConfigurationApplicationBusy.Error())
	case errors.Is(e, ErrMigrationPending):
		failure(w, 503, "migration_pending", ErrMigrationPending.Error())
	case errors.Is(e, errConfigurationBeforeEdit) || errors.Is(e, ErrConfigurationBackupKey):
		failure(w, 503, "before_edit_backup_failed", errConfigurationBeforeEdit.Error())
	default:
		failure(w, 503, "settings_unavailable", "设置操作暂未完成，请保留输入并重试")
	}
}

func (a *API) settingsRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	const prefix = "/api/v3/settings"
	if r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/") {
		return false
	}
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "只有管理员可以管理运行设置")
		return true
	}
	read := r.URL.Path == prefix
	if read && r.Method != "GET" || !read && r.Method != "POST" {
		failure(w, 405, "method_not_allowed", "请使用规定的设置接口方法")
		return true
	}
	if !read && r.URL.Path != prefix+"/preview" && r.URL.Path != prefix+"/confirm" {
		failure(w, 404, "not_found", "接口不存在")
		return true
	}
	if !read && !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "设置预览和保存需要可信 HTTPS 连接")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	before, e := a.configurationEditBackup()
	if e == nil {
		e = a.Store.vaultAvailable(ctx, before.vault)
	}
	if e != nil {
		settingsEditorFailure(w, errConfigurationBeforeEdit)
		return true
	}
	if read {
		v, e := a.Store.settingsEditor(ctx, id.Username, before)
		if e != nil {
			settingsEditorFailure(w, e)
		} else {
			reply(w, 200, v)
		}
		return true
	}
	in, e := decodeSettingsEditor(w, r)
	if e != nil {
		settingsEditorFailure(w, e)
		return true
	}
	if r.URL.Path == prefix+"/preview" {
		v, e := a.Store.previewSettingsEditor(ctx, id.Username, in, before)
		if e != nil {
			settingsEditorFailure(w, e)
		} else {
			reply(w, 200, v)
		}
		return true
	}
	if !identifier.MatchString(r.Header.Get("Idempotency-Key")) {
		failure(w, 400, "invalid_idempotency_key", "请提供有效幂等键")
		return true
	}
	v, e := a.Store.confirmSettingsEditor(ctx, id.Username, r.Header.Get("Idempotency-Key"), in, before)
	if e != nil {
		settingsEditorFailure(w, e)
	} else {
		reply(w, 200, v)
	}
	return true
}
