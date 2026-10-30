package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var errConfigurationRestoreRequest = errors.New("恢复请求格式不正确，请重新预览并确认操作")

// Explicit per-action, case-sensitive protocol. No paths, document, commands or
// diagnostic reports from the client can become application authority.
func decodeConfigurationRestore(w http.ResponseWriter, r *http.Request, allowed ...string) (map[string]json.RawMessage, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	defer clear(raw)
	if err != nil || !utf8.Valid(raw) || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return nil, errConfigurationRestoreRequest
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if uniqueBackupJSON(d, 0) != nil {
		return nil, errConfigurationRestoreRequest
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(allowed) {
		return nil, errConfigurationRestoreRequest
	}
	for _, name := range allowed {
		v, exists := fields[name]
		if !exists || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, errConfigurationRestoreRequest
		}
	}
	return fields, nil
}
func configurationRestoreString(fields map[string]json.RawMessage, name string) (string, error) {
	var value string
	if json.Unmarshal(fields[name], &value) != nil || !validArchiveSource(value) {
		return "", errConfigurationRestoreRequest
	}
	return value, nil
}
func configurationRestoreConfirmed(fields map[string]json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(fields["confirm"]), []byte("true"))
}

func configurationRestoreFailure(w http.ResponseWriter, err error) {
	var local configurationLocalFailure
	switch {
	case errors.Is(err, errConfigurationRestoreRequest):
		failure(w, 400, "invalid_restore_request", errConfigurationRestoreRequest.Error())
	case errors.Is(err, ErrConfigurationBackupPermission):
		failure(w, 403, "permission_denied", "只有管理员可以管理配置恢复")
	case errors.Is(err, sql.ErrNoRows):
		failure(w, 404, "restore_not_found", "备份或恢复记录不存在")
	case errors.Is(err, errConfigurationRestoreQuota):
		w.Header().Set("Retry-After", "600")
		failure(w, 429, "restore_quota_exceeded", errConfigurationRestoreQuota.Error())
	case errors.Is(err, errConfigurationRestorePending):
		failure(w, 409, "restore_pending", errConfigurationRestorePending.Error())
	case errors.Is(err, ErrDeploymentBusy):
		failure(w, 409, "deployment_busy", "存在未完成部署，请先继续或回退原任务")
	case errors.Is(err, errConfigurationApplicationBusy):
		failure(w, 409, "configuration_application_busy", errConfigurationApplicationBusy.Error())
	case errors.Is(err, errConfigurationApplication):
		failure(w, 503, "configuration_application_unverified", "配置应用状态暂时无法核实，请稍后刷新；未将未知状态标记为成功")
	case errors.Is(err, errConfigurationRestoreBlocked):
		failure(w, 409, "restore_blocked", errConfigurationRestoreBlocked.Error())
	case errors.As(err, &local):
		reply(w, 409, map[string]any{"code": "restore_local_check_failed", "message": "本机资料检查未通过，请重新检查；运行配置未修改", "report": local.Report})
	case errors.Is(err, errConfigurationRestorePreview), errors.Is(err, errConfigurationRevision), errors.Is(err, errConfigurationSaved), errors.Is(err, ErrConflict), errors.Is(err, ErrRequestConflict):
		failure(w, 409, "restore_conflict", errConfigurationRestorePreview.Error())
	case errors.Is(err, ErrMigrationPending):
		failure(w, 503, "migration_pending", ErrMigrationPending.Error())
	case errors.Is(err, errConfigurationBeforeEdit):
		failure(w, 503, "restore_material_unavailable", "恢复密钥或启动快照不可用；请检查资料，仍可取消未完成恢复")
	case errors.Is(err, ErrConfigurationBackupKey):
		failure(w, 503, "backup_key_unavailable", ErrConfigurationBackupKey.Error())
	default:
		failure(w, 503, "restore_unavailable", "恢复操作暂未完成；请保留原幂等键重试并查看恢复记录，运行配置不会自动切换")
	}
}

// Display-only projections. Do not relay arbitrary stored messages or unknown
// summary labels. Continuations always reconstruct authenticated archives.
func publicConfigurationStage(s configurationRestoreStage) (configurationRestoreStage, error) {
	switch s.Status {
	case "pending_validation":
		s.Message = "恢复意图已保存，待本机检查；运行配置未修改"
	case "pending_application":
		s.Message = "恢复候选已准备，尚未提交到保存配置；运行配置未修改"
	case "saved":
		s.Message = "已恢复到保存配置，待应用；运行配置未切换"
	case "cancelled":
		s.Message = "已取消恢复；运行配置未修改"
	default:
		return configurationRestoreStage{}, errConfigurationDocument
	}
	return s, nil
}
func publicConfigurationSummary(s configurationRestoreSummary) (configurationRestoreSummary, error) {
	for _, value := range s.Sections {
		switch value {
		case "retention", "backup", "monitoring", "website_monitor", "email", "feishu", "other":
		default:
			return s, errConfigurationDocument
		}
	}
	for _, value := range s.BlockedReasons {
		switch value {
		case "topology_migration_required", "node_mode_migration_required", "node_uninstall_required", "configuration_incomplete":
		default:
			return s, errConfigurationDocument
		}
	}
	for _, n := range s.Nodes {
		if !identifier.MatchString(n.Node) {
			return s, errConfigurationDocument
		}
		switch n.Action {
		case "add", "update", "remove":
		default:
			return s, errConfigurationDocument
		}
		for _, f := range n.Fields {
			switch f {
			case "configuration", "name", "endpoint", "server_name", "enabled", "mode", "rules", "requires_uninstall":
			default:
				return s, errConfigurationDocument
			}
		}
	}
	for _, n := range s.MissingNodes {
		if !identifier.MatchString(n) {
			return s, errConfigurationDocument
		}
	}
	for _, n := range []int{s.Added, s.Updated, s.Unchanged, s.Removed, s.CredentialsKept, s.CredentialsReplaced, s.CredentialsMissing} {
		if n < 0 {
			return s, errConfigurationDocument
		}
	}
	return s, nil
}

type configurationRestoreDetail struct {
	Stage       configurationRestoreStage   `json:"stage"`
	Summary     configurationRestoreSummary `json:"summary"`
	Revision    *configurationRevision      `json:"revision"`
	CanContinue bool                        `json:"can_continue"`
	CanCancel   bool                        `json:"can_cancel"`
	CanApply    bool                        `json:"can_apply"`
}

func (s *Store) configurationRestores(ctx context.Context, user string, after retentionCursor, limit int, vault configurationApplicationVault) ([]configurationRestoreStage, error) {
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = configurationBackupAdmin(ctx, tx, user); e != nil {
		return nil, e
	}
	stamp := after.Time
	if stamp.IsZero() {
		stamp = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	rows, e := tx.QueryContext(ctx, `SELECT `+configurationStageColumns+` FROM v3_configuration_restore_stages WHERE (created_at,id)<($1,$2) ORDER BY created_at DESC,id DESC LIMIT $3`, stamp, after.ID, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []configurationRestoreStage{}
	for rows.Next() {
		item, e := scanConfigurationStage(rows)
		if e != nil {
			return nil, e
		}
		item, e = publicConfigurationStage(item)
		if e != nil {
			return nil, e
		}
		items = append(items, item)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	rows.Close()
	if e = projectConfigurationApplicationsTx(ctx, tx, items, vault); e != nil {
		return nil, e
	}
	return items, tx.Commit()
}
func (s *Store) configurationRestoreDetail(ctx context.Context, user, id string, vault configurationApplicationVault, allowApply ...bool) (configurationRestoreDetail, error) {
	var out configurationRestoreDetail
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	account, e := configurationRestoreAccount(ctx, tx, user)
	if e != nil {
		return out, e
	}
	var raw []byte
	var ownerRevision int64
	// One MVCC snapshot keeps stage, summary and revision coherent during commit.
	stage, e := scanConfigurationStage(tx.QueryRowContext(ctx, `SELECT `+configurationStageColumns+` FROM v3_configuration_restore_stages WHERE id=$1`, id))
	if e != nil {
		return out, e
	}
	if out.Stage, e = publicConfigurationStage(stage); e != nil {
		return out, e
	}
	if e = tx.QueryRowContext(ctx, `SELECT summary,account_revision FROM v3_configuration_restore_stages WHERE id=$1`, id).Scan(&raw, &ownerRevision); e != nil {
		return out, e
	}
	if json.Unmarshal(raw, &out.Summary) != nil {
		return out, errConfigurationDocument
	}
	if out.Summary, e = publicConfigurationSummary(out.Summary); e != nil {
		return out, e
	}
	revision, e := scanConfigurationRevision(tx.QueryRowContext(ctx, `SELECT `+configurationRevisionColumns+` FROM v3_configuration_revisions WHERE stage=$1`, id))
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	if e == nil {
		switch revision.Status {
		case "pending_application":
			revision.Message = "候选已准备，尚未提交"
		case "saved":
			revision.Message = "已恢复到保存配置，待应用"
		case "cancelled":
			revision.Message = "已取消"
		default:
			return out, errConfigurationDocument
		}
		out.Revision = &revision
	}
	items := []configurationRestoreStage{out.Stage}
	if e = projectConfigurationApplicationsTx(ctx, tx, items, vault); e != nil {
		return out, e
	}
	out.Stage = items[0]
	if out.Revision != nil && out.Stage.Application != nil {
		out.Revision.Message = out.Stage.Message
	}
	out.CanCancel = stage.Status == "pending_validation" || stage.Status == "pending_application"
	out.CanContinue = out.CanCancel && stage.Username == user && ownerRevision == account
	out.CanApply = len(allowApply) > 0 && allowApply[0] && stage.Status == "saved" && stage.Username == user && ownerRevision == account && out.Revision != nil && out.Revision.Status == "saved" && out.Stage.Application == nil
	return out, tx.Commit()
}

// Routed before the archive handler's 20s timeout. All restore operations have
// the same 30s bound as their store transactions; writes never apply runtime.
func (a *API) configurationRestoreRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	const prefix = "/api/v3/configuration-restores"
	preview := strings.HasPrefix(r.URL.Path, "/api/v3/configuration-backups/") && strings.HasSuffix(r.URL.Path, "/restore-preview")
	if !preview && r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/") {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if id.Role != "admin" {
		configurationRestoreFailure(w, ErrConfigurationBackupPermission)
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if !preview && r.Method == "GET" {
		if path == "" {
			limit, e := pageSize(r, 20)
			if e != nil {
				failure(w, 400, "invalid_limit", "分页数量不正确")
				return true
			}
			cursor, e := decodeRetentionCursor(r.URL.Query().Get("cursor"))
			if e != nil {
				failure(w, 400, "invalid_cursor", "分页游标不正确")
				return true
			}
			items, e := a.Store.configurationRestores(ctx, id.Username, cursor, limit, a.configurationApplicationVault)
			if e != nil {
				configurationRestoreFailure(w, e)
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
		stage := strings.TrimPrefix(path, "/")
		if !validArchiveSource(stage) {
			failure(w, 400, "invalid_restore_id", "恢复编号不正确")
			return true
		}
		out, e := a.Store.configurationRestoreDetail(ctx, id.Username, stage, a.configurationApplicationVault, a.applicationWritesEnabled())
		if e != nil {
			configurationRestoreFailure(w, e)
		} else {
			reply(w, 200, out)
		}
		return true
	}
	if r.Method != "POST" {
		failure(w, 405, "method_not_allowed", "请使用规定的恢复接口方法")
		return true
	}
	if !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "配置恢复需要可信 HTTPS 连接")
		return true
	}
	// Cancelling abandoned intent must remain possible when local vault/bootstrap
	// material is unavailable. Cancellation never decrypts or changes settings.
	if !preview && strings.HasSuffix(path, "/cancel") {
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		if len(parts) != 2 || !validArchiveSource(parts[0]) {
			configurationRestoreFailure(w, errConfigurationRestoreRequest)
			return true
		}
		key, ok := mutationKey(w, r)
		if !ok {
			return true
		}
		fields, e := decodeConfigurationRestore(w, r, "confirm")
		if e != nil || !configurationRestoreConfirmed(fields) {
			configurationRestoreFailure(w, errConfigurationRestoreRequest)
			return true
		}
		out, e := a.Store.cancelConfigurationRestore(ctx, id.Username, key, parts[0])
		if e != nil {
			configurationRestoreFailure(w, e)
		} else {
			mutationReply(w, out, nil)
		}
		return true
	}
	before, e := a.configurationEditBackup()
	if e != nil {
		configurationRestoreFailure(w, e)
		return true
	}
	if preview {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v3/configuration-backups/"), "/")
		if len(parts) != 2 || !validArchiveSource(parts[0]) {
			configurationRestoreFailure(w, errConfigurationRestoreRequest)
			return true
		}
		fields, e := decodeConfigurationRestore(w, r, "use_backup_credentials")
		var use bool
		if e != nil || json.Unmarshal(fields["use_backup_credentials"], &use) != nil {
			configurationRestoreFailure(w, errConfigurationRestoreRequest)
			return true
		}
		out, e := a.Store.previewConfigurationRestore(ctx, before.vault, before.bootstrap, id.Username, parts[0], configurationRestoreOptions{UseBackupCredentials: use})
		if e != nil {
			configurationRestoreFailure(w, e)
		} else {
			reply(w, 200, out)
		}
		return true
	}
	key, ok := mutationKey(w, r)
	if !ok {
		return true
	}
	if path == "" {
		fields, e := decodeConfigurationRestore(w, r, "preview", "confirm")
		value, vErr := configurationRestoreString(fields, "preview")
		if e != nil || vErr != nil || !configurationRestoreConfirmed(fields) {
			configurationRestoreFailure(w, errConfigurationRestoreRequest)
			return true
		}
		out, e := a.Store.stageConfigurationRestore(ctx, before.vault, before.bootstrap, id.Username, key, value)
		if e != nil {
			configurationRestoreFailure(w, e)
		} else {
			mutationReply(w, out, nil)
		}
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 2 || !validArchiveSource(parts[0]) {
		configurationRestoreFailure(w, errConfigurationRestoreRequest)
		return true
	}
	stage, action := parts[0], parts[1]
	if action != "check" && action != "prepare" && action != "commit" && action != "cancel" {
		failure(w, 404, "not_found", "恢复接口不存在")
		return true
	}
	allowed := []string{}
	if action == "commit" {
		allowed = []string{"generation", "confirm"}
	}
	if action == "cancel" {
		allowed = []string{"confirm"}
	}
	fields, e := decodeConfigurationRestore(w, r, allowed...)
	if e != nil {
		configurationRestoreFailure(w, e)
		return true
	}
	var out json.RawMessage
	switch action {
	case "check":
		report, e := a.Store.inspectConfigurationRestoreLocal(ctx, before.vault, before.bootstrap, id.Username, stage)
		if e != nil {
			configurationRestoreFailure(w, e)
		} else {
			reply(w, 200, report)
		}
		return true
	case "prepare":
		out, e = a.Store.saveConfigurationRestorePending(ctx, before.vault, before.bootstrap, id.Username, key, stage)
	case "cancel":
		if !configurationRestoreConfirmed(fields) {
			configurationRestoreFailure(w, errConfigurationRestoreRequest)
			return true
		}
		out, e = a.Store.cancelConfigurationRestore(ctx, id.Username, key, stage)
	case "commit":
		var value string
		if json.Unmarshal(fields["generation"], &value) != nil || len(value) > 19 || len(value) < 1 || value[0] == '0' || !configurationRestoreConfirmed(fields) {
			configurationRestoreFailure(w, errConfigurationRestoreRequest)
			return true
		}
		for _, c := range value {
			if c < '0' || c > '9' {
				configurationRestoreFailure(w, errConfigurationRestoreRequest)
				return true
			}
		}
		generation, err := strconv.ParseInt(value, 10, 64)
		if err != nil || generation < 1 {
			configurationRestoreFailure(w, errConfigurationRestoreRequest)
			return true
		}
		out, e = a.Store.commitConfigurationRestoreSaved(ctx, before.vault, before.bootstrap, id.Username, key, stage, generation)
	}
	if e != nil {
		configurationRestoreFailure(w, e)
	} else {
		mutationReply(w, out, nil)
	}
	return true
}
