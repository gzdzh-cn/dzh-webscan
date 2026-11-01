package controlplane

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"webscan/internal/nodeconfig"
)

type NodeMonitoring struct {
	Source       string          `json:"source"`
	Rules        MonitoringRules `json:"rules"`
	RulesVersion string          `json:"rules_version"`
}

// The public rule object is complete, never a case-insensitive patch. Reject
// nulls and misspelled aliases before Go's JSON field matching can hide them.
func exactMonitoringJSON(raw []byte, into any, names ...string) error {
	if !uniqueProvisioningJSON(json.NewDecoder(bytes.NewReader(raw)), 0) {
		return errMonitoringRules
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(names) {
		return errMonitoringRules
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errMonitoringRules
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil || d.Decode(new(any)) != io.EOF {
		return errMonitoringRules
	}
	return nil
}

func (m *MonitoringRules) UnmarshalJSON(raw []byte) error {
	type fields MonitoringRules
	var value fields
	if exactMonitoringJSON(raw, &value, "roots", "extensions", "important_filenames", "critical_paths", "exclude_paths", "reconciliation_interval_hours") != nil || validateMonitoringRules(MonitoringRules(value)) != nil {
		return errMonitoringRules
	}
	*m = MonitoringRules(value)
	return nil
}

func (m *NodeMonitoring) UnmarshalJSON(raw []byte) error {
	type fields NodeMonitoring
	var value fields
	if exactMonitoringJSON(raw, &value, "source", "rules", "rules_version") != nil || (value.Source != "inherited" && value.Source != "independent") || !canonicalMonitoringVersion(value.RulesVersion) {
		return errMonitoringRules
	}
	*m = NodeMonitoring(value)
	return nil
}

func validateMonitoringPolicy(raw json.RawMessage) error {
	var policy struct {
		Source  string `json:"source"`
		Version string `json:"rules_version"`
	}
	if exactMonitoringJSON(raw, &policy, "source", "rules_version") != nil || (policy.Source != "inherited" && policy.Source != "independent") || !canonicalMonitoringVersion(policy.Version) {
		return errMonitoringRules
	}
	return nil
}

type monitoringRulesView struct {
	Version string          `json:"version"`
	Rules   MonitoringRules `json:"rules"`
}
type monitoringRulesRequest struct {
	Expected string          `json:"expected_version"`
	Rules    MonitoringRules `json:"rules"`
	Preview  string          `json:"preview,omitempty"`
}
type monitoringRulesTicket struct {
	Key     string `json:"key"`
	User    string `json:"user"`
	Account int64  `json:"account"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Expires int64  `json:"expires"`
	Nonce   string `json:"nonce"`
}

func rulesFromMonitor(m nodeconfig.Monitor) MonitoringRules {
	return MonitoringRules{Roots: append([]string{}, m.Roots...), Extensions: append([]string{}, m.Extensions...), ImportantFilenames: append([]string{}, m.ImportantFilenames...), CriticalPaths: append([]string{}, m.CriticalPaths...), ExcludePaths: append([]string{}, m.ExcludePaths...), ReconciliationIntervalHours: m.Reconciliation.IntervalHours}
}

func monitoringRulesFromDraft(d privateSettingsDraft) (monitoringRulesView, error) {
	v := monitoringRulesView{Version: strconv.FormatInt(d.Generation, 10), Rules: defaultMonitoringRules()}
	var root map[string]json.RawMessage
	if json.Unmarshal(d.Desired, &root) != nil {
		return v, errMonitoringRules
	}
	if raw, ok := root["file_monitoring"]; ok {
		if json.Unmarshal(raw, &v.Rules) != nil || validateMonitoringRules(v.Rules) != nil {
			return v, errMonitoringRules
		}
	}
	return v, nil
}

func (s *Store) monitoringRules(ctx context.Context, b *configurationEditBackup, user string) (monitoringRulesView, error) {
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return monitoringRulesView{}, e
	}
	defer tx.Rollback()
	if e = configurationBackupAdmin(ctx, tx, user); e != nil {
		return monitoringRulesView{}, e
	}
	d, e := readSettingsDraftTx(ctx, tx, false)
	if e != nil {
		return monitoringRulesView{}, e
	}
	if b == nil || checkSettingsDraftProof(b.vault, d) != nil {
		return monitoringRulesView{}, errConfigurationBeforeEdit
	}
	v, e := monitoringRulesFromDraft(d)
	if e != nil {
		return v, e
	}
	return v, tx.Commit()
}

func monitoringMAC(v *Vault, key string, raw []byte) string {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/monitoring-rules-preview/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func newMonitoringPreview(v *Vault, user string, account int64, in monitoringRulesRequest) (string, time.Time, error) {
	if v == nil {
		return "", time.Time{}, errConfigurationBeforeEdit
	}
	raw, _ := json.Marshal(in.Rules)
	expiry := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	t := monitoringRulesTicket{v.active, user, account, in.Expected, digest(raw), expiry.Unix(), token()}
	body, e := json.Marshal(t)
	if e != nil {
		return "", expiry, e
	}
	proof := monitoringMAC(v, t.Key, body)
	if proof == "" {
		return "", expiry, errConfigurationBeforeEdit
	}
	return base64.RawURLEncoding.EncodeToString(body) + "." + proof, expiry, nil
}
func checkMonitoringPreview(v *Vault, user string, account int64, in monitoringRulesRequest) error {
	parts := strings.Split(in.Preview, ".")
	if len(parts) != 2 || len(in.Preview) > 2048 {
		return errMonitoringRules
	}
	body, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return errMonitoringRules
	}
	var t monitoringRulesTicket
	if json.Unmarshal(body, &t) != nil {
		return errMonitoringRules
	}
	proof := monitoringMAC(v, t.Key, body)
	raw, _ := json.Marshal(in.Rules)
	if proof == "" || subtle.ConstantTimeCompare([]byte(proof), []byte(parts[1])) != 1 || t.User != user || t.Account != account || t.Version != in.Expected || t.Digest != digest(raw) || t.Expires <= time.Now().Unix() || t.Expires > time.Now().Add(10*time.Minute).Unix() {
		return errMonitoringRules
	}
	return nil
}

func (s *Store) saveMonitoringRules(ctx context.Context, b *configurationEditBackup, user, key string, in monitoringRulesRequest) (json.RawMessage, error) {
	if validateMonitoringRules(in.Rules) != nil {
		return nil, errMonitoringRules
	}
	return s.guardedMutation(ctx, user, key, "monitoring-rules-save", "monitoring", in, func(tx *sql.Tx) error { return b.lock(ctx, tx, user) }, func(tx *sql.Tx) (any, error) {
		d, e := readSettingsDraftTx(ctx, tx, true)
		if e != nil {
			return nil, e
		}
		if b == nil || checkSettingsDraftProof(b.vault, d) != nil {
			return nil, errConfigurationBeforeEdit
		}
		current, e := monitoringRulesFromDraft(d)
		if e != nil {
			return nil, e
		}
		if current.Version != in.Expected {
			return nil, ErrConflict
		}
		account, e := deploymentPreviewAccount(ctx, tx, user)
		if e != nil {
			return nil, e
		}
		if e = checkMonitoringPreview(b.vault, user, account, in); e != nil {
			return nil, e
		}
		if e = b.capture(ctx, tx, user, "monitoring-rules-save", "monitoring"); e != nil {
			return nil, e
		}
		var root map[string]json.RawMessage
		if json.Unmarshal(d.Desired, &root) != nil {
			return nil, errMonitoringRules
		}
		root["file_monitoring"], _ = json.Marshal(in.Rules)
		raw, _ := json.Marshal(root)
		if validateSettingsDraft(b.bootstrap, raw) != nil {
			return nil, errMonitoringRules
		}
		state, e := putSettingsDraftTx(ctx, tx, b.vault, raw, d.RuntimeVersion, d.Runtime)
		if e != nil {
			return nil, e
		}
		return monitoringRulesView{strconv.FormatInt(state.Generation, 10), in.Rules}, nil
	})
}

// Saving rules changes only saved intent. Each node keeps its own immutable
// effective monitor until an explicit, verified deployment applies that version.
func monitoringForNode(n Node) *NodeMonitoring {
	settings, e := nodeRuntimeSettings(n.Config)
	if e != nil {
		return nil
	}
	out := &NodeMonitoring{Source: "independent", Rules: rulesFromMonitor(settings.Monitor), RulesVersion: "0"}
	var root map[string]json.RawMessage
	var policy struct {
		Source  string `json:"source"`
		Version string `json:"rules_version"`
	}
	if json.Unmarshal(n.Config, &root) == nil && root["monitoring_policy"] != nil {
		if validateMonitoringPolicy(root["monitoring_policy"]) != nil || json.Unmarshal(root["monitoring_policy"], &policy) != nil {
			return nil
		}
		out.Source, out.RulesVersion = policy.Source, policy.Version
	}
	return out
}

func prepareMonitoringNodeTx(ctx context.Context, tx *sql.Tx, n *Node, expected int64, v *Vault) error {
	requested := n.Monitoring
	if requested == nil && expected > 0 {
		return nil
	}
	var raw json.RawMessage
	if expected > 0 {
		if e := tx.QueryRowContext(ctx, "SELECT config FROM v3_nodes WHERE id=$1 AND version=$2 AND removed_at IS NULL", n.ID, expected).Scan(&raw); e != nil {
			return e
		}
	} else {
		raw = n.Config
		if len(raw) == 0 {
			raw = json.RawMessage(`{}`)
		}
	}
	settings, e := nodeRuntimeSettings(raw)
	if e != nil {
		return errMonitoringRules
	}
	if requested == nil {
		requested = &NodeMonitoring{Source: "inherited"}
	}
	if requested.Source != "inherited" && requested.Source != "independent" {
		return errMonitoringRules
	}
	rules := requested.Rules
	version := requested.RulesVersion
	if requested.Source == "independent" && !canonicalMonitoringVersion(version) {
		return errMonitoringRules
	}
	if requested.Source == "inherited" {
		d, e := readSettingsDraftTx(ctx, tx, false)
		if e != nil {
			return e
		}
		if checkSettingsDraftProof(v, d) != nil {
			return errConfigurationBeforeEdit
		}
		global, e := monitoringRulesFromDraft(d)
		if e != nil {
			return e
		}
		if version != "" && version != global.Version {
			return ErrConflict
		}
		rules, version = global.Rules, global.Version
	}
	monitor, e := monitorWithRules(settings.Monitor, rules)
	if e != nil {
		return e
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil {
		return errMonitoringRules
	}
	root["monitor"], _ = json.Marshal(monitor)
	root["monitoring_policy"], _ = json.Marshal(map[string]string{"source": requested.Source, "rules_version": version})
	// Probe paths derived from the previous first root follow a roots change;
	// explicitly configured custom paths remain subject to the full validator.
	if len(settings.Monitor.Roots) > 0 && settings.ProbeDirectory == strings.TrimRight(settings.Monitor.Roots[0], "/")+"/.webscan-probe" {
		delete(root, "probe_directory")
	}
	updated, _ := json.Marshal(root)
	if _, e = nodeRuntimeSettings(updated); e != nil {
		return errMonitoringRules
	}
	n.Config = updated
	return nil
}

func (a *API) monitoringRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	if r.URL.Path != "/api/v3/monitoring/rules" && r.URL.Path != "/api/v3/monitoring/rules/preview" {
		return false
	}
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "需要管理员权限")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	b, e := a.configurationEditBackup()
	if e != nil {
		failure(w, 503, "monitoring_unavailable", errConfigurationBeforeEdit.Error())
		return true
	}
	if r.Method == "GET" && r.URL.Path == "/api/v3/monitoring/rules" {
		view, e := a.Store.monitoringRules(ctx, b, id.Username)
		if e != nil {
			monitoringFailure(w, e)
		} else {
			reply(w, 200, view)
		}
		return true
	}
	preview := r.URL.Path == "/api/v3/monitoring/rules/preview"
	if preview && r.Method != "POST" || !preview && r.Method != "PUT" {
		failure(w, 405, "method_not_allowed", "请使用规则读取、预览或保存方法")
		return true
	}
	if !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "监控配置需要可信 HTTPS 连接")
		return true
	}
	var in monitoringRulesRequest
	if decodeStrictDeployment(w, r, &in, 128<<10, "expected_version", "rules", "preview") != nil || validateMonitoringRules(in.Rules) != nil || !canonicalMonitoringVersion(in.Expected) {
		failure(w, 400, "invalid_monitoring_rules", "监控规则或配置版本不正确")
		return true
	}
	if preview {
		tx, e := a.Store.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if e != nil {
			monitoringFailure(w, e)
			return true
		}
		defer tx.Rollback()
		d, e := readSettingsDraftTx(ctx, tx, false)
		if e != nil {
			monitoringFailure(w, e)
			return true
		}
		if checkSettingsDraftProof(b.vault, d) != nil {
			monitoringFailure(w, errConfigurationBeforeEdit)
			return true
		}
		current, e := monitoringRulesFromDraft(d)
		if e != nil || current.Version != in.Expected {
			monitoringFailure(w, ErrConflict)
			return true
		}
		account, e := deploymentPreviewAccount(ctx, tx, id.Username)
		if e != nil {
			monitoringFailure(w, e)
			return true
		}
		proof, expiry, e := newMonitoringPreview(b.vault, id.Username, account, in)
		if e != nil {
			monitoringFailure(w, e)
			return true
		}
		changes := []string{}
		left, right := reflect.ValueOf(current.Rules), reflect.ValueOf(in.Rules)
		typ := left.Type()
		for i := 0; i < left.NumField(); i++ {
			if !reflect.DeepEqual(left.Field(i).Interface(), right.Field(i).Interface()) {
				changes = append(changes, typ.Field(i).Tag.Get("json"))
			}
		}
		reply(w, 200, map[string]any{"token": proof, "expires_at": expiry, "changed_fields": changes})
		return true
	}
	if !identifier.MatchString(r.Header.Get("Idempotency-Key")) {
		failure(w, 400, "invalid_idempotency_key", "请提供有效幂等键")
		return true
	}
	raw, e := a.Store.saveMonitoringRules(ctx, b, id.Username, r.Header.Get("Idempotency-Key"), in)
	if e != nil {
		monitoringFailure(w, e)
	} else {
		reply(w, 200, raw)
	}
	return true
}
func canonicalMonitoringVersion(s string) bool {
	n, e := strconv.ParseInt(s, 10, 64)
	return e == nil && n >= 0 && strconv.FormatInt(n, 10) == s
}

// A full configuration restore may replace any node in its saved document.
// Keep it separate from narrow rule applications instead of allowing two
// independent recovery journals to own the same remote service.
func monitoringApplicationsAvailableTx(ctx context.Context, tx *sql.Tx) error {
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_monitoring_application_nodes WHERE reserved)`).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return ErrDeploymentBusy
	}
	return nil
}

func monitoringFailure(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, ErrConfigurationBackupPermission):
		failure(w, 403, "permission_denied", "需要管理员权限")
	case errors.Is(e, ErrDeploymentBusy):
		failure(w, 409, "deployment_pending", "所选节点已有未完成操作，请继续或回退原任务")
	case errors.Is(e, ErrCredentialUnavailable):
		failure(w, 409, "credential_unavailable", "SSH 凭据不可用或已变化，请重新保存凭据并预览")
	case errors.Is(e, ErrDeploymentModeMigration):
		failure(w, 409, "deployment_target_mismatch", "所选节点的运行方式或版本与当前部署物料不一致，请先完成升级")
	case errors.Is(e, ErrDeploymentPreview), errors.Is(e, errMonitoringApplication):
		failure(w, 409, "monitoring_preview_expired", "规则应用预览、账号或节点状态已变化，请重新读取并预览")
	case errors.Is(e, ErrConflict), errors.Is(e, ErrRequestConflict), errors.Is(e, errMonitoringRules):
		failure(w, 409, "monitoring_conflict", errMonitoringRules.Error())
	case errors.Is(e, ErrMigrationPending):
		failure(w, 503, "migration_pending", ErrMigrationPending.Error())
	default:
		failure(w, 503, "monitoring_unavailable", "监控配置暂不可用，原配置未修改，请保留输入后重试")
	}
}
