package controlplane

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"
)

type metricsRetentionView struct {
	Configured bool                    `json:"configured"`
	Available  bool                    `json:"available"`
	Reason     string                  `json:"reason"`
	Status     *MetricsRetentionStatus `json:"status,omitempty"`
}

func metricsRetentionFields() []settingsField {
	return []settingsField{{Path: "monitoring.raw_hours", Label: "原始指标保留（小时）", Kind: "integer", Min: 24, Max: 168}, {Path: "monitoring.history_days", Label: "长期指标历史保留（天）", Kind: "integer", Min: 1, Max: 90}}
}

// The API verifies its read-only policy using the shared Vault. It never reads
// the host's mutable journal, CA, Docker socket or private executor files.
func readMetricsRetentionView(ctx context.Context, tx *sql.Tx, c Config, v *Vault) (metricsRetentionView, error) {
	out := metricsRetentionView{Configured: c.Metrics.PolicyFile != "", Reason: "尚未配置独立双层指标维护；现有时序库保留方式不变"}
	if !out.Configured {
		return out, nil
	}
	out.Reason = "指标保留维护尚未提供有效运行证据，请检查宿主服务"
	var p MetricsRetentionSpec
	raw, err := readTrustData(c.Metrics.PolicyFile, true, 64<<10)
	if err != nil || singleDecode(raw, &p) != nil || validateMetricsRetentionSpec(p) != nil || v == nil || p.Instance != c.Central.Instance || c.Metrics.RawURL == "" || c.Metrics.PolicyFile != filepath.Join(filepath.Dir(c.Metrics.PolicyFile), "policy.json") {
		return out, nil
	}
	proof := p.Proof
	p.Proof = ""
	expected, err := metricsRetentionMAC(v, p.KeyID, "spec", p)
	p.Proof = proof
	if err != nil || !hmac.Equal([]byte(expected), []byte(proof)) {
		return out, nil
	}
	policy, _ := json.Marshal(p)
	var details []byte
	var heartbeat time.Time
	var failure string
	if err := tx.QueryRowContext(ctx, `SELECT heartbeat,error,details FROM v3_role_status WHERE role='metrics-retention' AND instance=$1`, p.Instance).Scan(&heartbeat, &failure, &details); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return out, nil
		}
		return out, err
	}
	age := time.Since(heartbeat)
	var status MetricsRetentionStatus
	if age < -5*time.Second || age > 2*time.Minute || len(details) > 64<<10 || json.Unmarshal(details, &status) != nil || status.PolicySHA256 != digest(policy) {
		return out, nil
	}
	for _, target := range []*metricsRetentionTarget{status.Desired, status.Effective} {
		if target != nil && (target.RawHours < 24 || target.RawHours > 168 || target.HistoryDays < 1 || target.HistoryDays > 90 || target.Version < 1) {
			return out, nil
		}
	}
	if status.State != "confirmed" && status.State != "failed" && status.State != "unknown" {
		return out, nil
	}
	// A live coordinator may be failing on a legacy unsupported value. Allow
	// correcting the desired policy, but keep its engine state explicitly failed.
	out.Available, out.Reason, out.Status = true, "", &status
	if failure != "" || status.State != "confirmed" || status.Effective == nil {
		out.Reason = "维护任务尚未确认实际保留期限；修改后仍需等待备份和引擎核验"
	}
	return out, nil
}

func hasMetricsRetentionChange(changed []string) bool {
	for _, path := range changed {
		if path == "monitoring.raw_hours" || path == "monitoring.history_days" {
			return true
		}
	}
	return false
}

func (a *API) metricsRetentionAvailability(ctx context.Context) metricsRetentionView {
	c := a.Config
	if a.bootstrapConfig != nil {
		c = *a.bootstrapConfig
	}
	out := metricsRetentionView{Configured: c.Metrics.PolicyFile != "", Reason: "指标保留维护运行证据暂不可用"}
	v, err := OpenVault(a.Config.DeploymentTrust.VaultKeyFile, a.Config.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return out
	}
	tx, err := a.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return out
	}
	defer tx.Rollback()
	view, err := readMetricsRetentionView(ctx, tx, c, v)
	if err != nil {
		return out
	}
	return view
}
