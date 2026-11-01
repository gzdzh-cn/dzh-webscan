package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

func metricsPolicyViewFixture(t *testing.T, a *API) (MetricsRetentionSpec, *Vault, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(root, "single")
	p := MetricsRetentionSpec{Format: 1, Instance: a.bootstrapConfig.Central.Instance, Root: install, InstallationFile: filepath.Join(install, "install.json"), InstallationSHA256: strings.Repeat("a", 64), HostConfigFile: filepath.Join(install, "executor.yaml"), HostConfigSHA256: strings.Repeat("b", 64), ComposeFile: filepath.Join(install, "compose.yaml"), ComposeSHA256: strings.Repeat("c", 64), HelperFile: filepath.Join(install, "webscan"), HelperSHA256: strings.Repeat("d", 64), StateDirectory: install + "-state", BackupDirectory: install + "-backups"}
	p.BackupRequest = singleBackupSpec{Format: 1, Installation: p.InstallationFile, HostConfig: p.HostConfigFile, APIConfig: filepath.Join(install, "config.yaml"), ComposeFile: p.ComposeFile, RecoveryDirectories: []string{p.StateDirectory}}
	v, err := OpenVault(a.Config.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	p.KeyID = v.active
	p.Proof, err = metricsRetentionMAC(v, p.KeyID, "spec", p)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	path := filepath.Join(root, "policy.json")
	localWrite(t, path, raw)
	a.Config.Metrics.RawURL = "http://127.0.0.1:29999"
	a.Config.Metrics.PolicyFile = path
	c := *a.bootstrapConfig
	c.Metrics = a.Config.Metrics
	a.bootstrapConfig = &c
	return p, v, digest(raw)
}

func putMetricsPolicyHeartbeat(t *testing.T, a *API, hash string, at time.Time, state string) {
	t.Helper()
	details := MetricsRetentionStatus{State: state, PolicySHA256: hash, Observed: at, Effective: &metricsRetentionTarget{RawHours: 48, HistoryDays: 15, Version: 1}}
	mustHistoryExec(t, a.Store.DB, `INSERT INTO v3_role_status(role,instance,heartbeat,error,details) VALUES('metrics-retention',$1,$2,'',$3) ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,details=excluded.details`, a.bootstrapConfig.Central.Instance, at, common.JSON(details))
}

func TestMetricsRetentionViewRequiresAuthenticatedFreshActualPolicy(t *testing.T) {
	a, _, _ := configurationAPIFixture(t)
	p, _, hash := metricsPolicyViewFixture(t, a)
	check := func(available bool) metricsRetentionView {
		t.Helper()
		r := a.metricsRetentionAvailability(context.Background())
		if r.Available != available {
			t.Fatalf("availability mismatch: %#v", r)
		}
		return r
	}
	check(false)
	putMetricsPolicyHeartbeat(t, a, strings.Repeat("f", 64), time.Now(), "confirmed")
	check(false)
	putMetricsPolicyHeartbeat(t, a, hash, time.Now().Add(-3*time.Minute), "confirmed")
	if check(false).Status != nil {
		t.Fatal("stale engine shown")
	}
	putMetricsPolicyHeartbeat(t, a, hash, time.Now().Add(time.Minute), "confirmed")
	check(false)
	putMetricsPolicyHeartbeat(t, a, hash, time.Now(), "confirmed")
	if check(true).Status.Effective.RawHours != 48 {
		t.Fatal("invented engine policy")
	}
	putMetricsPolicyHeartbeat(t, a, hash, time.Now(), "failed")
	if check(true).Reason == "" {
		t.Fatal("failure hidden")
	}
	p.Proof = strings.Repeat("0", 64)
	raw, _ := json.Marshal(p)
	localWrite(t, a.Config.Metrics.PolicyFile, raw)
	check(false)
}

func TestMetricsRetentionSettingsSaveApplyDoesNotClaimEngineConfirmed(t *testing.T) {
	a, _, sessions := configurationAPIFixture(t)
	_, _, hash := metricsPolicyViewFixture(t, a)
	in := editorRequestForTest(t, a.Store, "save", settingsEdit{Values: map[string]json.RawMessage{"monitoring.raw_hours": json.RawMessage(`36`), "monitoring.history_days": json.RawMessage(`7`)}})
	w := settingsEditorAPICall(a, "POST", "/preview", common.JSON(in), sessions["admin"], "", true)
	if w.Code != 503 || tableCount(t, a.Store, "v3_configuration_backups") != 0 {
		t.Fatal("unobserved coordinator accepted edit", w.Code)
	}
	putMetricsPolicyHeartbeat(t, a, hash, time.Now(), "confirmed")
	in = editorPreviewForTest(t, a, sessions["admin"], in)
	w = settingsEditorAPICall(a, "POST", "/confirm", common.JSON(in), sessions["admin"], "metrics-save", true)
	if w.Code != 200 {
		t.Fatal("save failed", w.Code, w.Body.String())
	}
	var runtime []byte
	if err := a.Store.DB.QueryRow(`SELECT payload FROM v3_settings WHERE id=1`).Scan(&runtime); err != nil || strings.Contains(string(runtime), "raw_hours") {
		t.Fatal("save applied policy", err)
	}
	apply := editorRequestForTest(t, a.Store, "apply", settingsEdit{})
	apply = editorPreviewForTest(t, a, sessions["admin"], apply)
	w = settingsEditorAPICall(a, "POST", "/confirm", common.JSON(apply), sessions["admin"], "metrics-apply", true)
	if w.Code != 200 {
		t.Fatal("apply failed", w.Code, w.Body.String())
	}
	w = settingsEditorAPICall(a, "GET", "", nil, sessions["admin"], "", true)
	var out settingsEditorView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.MetricsRetention.Status == nil {
		t.Fatal("read failed", w.Code)
	}
	if out.MetricsRetention.Status.Effective.RawHours != 48 || common.I(out.RuntimeValues["monitoring.raw_hours"]) != 36 {
		t.Fatal("desired values impersonated actual engine")
	}
	for _, field := range out.Fields {
		if field.Path == "monitoring.raw_hours" && field.Min != 24 {
			t.Fatal("sub-day engine retention exposed")
		}
	}
	if strings.Contains(w.Body.String(), "executor.yaml") || strings.Contains(w.Body.String(), "backups") || strings.Contains(w.Body.String(), "key_id") {
		t.Fatal("private bindings leaked")
	}
}
