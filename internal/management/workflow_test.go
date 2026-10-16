package management

import (
	"bytes"
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
)

func TestRecoveryPreviewBindsOwnerRunAndRevision(t *testing.T) {
	s := managerFixture(t)
	state := common.Map{"step": "installing", "run_id": "one", "target_node": "node-202", "target_add_node": true, "management_job": "job-one", "target_release": "v2.0.39"}
	if err := common.AtomicJSON(filepath.Join(s.StateDir, "state.json"), state); err != nil {
		t.Fatal(err)
	}
	_, err := s.DB.Exec("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)", "job-one", "key", "add-node", "node-202", "failed", 1, 1, revision(t, s), "failed")
	if err != nil {
		t.Fatal(err)
	}
	code, p := request(t, s, "POST", "/jobs/job-one/recovery-preview", common.Map{"kind": "resume"})
	if code != 200 {
		t.Fatal(code, p)
	}
	in := Start{Kind: "resume", OriginalJob: "job-one", RecoveryToken: common.S(p["token"]), Revision: revision(t, s)}
	req := httptest.NewRequest("POST", "/jobs", nil)
	if err = s.checkRecovery(req, &in, state); err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Webscan-Owner", "other")
	if err = s.checkRecovery(req, &in, state); err == nil {
		t.Fatal("cross-account preview accepted")
	}
	req.Header.Del("X-Webscan-Owner")
	state["run_id"] = "two"
	common.AtomicJSON(filepath.Join(s.StateDir, "state.json"), state)
	if err = s.checkRecovery(req, &in, state); err == nil {
		t.Fatal("changed run accepted")
	}
	state["step"] = "complete"
	common.AtomicJSON(filepath.Join(s.StateDir, "state.json"), state)
	if common.B(s.recoveryStatus()["can_resume"]) {
		t.Fatal("completed task recoverable")
	}
}
func TestWorkflowProgressAndDownloadArePersisted(t *testing.T) {
	s := managerFixture(t)
	s.DB.Exec("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)", "job", "key", "apply", "", "failed", 1, 1, "rev", "")
	writer := logWriter{s: s, id: "job", secrets: []string{"secret-value"}}
	_, err := writer.Write([]byte("@webscan-progress " + string(common.JSON(common.Map{"step": 2, "phase": "部署", "host": "node", "title": "环境检查", "status": "失败", "message": "secret-value", "time": time.Now().Unix()})) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	stages := s.jobStages("job")
	if len(stages) != 1 || common.S(stages[0]["message"]) != "[已隐藏]" {
		t.Fatal(stages)
	}
	writer.Write([]byte("failed secret-value\n"))
	w := httptest.NewRecorder()
	s.Handler(w, httptest.NewRequest("GET", "/jobs/job/logs/download", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret-value") || !strings.Contains(w.Body.String(), "[已隐藏]") {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestPendingConfigurationFingerprintDetectsHiddenCredential(t *testing.T) {
	s := managerFixture(t)
	c, err := config.Load(s.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	state := common.Map{"configuration": config.Redact(c.Raw)}
	config.RecordApplied(state, config.ApplicationInput(c.Raw, c.Nodes), "", false)
	first := s.configurationStatus(c, state)
	if len(first["changes"].([]Change)) != 0 {
		t.Fatal(first)
	}
	nodes := common.A(c.Raw["nodes"])
	node := common.M(nodes[0])
	common.M(node["ssh"])["password"] = "new-secret-value"
	common.M(c.Nodes[0]["ssh"])["password"] = "new-secret-value"
	result := s.configurationStatus(c, state)
	if common.S(common.M(result["statuses"])[common.S(node["id"])]) != "pending" || bytes.Contains(common.JSON(result), []byte("new-secret-value")) {
		t.Fatal(result)
	}
	config.RecordApplied(state, c.Raw, "", true)
	if common.S(common.M(s.configurationStatus(c, state)["statuses"])[common.S(node["id"])]) != "pending" {
		t.Fatal("central-only cleared node change")
	}
}
func TestPreflightRejectsConflictAndPreservesConfiguration(t *testing.T) {
	s := managerFixture(t)
	before := revision(t, s)
	s.running = true
	code, _ := request(t, s, "POST", "/servers/preflight", Edit{Revision: before, Node: common.Map{"id": "node-202"}})
	if code != 409 || revision(t, s) != before {
		t.Fatal(code)
	}
	s.running = false
	code, _ = request(t, s, "POST", "/servers/preflight", Edit{Revision: "obsolete", Node: common.Map{"id": "node-202"}})
	if code != 409 || revision(t, s) != before || len(s.preflightOwners) != 0 {
		t.Fatal(code)
	}
}

func TestLegacyDerivedFieldsDoNotInventPendingChanges(t *testing.T) {
	s := managerFixture(t)
	c, err := config.Load(s.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	common.M(c.Raw["ssl"])["enabled"] = false
	old := common.M(config.Redact(c.Raw))
	state := common.Map{"configuration": old, "nodes": common.Map{}}
	for i, n := range c.Nodes {
		id := common.S(n["id"])
		n["_deployment_explicit"] = false
		common.M(n["deployment"])["mode"] = "native"
		common.M(n["ssh"])["private_key_path"] = "/new/private/key"
		original := common.M(common.A(old["nodes"])[i])
		delete(original, "deployment")
		original["_deployment_explicit"] = false
		common.M(original["ssh"])["private_key_path"] = "/old/private/key"
		original["metrics"] = common.Map{"tls_enabled": false}
		common.M(state["nodes"])[id] = common.Map{"deployment_mode": "docker", "phase": "complete"}
	}
	result := s.configurationStatus(c, state)
	if changes := result["changes"].([]Change); len(changes) > 0 {
		t.Fatalf("derived differences: %#v", changes)
	}
	for _, n := range c.Nodes {
		if common.S(common.M(result["statuses"])[common.S(n["id"])]) != "unknown" {
			t.Fatal(result)
		}
	}
}

func TestCommandLineRecoveryRetainsOriginalTask(t *testing.T) {
	s := managerFixture(t)
	state := common.Map{"step": "installing", "run_id": "go-external", "target_node": "node-202", "target_add_node": true}
	common.AtomicJSON(filepath.Join(s.StateDir, "state.json"), state)
	release := make(chan struct{})
	s.execute = func(context.Context, string, string, string) error { <-release; return nil }
	code, preview := request(t, s, "POST", "/jobs/current/recovery-preview", common.Map{"kind": "resume"})
	if code != 200 {
		t.Fatal(code, preview)
	}
	input := Start{Key: "resume-cli", Revision: revision(t, s), Kind: "resume", Node: "node-202", OriginalJob: "current", RecoveryToken: common.S(preview["token"])}
	code, job := request(t, s, "POST", "/jobs", input)
	if code != 202 {
		close(release)
		t.Fatal(code, job)
	}
	var parent string
	s.DB.QueryRow("SELECT parent FROM job_workflow WHERE job=?", common.S(job["id"])).Scan(&parent)
	if parent == "" || parent == "current" {
		close(release)
		t.Fatal("unstable parent", parent)
	}
	code, original := request(t, s, "GET", "/jobs/"+parent, nil)
	if code != 200 || common.S(common.M(original["job"])["node"]) != "node-202" {
		close(release)
		t.Fatal(code, original)
	}
	close(release)
	for i := 0; i < 100; i++ {
		s.mu.Lock()
		done := !s.running
		s.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("task did not settle")
}
