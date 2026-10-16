package management

import (
	"context"
	"gopkg.in/yaml.v3"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
	"webscan/internal/deploy"
)

func upgradeFixture(t *testing.T) (*Service, string) {
	s := managerFixture(t)
	old := deploy.Release
	deploy.Release = "v2.0.44"
	t.Cleanup(func() { deploy.Release = old })
	c, e := config.Load(s.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	n := c.Selected("")[0]
	id := common.S(n["id"])
	state := common.Map{"step": "complete", "central_installed": true, "active": []string{id}, "nodes": common.Map{id: common.Map{"phase": "complete", "deployment_mode": deploy.ResolveNodeMode(n, nil), "go_release": "v2.0.43", "go_image": "test/agent@sha256:" + strings.Repeat("a", 64)}}}
	if e = common.AtomicJSON(s.StateDir+"/state.json", state); e != nil {
		t.Fatal(e)
	}
	s.upgradeResolver = func(context.Context, *config.Config) (string, string, error) {
		return "test/agent@sha256:" + strings.Repeat("b", 64), deploy.Release, nil
	}
	return s, id
}
func TestUpgradePreviewBindsOwnerConfigStateAndTarget(t *testing.T) {
	s, id := upgradeFixture(t)
	code, v := request(t, s, "POST", "/servers/"+id+"/upgrade-preview", common.Map{"revision": revision(t, s)})
	if code != 200 || common.S(v["preview_token"]) == "" {
		t.Fatal(code, v)
	}
	c, _ := config.Load(s.ConfigPath)
	in := Start{Kind: "upgrade-node", Node: id, Revision: revision(t, s), PreviewToken: common.S(v["preview_token"])}
	r := httptest.NewRequest("POST", "/jobs", nil)
	if _, _, e := s.checkUpgrade(r, in, c); e != nil {
		t.Fatal(e)
	}
	r.Header.Set("X-Webscan-Owner", "other")
	if _, _, e := s.checkUpgrade(r, in, c); e == nil {
		t.Fatal("other owner accepted")
	}
	r.Header.Del("X-Webscan-Owner")
	in.Edit = &Edit{}
	if _, _, e := s.checkUpgrade(r, in, c); e == nil {
		t.Fatal("draft edit accepted")
	}
	in.Edit = nil
	state := s.state()
	common.M(common.M(state["nodes"])[id])["go_release"] = "v2.0.42"
	common.AtomicJSON(s.StateDir+"/state.json", state)
	if _, _, e := s.checkUpgrade(r, in, c); e == nil {
		t.Fatal("state changed but preview accepted")
	}
}
func TestUpgradeJobUsesSavedConfigAndPersistsLock(t *testing.T) {
	s, id := upgradeFixture(t)
	var calls atomic.Int32
	s.execute = func(ctx context.Context, job, kind, node string) error {
		if kind != "upgrade-node" || node != id {
			t.Error("scope lost")
		}
		image, e := s.upgradeLockForJob(job)
		if e != nil || !strings.Contains(image, "@sha256:") {
			t.Error("target lock lost", e)
		}
		calls.Add(1)
		return nil
	}
	code, v := request(t, s, "POST", "/servers/"+id+"/upgrade-preview", common.Map{"revision": revision(t, s)})
	if code != 200 {
		t.Fatal(code, v)
	}
	rawBefore := revision(t, s)
	input := common.Map{"kind": "upgrade-node", "node": id, "revision": rawBefore, "preview_token": v["preview_token"], "request_key": "upgrade-fixture"}
	input["edit"] = common.Map{}
	code, _ = request(t, s, "POST", "/jobs", input)
	if code < 400 {
		t.Fatal("edit allowed")
	}
	delete(input, "edit")
	code, job := request(t, s, "POST", "/jobs", input)
	if code != 202 {
		t.Fatal(code, job)
	}
	for i := 0; i < 300; i++ {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(time.Millisecond * 10)
	}
	if calls.Load() != 1 || revision(t, s) != rawBefore {
		t.Fatal("draft persisted or job not run")
	}
	code, repeated := request(t, s, "POST", "/jobs", input)
	if code != 200 || repeated["id"] != job["id"] {
		t.Fatal("duplicate job")
	}
	s.DB.Exec("INSERT INTO jobs VALUES('resume-child','resume-child-key','resume',?,'queued',0,0,'','')", id)
	s.DB.Exec("INSERT INTO job_workflow(job,parent,run_id) VALUES('resume-child',?,'')", job["id"])
	if image, e := s.upgradeLockForJob("resume-child"); e != nil || image == "" {
		t.Fatal("resume changed image", e)
	}
}
func TestUpgradeRejectsModeChangeDowngradeAndExpiredPreview(t *testing.T) {
	s, id := upgradeFixture(t)
	c, _ := config.Load(s.ConfigPath)
	state := s.state()
	old := common.M(common.M(state["nodes"])[id])
	old["go_release"] = "v2.0.50"
	if _, e := s.upgradeNode(c, state, id); e == nil {
		t.Fatal("downgrade allowed")
	}
	old["go_release"] = "v2.0.43"
	old["deployment_mode"] = "docker"
	if deploy.ResolveNodeMode(c.Selected(id)[0], state) == "docker" {
		old["deployment_mode"] = "native"
	}
	if _, e := s.upgradeNode(c, state, id); e == nil {
		t.Fatal("mode switch allowed")
	}
	code, v := request(t, s, "POST", "/servers/"+id+"/upgrade-preview", common.Map{"revision": revision(t, s)})
	if code != 200 {
		t.Fatal(code, v)
	}
	s.DB.Exec("UPDATE upgrade_previews SET expires=0")
	_, _, e := s.checkUpgrade(httptest.NewRequest("POST", "/jobs", nil), Start{Node: id, Revision: revision(t, s), PreviewToken: common.S(v["preview_token"])}, c)
	if e == nil {
		t.Fatal("expired preview accepted")
	}
}
func TestConfirmedSameDigestNoOpForBothDeploymentModes(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			s, id := upgradeFixture(t)
			raw, e := os.ReadFile(s.ConfigPath)
			if e != nil {
				t.Fatal(e)
			}
			var yamlMap common.Map
			if e = yaml.Unmarshal(raw, &yamlMap); e != nil {
				t.Fatal(e)
			}
			for _, v := range common.A(yamlMap["nodes"]) {
				n := common.M(v)
				if common.S(n["id"]) == id {
					n["deployment"] = common.Map{"mode": mode}
				}
			}
			raw, e = yaml.Marshal(yamlMap)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(s.ConfigPath, raw, 0600); e != nil {
				t.Fatal(e)
			}
			c, e := config.Load(s.ConfigPath)
			if e != nil {
				t.Fatal(e)
			}
			state := s.state()
			old := common.M(common.M(state["nodes"])[id])
			old["deployment_mode"] = mode
			old["go_release"] = deploy.Release
			old["agent_image"] = "mirror/agent@sha256:" + strings.Repeat("b", 64)
			state["fingerprint_key"] = "isolated-key"
			state["configuration"] = config.Redact(config.ApplicationInput(c.Raw, c.Nodes))
			state["applied_fingerprints"] = config.ApplicationFingerprints(config.ApplicationInput(c.Raw, c.Nodes), "isolated-key", state)
			common.AtomicJSON(s.StateDir+"/state.json", state)
			code, v := request(t, s, "POST", "/servers/"+id+"/upgrade-preview", common.Map{"revision": revision(t, s)})
			if code != 200 || !common.B(v["no_change"]) || common.S(v["preview_token"]) != "" {
				t.Fatal("same digest not recognized", code, v)
			}
		})
	}
}
