package central

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
	"webscan/internal/telemetry"
)

func TestRepeatedMaintenanceReloadKeepsProtectedSettings(t *testing.T) {
	s := testStore(t)
	path := filepath.Join(t.TempDir(), "runtime.json")
	s.Config["runtime_path"] = path
	s.Config["monitoring"] = common.Map{"mode": "native", "maintenance_nodes": []string{"node"}}
	for _, ids := range [][]string{{"node"}, {}, {}} {
		c := common.Clone(s.Snapshot())
		delete(c, "runtime_path")
		common.M(c["monitoring"])["maintenance_nodes"] = ids
		if e := common.AtomicJSON(path, c); e != nil {
			t.Fatal(e)
		}
		if e := s.reloadSettings(path); e != nil {
			t.Fatal(e)
		}
		if len(common.SS(common.M(s.Snapshot()["monitoring"])["maintenance_nodes"])) != len(ids) {
			t.Fatal("maintenance not applied")
		}
	}
	c := common.Clone(s.Snapshot())
	common.M(common.M(c["nodes"])["node"])["token"] = "private-rejected-token"
	common.AtomicJSON(path, c)
	err := s.reloadSettings(path)
	if err == nil || !strings.Contains(err.Error(), "nodes") || strings.Contains(err.Error(), "private-rejected-token") {
		t.Fatal("protected node change accepted or leaked", err)
	}
	if common.S(common.M(common.M(s.Snapshot()["nodes"])["node"])["token"]) != "fixture-token" {
		t.Fatal("rejected runtime replaced active settings")
	}
}

func TestReloadDistinguishesUnavailableMetricsFromRejectedConfiguration(t *testing.T) {
	s := testStore(t)
	s.Config["alert_token"] = "reload-test-token"
	s.Config["monitoring"] = common.Map{"mode": "native"}
	path := filepath.Join(t.TempDir(), "runtime.json")
	s.Config["runtime_path"] = path
	var err error
	s.Telemetry, err = telemetry.Open(t.TempDir(), nil, common.Map{})
	if err != nil {
		t.Fatal(err)
	}
	s.Telemetry.DB.Close()
	for _, rejected := range []bool{false, true} {
		c := common.Clone(s.Snapshot())
		if rejected {
			common.M(common.M(c["nodes"])["node"])["token"] = "private-rejected-token"
		}
		if err = common.AtomicJSON(path, c); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/reload-settings", strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer reload-test-token")
		w := httptest.NewRecorder()
		s.Handler(w, r)
		want := 503
		if rejected {
			want = 400
		}
		if w.Code != want || strings.Contains(w.Body.String(), "private-rejected-token") {
			t.Fatal(w.Code, want, w.Body.String())
		}
	}
}
