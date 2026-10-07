package central

import (
	"context"
	"testing"
	"webscan/internal/common"
)

func TestAcceptanceSuppressesOnlyRegisteredExpectedEventsAndKeepsLoki(t *testing.T) {
	s := testStore(t)
	s.Config["alert_token"] = "deployment-admin"
	path := "/sites/.webscan-deploy-test-0123456789abcdef0123456789abcdef/fixture.php"
	hash := common.Hash([]byte("known benign YARA test fixture"))
	request := common.Map{"node": "node", "events": []any{common.Map{"operation": "scan", "path": path, "sha256": hash, "scan": common.Map{"status": "matched"}}}}
	if w := deploymentCall(s, "/deployment-acceptance", "fixture-token", request); w.Code != 401 {
		t.Fatal("agent can silence alerts", w.Code)
	}
	if w := deploymentCall(s, "/deployment-acceptance", "deployment-admin", request); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		id, path, hash, status string
		want                   int
	}{{"expected", path, hash, "matched", 0}, {"wrong-hash", path, common.Hash([]byte("real unexpected content")), "matched", 1}, {"scan-failure", path, hash, "error", 2}, {"business-file", "/sites/business.php", hash, "matched", 3}} {
		e := fixture()
		e["event_id"], e["operation"], e["path"], e["sha256"], e["scan"] = tc.id, "scan", tc.path, tc.hash, common.Map{"status": tc.status}
		if _, err := s.Ingest(context.Background(), "node", []any{e}); err != nil {
			t.Fatal(err)
		}
		var count int
		s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='feishu'").Scan(&count)
		if count != tc.want {
			t.Fatal(tc.id, "unexpected alert count", count, tc.want)
		}
		var loki int
		s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='loki' AND event_id=?", tc.id).Scan(&loki)
		if loki != 1 {
			t.Fatal("test event missing from Loki", tc.id)
		}
	}
	s.DB.Exec("UPDATE kv SET value=json_set(value,'$.expires',0) WHERE key=?", acceptanceKey("node", path))
	e := fixture()
	e["event_id"], e["operation"], e["path"], e["sha256"], e["scan"] = "expired", "scan", path, hash, common.Map{"status": "matched"}
	if _, err := s.Ingest(context.Background(), "node", []any{e}); err != nil {
		t.Fatal(err)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='feishu'").Scan(&count)
	if count != 4 {
		t.Fatal("expired fixture silenced scan", count)
	}
}

func TestAcceptanceRejectsBusinessPathsAndScanErrors(t *testing.T) {
	s := testStore(t)
	s.Config["alert_token"] = "deployment-admin"
	for _, path := range []string{"/sites/config.php", "/sites/.webscan-deploy-test-0123456789abcdef0123456789abcdef/../fixture.php"} {
		body := common.Map{"node": "node", "events": []any{common.Map{"operation": "scan", "path": path, "sha256": common.Hash([]byte("x")), "scan": common.Map{"status": "matched"}}}}
		if w := deploymentCall(s, "/deployment-acceptance", "deployment-admin", body); w.Code != 400 {
			t.Fatal("business registration accepted", w.Code)
		}
	}
}
