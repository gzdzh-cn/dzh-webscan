package controlplane

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNodeRemovalPreservesHistoryAndFencesCollection(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx := context.Background()
	before := &configurationEditBackup{v, c}
	in := deploymentFixture(t, s)
	j := createDeployment(t, s, in, "historical-deployment")
	mustHistoryExec(t, s.DB, `UPDATE v3_deployment_jobs SET status='rolled_back',recovery_required=false WHERE id=$1`, j.ID)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_events(node,id,received_at,operation,payload) VALUES('saved-node','keep-event',clock_timestamp(),'modify','{}')`)
	// Read the actual registered snapshot rather than desired form metadata.
	n, err := scanActiveNode(s.DB.QueryRow(`SELECT ` + activeNodeColumns + ` FROM v3_active_nodes WHERE id='saved-node'`))
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.Acquire(ctx, shardResource(n.Shard), "old-collector")
	if err != nil {
		t.Fatal(err)
	}
	records := []nodeRemovalRecord{{"saved-node", 1}, {"node-a", 1}}
	raw, err := s.removeNodes(ctx, "admin", "remove-both", records, true, before)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.removeNodes(ctx, "admin", "remove-both", []nodeRemovalRecord{records[1], records[0]}, true, before)
	var response, replayed map[string]any
	if err != nil || json.Unmarshal(raw, &response) != nil || json.Unmarshal(replay, &replayed) != nil || !reflect.DeepEqual(response, replayed) {
		t.Fatal("lost idempotent receipt", err)
	}
	if _, err = s.removeNodes(ctx, "admin", "remove-both", records[:1], true, before); !errors.Is(err, ErrRequestConflict) {
		t.Fatal("reused a key for a different selection", err)
	}
	items, err := s.consoleNodes(ctx, "", "", "", 20, 30)
	if err != nil || len(items) != 0 || tableCount(t, s, "v3_active_nodes") != 0 || tableCount(t, s, "v3_nodes") != 2 || tableCount(t, s, "v3_events") != 1 || tableCount(t, s, "v3_deployment_jobs") != 1 {
		t.Fatal("removal lost history or retained a collector target", err, len(items))
	}
	summary, err := s.Summary(ctx)
	var counts struct {
		Servers int `json:"servers"`
	}
	if err != nil || json.Unmarshal(summary, &counts) != nil || counts.Servers != 0 {
		t.Fatal("overview still includes removed nodes", err)
	}
	backups, err := s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || len(backups) != 1 || len(readPrivateConfigurationBackup(t, s, v, backups[0].ID).Nodes) != 2 {
		t.Fatal("missing exact before-removal backup", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FenceNode(ctx, tx, n, l); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old collector can still commit", err)
	}
	tx.Rollback()
	if _, err := s.SaveNode(ctx, "admin", "revive-node", nodeFixture("saved-node"), 2, 256); !errors.Is(err, ErrConflict) {
		t.Fatal("editing resurrected a removed node", err)
	}
	if err := s.PutNode(ctx, nodeFixture("saved-node"), 0, 256); !errors.Is(err, ErrConflict) {
		t.Fatal("node ID was reused across history", err)
	}
	if _, err := s.CreateDeployment(ctx, "admin", "revive-deployment", in); !errors.Is(err, ErrConflict) {
		t.Fatal("deployment resurrected a removed node", err)
	}
	if _, err := s.SaveSite(ctx, "admin", "new-site", SiteInput{Name: "example", URL: "https://example.test", Node: "saved-node"}, 0); !errors.Is(err, ErrSiteNodeMissing) {
		t.Fatal("new website referenced a removed node", err)
	}
	archive, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err := restored.RestorePostgres(ctx, archive); err != nil {
		t.Fatal(err)
	}
	items, err = restored.consoleNodes(ctx, "", "", "", 20, 30)
	if err != nil || len(items) != 0 || tableCount(t, restored, "v3_events") != 1 || tableCount(t, restored, "v3_deployment_jobs") != 1 {
		t.Fatal("disaster restore revived removed nodes or lost history", err)
	}
}

func TestNodeRemovalProtectsWebsiteTasksAndWholeSelection(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	before := &configurationEditBackup{v, c}
	in := deploymentFixture(t, s)
	j := createDeployment(t, s, in, "unfinished-deployment")
	records := []nodeRemovalRecord{{"saved-node", 1}, {"node-a", 1}}
	for _, status := range []string{"queued", "failed"} {
		mustHistoryExec(t, s.DB, `UPDATE v3_deployment_jobs SET status=$2,recovery_required=true WHERE id=$1`, j.ID, status)
		_, err := s.removeNodes(context.Background(), "admin", "blocked-task", records, true, before)
		var blocked *nodeRemovalBlocked
		if !errors.As(err, &blocked) || !strings.Contains(err.Error(), "未完成部署") {
			t.Fatal("unfinished operation did not protect node", err)
		}
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_deployment_jobs SET status='failed',recovery_required=false WHERE id=$1`, j.ID)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_websites(name,url,node) VALUES('example','https://example.test','node-a')`)
	_, err := s.removeNodes(context.Background(), "admin", "blocked-website", records, true, before)
	var blocked *nodeRemovalBlocked
	if !errors.As(err, &blocked) || !strings.Contains(err.Error(), "关联网站") {
		t.Fatal("associated website was orphaned", err)
	}
	var removed int
	s.DB.QueryRow(`SELECT count(*) FROM v3_nodes WHERE removed_at IS NOT NULL`).Scan(&removed)
	if removed != 0 || tableCount(t, s, "v3_configuration_backups") != 0 {
		t.Fatal("part of a protected selection was removed")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_websites SET deleted=true`)
	if _, err := s.removeNodes(context.Background(), "admin", "unblocked", records, true, before); err != nil {
		t.Fatal("historical read-only failure should not reserve a node forever", err)
	}
}

func TestNodeRemovalBackupOrAuditFailurePreservesOriginal(t *testing.T) {
	for _, table := range []string{"v3_configuration_backups", "v3_audit"} {
		t.Run(table, func(t *testing.T) {
			s, v, c := configurationBackupStoreFixture(t)
			mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_removal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-storage-error'; END $$;CREATE TRIGGER reject_removal BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION fail_removal()`)
			if _, err := s.removeNodes(context.Background(), "admin", "must-rollback", []nodeRemovalRecord{{"saved-node", 1}}, true, &configurationEditBackup{v, c}); err == nil {
				t.Fatal("storage failure accepted")
			}
			var version int64
			var removed sql.NullTime
			if err := s.DB.QueryRow(`SELECT version,removed_at FROM v3_nodes WHERE id='saved-node'`).Scan(&version, &removed); err != nil || version != 1 || removed.Valid || tableCount(t, s, "v3_node_runtime") != 1 || tableCount(t, s, "v3_requests") != 0 || tableCount(t, s, "v3_configuration_backups") != 0 {
				t.Fatal("failed removal changed original state", err)
			}
		})
	}
}

func TestNodeRemovalHTTPAuthorizationAndStrictInput(t *testing.T) {
	a, _, sessions := configurationAPIFixture(t)
	call := func(user, csrf, body, key string, secure bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v3/servers/remove", strings.NewReader(body))
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions[user]})
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	body := `{"records":[{"id":"saved-node","expected_version":1}],"confirm":true}`
	for _, tc := range []struct {
		user, csrf, body, key string
		secure                bool
		want                  int
	}{
		{"missing", "configuration-csrf", body, "one", true, 401},
		{"viewer", "configuration-csrf", body, "one", true, 403},
		{"operator", "configuration-csrf", body, "one", true, 403},
		{"admin", "wrong", body, "one", true, 403},
		{"admin", "configuration-csrf", body, "one", false, 403},
		{"admin", "configuration-csrf", body, "", true, 400},
		{"admin", "configuration-csrf", strings.Replace(body, `"confirm":true`, `"confirm":true,"confirm":false`, 1), "one", true, 400},
		{"admin", "configuration-csrf", strings.Replace(body, `"confirm":true`, `"confirm":true,"command":"anything"`, 1), "one", true, 400},
		{"admin", "configuration-csrf", strings.Replace(body, `"confirm":true`, `"confirm":false`, 1), "one", true, 400},
		{"admin", "configuration-csrf", strings.Replace(body, `"expected_version":1`, `"expected_version":2`, 1), "one", true, 409},
	} {
		if w := call(tc.user, tc.csrf, tc.body, tc.key, tc.secure); w.Code != tc.want {
			t.Fatal(tc.user, w.Code, w.Body.String())
		}
	}
	if w := call("admin", "configuration-csrf", body, "remove-once", true); w.Code != 200 || strings.Contains(w.Body.String(), "private-") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("admin", "configuration-csrf", body, "remove-once", true); w.Code != 200 {
		t.Fatal("retry failed", w.Code, w.Body.String())
	}
}

func TestNodeRemovalWaitsForWebsiteAssociation(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := lockWebsiteConfiguration(ctx, tx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.removeNodes(ctx, "admin", "concurrent-removal", []nodeRemovalRecord{{"saved-node", 1}}, true, &configurationEditBackup{v, c})
		done <- err
	}()
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_websites(name,url,node) VALUES('example','https://example.test','saved-node')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var blocked *nodeRemovalBlocked
	if err := <-done; !errors.As(err, &blocked) {
		t.Fatal("concurrent website association was missed", err)
	}
}

func TestNodeRemovalMigrationRequiresBackupAndKeepsExistingNodes(t *testing.T) {
	s, _, _ := configurationBackupStoreFixture(t)
	mustHistoryExec(t, s.DB, `CREATE OR REPLACE VIEW v3_active_nodes AS
 SELECT c.node AS id,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.version,n.applied_version,c.shard,c.config,r.epoch AS runtime_epoch
 FROM v3_node_runtime r JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot JOIN v3_nodes n ON n.id=c.node;
 ALTER TABLE v3_nodes DROP COLUMN removed_at; DELETE FROM v3_schema WHERE version=36`)
	ctx := context.Background()
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("migration skipped the required consistent backup")
	}
	if err := s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	items, err := s.consoleNodes(ctx, "", "", "", 20, 30)
	if err != nil || len(items) != 1 || tableCount(t, s, "v3_active_nodes") != 1 {
		t.Fatal("migration removed a preexisting target", err)
	}
}
