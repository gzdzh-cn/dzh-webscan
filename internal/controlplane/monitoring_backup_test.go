package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"webscan/internal/common"
)

func TestMonitoringBackupRestorePreservesJournalAndRevokesRuntimeAuthority(t *testing.T) {
	for _, status := range []string{"paused", "queued", "running"} {
		t.Run(status, func(t *testing.T) {
			ctx := context.Background()
			f := newMonitoringApplicationFixture(t)
			p := f.confirmed(t)
			f.worker.runtime = readinessFixtureRuntime{&fakeDeploymentRuntime{failPhase: "activate"}, t, f.s}
			f.worker.execute(ctx, p)
			p, e := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
			if e != nil || p.Status != "paused" || len(p.Nodes) != 1 || p.Nodes[0].Job == "" {
				t.Fatal("fixture did not retain partial child journal", e)
			}
			if _, _, e = f.s.previewMonitoringReauthorization(ctx, f.t.vault, "admin", "backup-reauthorization", p.ID, p.Expected); e != nil {
				t.Fatal("reauthorization fixture", e)
			}
			if status != "paused" {
				if _, e = f.s.recoverMonitoringApplication(ctx, f.t.vault, "admin", "backup-queue", p.ID, p.Expected, "forward"); e != nil {
					t.Fatal(e)
				}
			}
			if status == "running" {
				if _, e = f.worker.claim(ctx); e != nil {
					t.Fatal(e)
				}
			}
			p, e = f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
			if e != nil || p.Status != status {
				t.Fatal("incorrect source status", p.Status, e)
			}
			f.worker.heartbeat(ctx)
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_role_status(role,instance,heartbeat) VALUES('isolated-preserved-role','backup-test',clock_timestamp())`)
			session := token()
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,'admin',1,'configuration-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(session)))
			for _, table := range []string{"v3_monitoring_application_authorizations", "v3_monitoring_application_nodes"} {
				if tableCount(t, f.s, table) != 1 {
					t.Fatal("incomplete source fixture", table)
				}
			}
			if deploymentBackupPinCount(t, f.s, reloadDeployment(t, f.s, p.Nodes[0].Job), "rollback") != 1 {
				t.Fatal("source lost child rollback archive")
			}
			parentRows := publicMonitoringRows(t, f.s, "v3_monitoring_applications", "id")
			nodeRows := publicMonitoringRows(t, f.s, "v3_monitoring_application_nodes", "application,node")
			childRows := publicMonitoringRows(t, f.s, "v3_deployment_jobs", "id")
			privateNodeRows := publicMonitoringRows(t, f.s, "v3_nodes", "id")
			activeRows := publicMonitoringRows(t, f.s, "v3_active_nodes", "id")
			pins := publicMonitoringRows(t, f.s, "v3_configuration_backup_pins", "backup,kind,reference")
			path, e := f.s.BackupPostgres(ctx, privateTestDir(t))
			if e != nil {
				t.Fatal("backup current schema", e)
			}
			header, e := inspectPGBackup(path)
			if e != nil || header.Version != SchemaVersion {
				t.Fatal("incorrect archive version", header.Version, e)
			}
			target := emptyTestStore(t)
			if e = target.RestorePostgres(ctx, path); e != nil {
				t.Fatal("restore current schema", e)
			}
			if e = target.Migrate(ctx); e != nil {
				t.Fatal("restored schema not current", e)
			}
			// Compare every signed parent byte after excluding only the intended
			// recovery_hold revocation. Restoration must not rewrite its proof.
			var restoredParents string
			if e = target.DB.QueryRow(`SELECT jsonb_agg(to_jsonb(r)||'{"recovery_hold":false}'::jsonb ORDER BY id)::text FROM v3_monitoring_applications r`).Scan(&restoredParents); e != nil {
				t.Fatal(e)
			}
			if restoredParents != parentRows {
				t.Fatal("restore changed immutable parent plan or signed checkpoint")
			}
			for _, tc := range []struct{ table, order, before string }{
				{"v3_monitoring_application_nodes", "application,node", nodeRows},
				{"v3_deployment_jobs", "id", childRows},
				{"v3_nodes", "id", privateNodeRows},
				{"v3_active_nodes", "id", activeRows},
				{"v3_configuration_backup_pins", "backup,kind,reference", pins},
			} {
				if publicMonitoringRows(t, target, tc.table, tc.order) != tc.before {
					t.Fatal("restoration changed retained recovery records", tc.table)
				}
			}
			var held, reserved bool
			if e = target.DB.QueryRow(`SELECT recovery_hold FROM v3_monitoring_applications WHERE id=$1`, p.ID).Scan(&held); e != nil || !held {
				t.Fatal("restored parent not held", e)
			}
			if e = target.DB.QueryRow(`SELECT reserved FROM v3_monitoring_application_nodes WHERE application=$1`, p.ID).Scan(&reserved); e != nil || !reserved {
				t.Fatal("restore released node reservation", e)
			}
			if tableCount(t, target, "v3_monitoring_application_authorizations") != 0 {
				t.Fatal("archived reauthorization capability survived restore")
			}
			var heartbeats int
			if e = target.DB.QueryRow(`SELECT count(*) FROM v3_role_status WHERE role='monitoring-applications'`).Scan(&heartbeats); e != nil || heartbeats != 0 {
				t.Fatal("archived monitoring heartbeat certified recovered worker", e)
			}
			if e = target.DB.QueryRow(`SELECT count(*) FROM v3_role_status WHERE role='isolated-preserved-role'`).Scan(&heartbeats); e != nil || heartbeats != 1 {
				t.Fatal("restore cleared unrelated heartbeat", e)
			}
			remote := &fakeDeploymentRuntime{}
			worker := NewMonitoringApplicationWorker(target, f.c, f.t, readinessFixtureRuntime{remote, t, target}, "restored-monitoring-worker")
			if _, e = worker.claim(ctx); e != sql.ErrNoRows {
				t.Fatal("worker automatically claimed restored authority", e)
			}
			if len(remote.calls) != 0 {
				t.Fatal("recovered worker performed remote actions")
			}
			view, e := target.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
			if e != nil || view.CanResume || view.CanRollback || view.CanReauthorize || view.Digest != p.Digest || !reflect.DeepEqual(view.Plan, p.Plan) {
				t.Fatal("held restore advertised actionable or changed plan", e)
			}
			for _, item := range view.Nodes {
				if item.CanResume || item.CanRollback {
					t.Fatal("held restore advertised node recovery")
				}
			}
			a := NewAPI(target, f.c)
			w := publicMonitoringCall(a, "GET", "/api/v3/monitoring/applications/"+p.ID, nil, session, "", "", true)
			var body monitoringApplication
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.CanResume || body.CanRollback || body.CanReauthorize {
				t.Fatal("restored GET granted stale execution authority", w.Code, w.Body.String())
			}
			if status == "paused" {
				beforeHeld := publicMonitoringRows(t, target, "v3_monitoring_applications", "id")
				for _, direction := range []string{"forward", "rollback"} {
					for _, scope := range []string{"all", "node"} {
						var selected []string
						if scope == "node" {
							selected = []string{f.in.Node}
						}
						if _, e = target.recoverMonitoringApplication(ctx, f.t.vault, "admin", "reject-held-"+direction+"-"+scope, p.ID, view.Expected, direction, selected...); e == nil {
							t.Error("direct recovery accepted archived authority despite recovery_hold", direction, scope)
						}
					}
				}
				if publicMonitoringRows(t, target, "v3_monitoring_applications", "id") != beforeHeld {
					t.Error("rejected held recovery changed signed parent state")
				}
			}
		})
	}
}

func TestMonitoringBackupMigration38RequiresBackupAndRollsBackFailure(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("migration38-preserved")
	n.Config = common.JSON(map[string]any{"monitor": map[string]any{"roots": []string{"/srv/pre-upgrade"}}, "private": map[string]any{"token": "isolated-preserved-value"}})
	if e := s.PutNode(ctx, n, 0, 256); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, s.DB, postMonitoringMigrationsTestDrop+`INSERT INTO v3_accounts(username,password_hash,role) VALUES('admin','isolated-not-a-login','admin');INSERT INTO v3_events(node,id,received_at,operation,payload) VALUES('migration38-preserved','keep-event',clock_timestamp(),'modify','{"path":"/srv/pre-upgrade/index.php"}');DROP TABLE v3_monitoring_application_authorizations;DROP TABLE v3_monitoring_application_nodes;DROP TABLE v3_monitoring_applications;DELETE FROM v3_schema WHERE version=39`)
	nodes := publicMonitoringRows(t, s, "v3_nodes", "id")
	events := publicMonitoringRows(t, s, "v3_events", "node,id")
	accounts := publicMonitoringRows(t, s, "v3_accounts", "username")
	assertOld := func() {
		t.Helper()
		version, e := currentSchema(ctx, s.DB)
		if e != nil || version != 38 {
			t.Fatal("failed upgrade changed schema version", version, e)
		}
		var exists bool
		if e = s.DB.QueryRow(`SELECT to_regclass(current_schema()||'.v3_monitoring_applications') IS NOT NULL`).Scan(&exists); e != nil || exists {
			t.Fatal("failed upgrade left partial schema39", e)
		}
		if publicMonitoringRows(t, s, "v3_nodes", "id") != nodes || publicMonitoringRows(t, s, "v3_events", "node,id") != events || publicMonitoringRows(t, s, "v3_accounts", "username") != accounts {
			t.Fatal("failed upgrade changed preexisting business data")
		}
	}
	if e := s.Migrate(ctx); e == nil {
		t.Fatal("schema38 silently upgraded without verified backup")
	}
	assertOld()
	unsafe := filepath.Join(privateTestDir(t), "not-private")
	if e := os.Mkdir(unsafe, 0755); e != nil {
		t.Fatal(e)
	}
	if e := s.Upgrade(ctx, unsafe); e == nil {
		t.Fatal("migration accepted invalid backup directory")
	}
	assertOld()
	mustHistoryExec(t, s.DB, `CREATE FUNCTION reject_schema39() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.version=39 THEN RAISE EXCEPTION 'isolated schema39 write failure';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_schema39 BEFORE INSERT ON v3_schema FOR EACH ROW EXECUTE FUNCTION reject_schema39()`)
	backupDir := privateTestDir(t)
	if e := s.Upgrade(ctx, backupDir); e == nil {
		t.Fatal("synthetic schema39 migration failure ignored")
	}
	assertOld()
	files, e := os.ReadDir(backupDir)
	if e != nil || len(files) != 1 {
		t.Fatal("missing consistent pre-migration backup", e)
	}
	path := filepath.Join(backupDir, files[0].Name())
	header, e := inspectPGBackup(path)
	if e != nil || header.Version != 38 {
		t.Fatal("invalid pre-migration backup", e)
	}
	prior := emptyTestStore(t)
	if e = prior.RestorePostgres(ctx, path); e != nil {
		t.Fatal("pre-migration schema38 backup cannot restore", e)
	}
	for _, tc := range []struct{ table, order, want string }{{"v3_nodes", "id", nodes}, {"v3_events", "node,id", events}, {"v3_accounts", "username", accounts}} {
		if publicMonitoringRows(t, prior, tc.table, tc.order) != tc.want {
			t.Fatal("pre-migration backup lost data", tc.table)
		}
	}
	mustHistoryExec(t, s.DB, `DROP TRIGGER reject_schema39 ON v3_schema`)
	if e = s.Upgrade(ctx, privateTestDir(t)); e != nil {
		t.Fatal("migration retry failed", e)
	}
	version, e := currentSchema(ctx, s.DB)
	if e != nil || version != SchemaVersion {
		t.Fatal("migration retry not current", version, e)
	}
	if publicMonitoringRows(t, s, "v3_nodes", "id") != nodes || publicMonitoringRows(t, s, "v3_events", "node,id") != events || publicMonitoringRows(t, s, "v3_accounts", "username") != accounts {
		t.Fatal("schema39 upgrade rewrote existing data")
	}
	for _, table := range []string{"v3_monitoring_applications", "v3_monitoring_application_nodes", "v3_monitoring_application_authorizations"} {
		if tableCount(t, s, table) != 0 {
			t.Fatal("migration created phantom monitoring tasks", table)
		}
	}
}
