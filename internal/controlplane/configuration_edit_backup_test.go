package controlplane

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func configurationEditAPIFixture(t *testing.T, s *Store) *API {
	t.Helper()
	c := configurationBootstrapFixture(t)
	_, path := testVault(t)
	c.DeploymentTrust = DeploymentTrustConfig{VaultKeyFile: path,
		PublicKeyFile: "/test/release.pub", ManifestFile: "/test/release.json",
		SignatureFile: "/test/release.sig", HelperFile: "/test/helper", NativeBundleFile: "/test/native.tar"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return NewAPI(s, c)
}

func TestConfigurationEditBackupSnapshotsAndConcurrentRetry(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	before := &configurationEditBackup{v, c}
	ctx := context.Background()
	n := nodeFixture("saved-node")
	n.Name = "edited-name"
	var wg sync.WaitGroup
	errorsCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.saveNode(ctx, "admin", "edit-node", n, 1, 256, before)
			errorsCh <- err
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || len(items) != 1 || items[0].Source != "before_edit" {
		t.Fatal("retry created multiple backups", len(items), err)
	}
	doc := readPrivateConfigurationBackup(t, s, v, items[0].ID)
	if doc.Nodes[n.ID].Name == n.Name || doc.Nodes[n.ID].Version != 1 || doc.SettingsVersion != 5 {
		t.Fatal("backup did not capture old desired configuration")
	}
	body, err := marshalConfigurationDocument(doc)
	if err != nil || !bytes.Contains(body, []byte("private-stored-node-value")) || !bytes.Contains(body, []byte("private-stored-mail-value")) {
		t.Fatal("private fields missing from encrypted snapshot", err)
	}
	if _, err = s.saveRetentionPolicy(ctx, "admin", "edit-policy", RetentionPolicy{90, 90, 90, 90, 90}, 5, before); err != nil {
		t.Fatal(err)
	}
	items, err = s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || len(items) != 2 {
		t.Fatal(len(items), err)
	}
	doc = readPrivateConfigurationBackup(t, s, v, items[0].ID)
	if doc.Nodes[n.ID].Name != n.Name || doc.Nodes[n.ID].Version != 2 || doc.SettingsVersion != 5 {
		t.Fatal("second backup lost preceding committed edit")
	}
	p, err := retentionPolicy(doc.Settings)
	if err != nil || p.Events != 60 {
		t.Fatal("before-policy snapshot used new policy", err)
	}
	if tableCount(t, s, "v3_requests") != 2 || tableCount(t, s, "v3_audit") != 4 {
		t.Fatal("backup and mutation receipts/audits not atomic")
	}
	var public []byte
	if err = s.DB.QueryRow(`SELECT jsonb_agg(result)::text FROM v3_audit`).Scan(&public); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(public, []byte("private-")) || bytes.Contains(public, []byte(n.Endpoint)) {
		t.Fatal("audit leaked private state")
	}
}

func TestConfigurationEditBackupFailureRollsBackAllWrites(t *testing.T) {
	for _, operation := range []string{"node", "policy"} {
		for _, point := range []string{"header", "part", "backup-audit", "mutation-audit"} {
			t.Run(operation+"/"+point, func(t *testing.T) {
				s, v, c := configurationBackupStoreFixture(t)
				before := &configurationEditBackup{v, c}
				table, condition := "v3_configuration_backups", "true"
				switch point {
				case "part":
					table = "v3_configuration_backup_parts"
				case "backup-audit":
					table, condition = "v3_audit", "NEW.kind='configuration-backup-before-edit'"
				case "mutation-audit":
					table, condition = "v3_audit", "NEW.kind IN ('save-node','retention-policy')"
				}
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_edit_backup() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF `+condition+` THEN RAISE EXCEPTION 'synthetic disk/write failure private-detail';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_edit BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION fail_edit_backup()`)
				mutate := func() error {
					n := nodeFixture("saved-node")
					n.Name = "should-rollback"
					var err error
					if operation == "node" {
						_, err = s.saveNode(context.Background(), "admin", "retry-edit", n, 1, 256, before)
					} else {
						_, err = s.saveRetentionPolicy(context.Background(), "admin", "retry-edit", RetentionPolicy{90, 90, 90, 90, 90}, 5, before)
					}
					return err
				}
				if err := mutate(); err == nil {
					t.Fatal("injected failure ignored")
				}
				for _, table := range []string{"v3_configuration_backups", "v3_configuration_backup_parts", "v3_audit", "v3_requests"} {
					if tableCount(t, s, table) != 0 {
						t.Fatal("partial write survived", table)
					}
				}
				var nodeVersion, settingsVersion int64
				if err := s.DB.QueryRow(`SELECT n.version,s.version FROM v3_nodes n CROSS JOIN v3_settings s WHERE n.id='saved-node' AND s.id=1`).Scan(&nodeVersion, &settingsVersion); err != nil || nodeVersion != 1 || settingsVersion != 5 {
					t.Fatal("failed save changed configuration", nodeVersion, settingsVersion, err)
				}
				mustHistoryExec(t, s.DB, `DROP TRIGGER fail_edit ON `+table)
				if err := mutate(); err != nil || tableCount(t, s, "v3_configuration_backups") != 1 {
					t.Fatal("same-key retry could not recover", err)
				}
			})
		}
	}
}

func TestConfigurationEditBackupRejectsConflictBusyAndDemoted(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx := context.Background()
	before := &configurationEditBackup{v, c}
	n := nodeFixture("saved-node")
	if _, err := s.saveNode(ctx, "admin", "stale-node", n, 9, 256, before); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err := s.saveRetentionPolicy(ctx, "admin", "stale-policy", RetentionPolicy{90, 90, 90, 90, 90}, 9, before); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	in := DeploymentRequest{Node: n.ID, Kind: "install", Expected: 1, Credential: addCredential(t, s, v, n.ID), Release: "v3.0.0", SHA256: digest([]byte("synthetic-target"))}
	_ = createDeployment(t, s, in, "busy")
	if _, err := s.saveNode(ctx, "admin", "busy-edit", n, 1, 256, before); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal(err)
	}
	for _, user := range []string{"operator", "viewer", "missing"} {
		if _, err := s.saveRetentionPolicy(ctx, user, "forbidden-edit", RetentionPolicy{90, 90, 90, 90, 90}, 5, before); !errors.Is(err, ErrConfigurationBackupPermission) {
			t.Fatal("permission not rechecked", err)
		}
	}
	if tableCount(t, s, "v3_configuration_backups") != 0 {
		t.Fatal("rejected operation created a backup")
	}
}

func TestConfigurationEditBackupPublicAPIAndUnavailableVault(t *testing.T) {
	for _, route := range []string{"/api/v3/servers", "/api/v3/retention/policy"} {
		t.Run(route, func(t *testing.T) {
			a, v, sessions := configurationAPIFixture(t)
			method, body := "POST", `{"node":{"id":"new-node","name":"new node","endpoint":"192.0.2.9:19100","server_name":"new-node.example.test","enabled":true,"mode":"native"},"expected_version":0}`
			if strings.HasSuffix(route, "policy") {
				method, body = "PUT", `{"expected_version":5,"policy":{"sqlite_events_days":90,"security_events_days":90,"website_incidents_days":90,"server_alerts_days":90,"delivery_records_days":90}}`
			}
			call := func(csrf string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, route, strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
				r.Header.Set("X-CSRF-Token", csrf)
				r.Header.Set("Idempotency-Key", "public-edit")
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			if w := call(""); w.Code != 403 {
				t.Fatal("CSRF bypass", w.Code)
			}
			path := a.Config.DeploymentTrust.VaultKeyFile
			a.Config.DeploymentTrust.VaultKeyFile = "/not-a-real-key"
			if w := call("configuration-csrf"); w.Code != 503 || !strings.Contains(w.Body.String(), "before_edit_backup_failed") || strings.Contains(w.Body.String(), "/not-a-real-key") {
				t.Fatal("vault failure not safely blocked", w.Code, w.Body.String())
			}
			if tableCount(t, a.Store, "v3_requests") != 0 || tableCount(t, a.Store, "v3_configuration_backups") != 0 {
				t.Fatal("vault failure changed state")
			}
			a.Config.DeploymentTrust.VaultKeyFile = path
			for i := 0; i < 2; i++ {
				if w := call("configuration-csrf"); w.Code != 200 || strings.Contains(w.Body.String(), "private-") {
					t.Fatal("public backed mutation", w.Code, w.Body.String())
				}
			}
			items, err := a.Store.configurationBackups(context.Background(), "admin", retentionCursor{}, 20)
			if err != nil || len(items) != 1 || items[0].Source != "before_edit" {
				t.Fatal("public route bypassed backup", len(items), err)
			}
			archive := readPrivateConfigurationBackup(t, a.Store, v, items[0].ID)
			raw, err := marshalConfigurationDocument(archive)
			if err != nil || bytes.Contains(raw, []byte("runtime-only-lease-owner")) || len(archive.Nodes) != 1 || archive.SettingsVersion != 5 {
				t.Fatal("API used edited/runtime bootstrap or new state", err)
			}
			mustHistoryExec(t, a.Store.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
			if w := call("configuration-csrf"); w.Code != 403 {
				t.Fatal("replay bypassed revocation", w.Code)
			}
		})
	}
}

func TestConfigurationEditBackupWaitsAndCapturesCommittedState(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gate, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err = gate.ExecContext(ctx, `UPDATE v3_nodes SET name='committed-before-wait' WHERE id='saved-node'`); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := s.saveRetentionPolicy(ctx, "admin", "after-wait", RetentionPolicy{90, 90, 90, 90, 90}, 5, &configurationEditBackup{v, c})
		result <- err
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='v3_nodes'::regclass AND mode='ShareRowExclusiveLock' AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-result:
			t.Fatal("write did not wait", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	if err = gate.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	items, err := s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || len(items) != 1 {
		t.Fatal(err)
	}
	doc := readPrivateConfigurationBackup(t, s, v, items[0].ID)
	if doc.Nodes["saved-node"].Name != "committed-before-wait" {
		t.Fatal("captured stale snapshot from before relation-lock wait")
	}
}

func TestConfigurationEditBackupCancellationAndInvalidSnapshot(t *testing.T) {
	for _, scenario := range []string{"cancelled-lock", "invalid-saved-config", "duplicate-new-node", "missing-bootstrap"} {
		t.Run(scenario, func(t *testing.T) {
			s, v, c := configurationBackupStoreFixture(t)
			before := &configurationEditBackup{v, c}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			expected := int64(1)
			switch scenario {
			case "cancelled-lock":
				gate, err := s.DB.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer gate.Rollback()
				if err = lockConfigurationRestoreStateTx(ctx, gate); err != nil {
					t.Fatal(err)
				}
				short, stop := context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
				if _, err = s.saveNode(short, "admin", "cancelled-save", nodeFixture("saved-node"), 1, 256, before); err == nil || short.Err() == nil {
					t.Fatal("cancelled lock was not abandoned", err)
				}
				if err = gate.Rollback(); err != nil {
					t.Fatal(err)
				}
			case "invalid-saved-config":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET config='[]'`)
				if _, err := s.saveNode(ctx, "admin", "invalid-snapshot", nodeFixture("saved-node"), 1, 256, before); !errors.Is(err, errConfigurationBeforeEdit) {
					t.Fatal("unrecoverable snapshot did not stop save", err)
				}
			case "duplicate-new-node":
				expected = 0
				if _, err := s.saveNode(ctx, "admin", "duplicate-save", nodeFixture("saved-node"), expected, 256, before); !errors.Is(err, ErrConflict) {
					t.Fatal("duplicate create accepted", err)
				}
			case "missing-bootstrap":
				a := configurationEditAPIFixture(t, s)
				a.bootstrapConfig = nil
				if _, err := a.configurationEditBackup(); !errors.Is(err, errConfigurationBeforeEdit) {
					t.Fatal("fell back to mutable runtime config", err)
				}
			}
			for _, table := range []string{"v3_configuration_backups", "v3_configuration_backup_parts", "v3_requests", "v3_audit"} {
				if tableCount(t, s, table) != 0 {
					t.Fatal("rejected save left artifacts", table)
				}
			}
			var version int64
			if err := s.DB.QueryRow(`SELECT version FROM v3_nodes WHERE id='saved-node'`).Scan(&version); err != nil || version != 1 {
				t.Fatal("failed save changed node", version, err)
			}
		})
	}
}
