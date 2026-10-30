package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func preparedPreviewFixture(t *testing.T) (provisioningFixture, DeploymentRequest, DeploymentPreview) {
	t.Helper()
	f := localProvisioningFixture(t)
	in, err := f.s.prepareLocalDeployment(context.Background(), f.c, f.t, f.in)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.s.previewLocalDeployment(context.Background(), f.c, f.t, "admin", in)
	if err != nil {
		t.Fatal(err)
	}
	return f, in, p
}

func TestDeploymentPreviewBoundTokenAndAtomicReplay(t *testing.T) {
	f, in, p := preparedPreviewFixture(t)
	ctx := context.Background()
	if p.Node != in.Node || p.Target.Mode != "native" || p.Target.Release != in.Release || p.Target.SHA256 != in.SHA256 || p.Version != 1 || p.Current != nil || p.Comparison != "unknown" || time.Until(p.ExpiresAt) < 9*time.Minute || time.Until(p.ExpiresAt) > 10*time.Minute {
		t.Fatal("wrong preview", p)
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 0 || tableCount(t, f.s, "v3_workers") != 0 {
		t.Fatal("preview started deployment")
	}
	var stored string
	if err := f.s.DB.QueryRow("SELECT token_hash FROM v3_deployment_previews").Scan(&stored); err != nil || stored != digest([]byte(p.Token)) {
		t.Fatal("stored bearer token", err)
	}
	raw, err := f.s.confirmLocalDeployment(ctx, f.c, f.t, "admin", "confirmed-install", p.Token)
	if err != nil {
		t.Fatal(err)
	}
	// Receipts remain retrievable after timeout. They cannot create another job.
	mustHistoryExec(t, f.s.DB, "UPDATE v3_deployment_previews SET expires_at=clock_timestamp()-interval '1 second'")
	replay, err := f.s.confirmLocalDeployment(ctx, f.c, f.t, "admin", "confirmed-install", p.Token)
	if err != nil || !sameProvisioningResponse(raw, replay) {
		t.Fatal("lost idempotent receipt", err)
	}
	if _, err = f.s.confirmLocalDeployment(ctx, f.c, f.t, "admin", "different-key", p.Token); !errors.Is(err, ErrDeploymentPreview) {
		t.Fatal("token reused", err)
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 1 {
		t.Fatal("duplicate job")
	}
	var response struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	job := reloadDeployment(t, f.s, response.ID)
	if job.Plan.Request.RuntimeArtifact == nil || job.Plan.Request.RuntimeArtifact.SHA256 != in.RuntimeArtifact.SHA256 || job.Plan.Request.Credential != in.Credential || job.NodeVersion != 1 {
		t.Fatal("confirmation changed immutable plan")
	}
	for _, table := range []string{"v3_deployment_previews", "v3_deployment_jobs", "v3_deployment_logs", "v3_requests", "v3_audit"} {
		rows, err := f.s.DB.Query("SELECT row_to_json(t)::text FROM " + table + " t")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var line string
			if err = rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(line, p.Token) || strings.Contains(line, "PRIVATE KEY") {
				t.Fatal("secret leaked into " + table)
			}
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
}

func TestDeploymentPreviewRejectsChangedConditions(t *testing.T) {
	for _, name := range []string{"expired", "account-revision", "demoted", "other-account", "node-version", "node-config", "node-disabled", "applied-version", "credential-revision", "tampered-material", "missing-material", "new-crl", "request-digest", "intervening-task", "busy-task", "migration", "executor-disabled"} {
		t.Run(name, func(t *testing.T) {
			f, in, p := preparedPreviewFixture(t)
			user := "admin"
			switch name {
			case "expired":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_deployment_previews SET expires_at=clock_timestamp()-interval '1 second'")
			case "account-revision":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'")
			case "demoted":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_accounts SET role='viewer' WHERE username='admin'")
			case "other-account":
				mustHistoryExec(t, f.s.DB, "INSERT INTO v3_accounts(username,password_hash,role) VALUES('second-admin','fixture','admin')")
				user = "second-admin"
			case "node-version":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_nodes SET version=version+1")
			case "node-config":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET config='{"probe_seconds":120}'`)
			case "node-disabled":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_nodes SET enabled=false")
			case "applied-version":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_nodes SET applied_version=1")
			case "credential-revision":
				cred, err := f.s.ReadCredential(context.Background(), f.t.vault, in.Credential, in.Node)
				if err != nil {
					t.Fatal(err)
				}
				key, nonce, sealed, err := f.t.vault.seal(in.Credential, in.Node, 2, cred)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.s.DB, "UPDATE v3_credentials SET revision=2,key_id=$1,nonce=$2,ciphertext=$3 WHERE id=$4", key, nonce, sealed, in.Credential)
			case "tampered-material", "missing-material":
				path := filepath.Join(f.c.Executor.ConfigurationDirectory, in.RuntimeArtifact.SHA256, "node.json")
				var err error
				if name == "missing-material" {
					err = os.Remove(path)
				} else {
					err = os.WriteFile(path, []byte("changed"), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "new-crl":
				crl, err := f.ca.Revoke(f.crl, nil, time.Now().UTC().Truncate(time.Second), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(f.c.Collector.RevocationFile, crl, 0600); err != nil {
					t.Fatal(err)
				}
			case "request-digest":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_deployment_previews SET request=jsonb_set(request,'{expected_version}','2')")
			case "intervening-task", "busy-task":
				job := createDeployment(t, f.s, in, "intervening-install")
				if name == "intervening-task" {
					mustHistoryExec(t, f.s.DB, "UPDATE v3_deployment_jobs SET status='failed',finished_at=clock_timestamp() WHERE id=$1", job.ID)
				}
			case "migration":
				mustHistoryExec(t, f.s.DB, "INSERT INTO v3_migration_domains(domain,source) VALUES('fixture',$1)", strings.Repeat("a", 64))
			case "executor-disabled":
				f.c.Executor.Enabled = false
			}
			before := tableCount(t, f.s, "v3_deployment_jobs")
			if _, err := f.s.confirmLocalDeployment(context.Background(), f.c, f.t, user, "reject-confirmation", p.Token); err == nil {
				t.Fatal("changed condition accepted")
			}
			if tableCount(t, f.s, "v3_deployment_jobs") != before {
				t.Fatal("failed confirmation queued task")
			}
			var consumed bool
			if err := f.s.DB.QueryRow("SELECT job IS NOT NULL FROM v3_deployment_previews").Scan(&consumed); err != nil || consumed {
				t.Fatal("failed confirmation consumed preview", err)
			}
			var receipts int
			if err := f.s.DB.QueryRow("SELECT count(*) FROM v3_requests WHERE key='reject-confirmation'").Scan(&receipts); err != nil || receipts != 0 {
				t.Fatal("failed confirmation committed receipt", err)
			}
		})
	}
}

func TestDeploymentPreviewReplayRevokedWithAccount(t *testing.T) {
	for _, condition := range []string{"revision", "role"} {
		t.Run(condition, func(t *testing.T) {
			f, _, p := preparedPreviewFixture(t)
			if _, err := f.s.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "once", p.Token); err != nil {
				t.Fatal(err)
			}
			if condition == "revision" {
				mustHistoryExec(t, f.s.DB, "UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'")
			} else {
				mustHistoryExec(t, f.s.DB, "UPDATE v3_accounts SET role='viewer' WHERE username='admin'")
			}
			if _, err := f.s.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "once", p.Token); !errors.Is(err, ErrDeploymentPreview) {
				t.Fatal("revoked account replayed", err)
			}
		})
	}
}

func TestDeploymentPreviewConcurrentConfirmation(t *testing.T) {
	for _, sameKey := range []bool{true, false} {
		t.Run(map[bool]string{true: "same-key", false: "different-keys"}[sameKey], func(t *testing.T) {
			f, _, p := preparedPreviewFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var wg sync.WaitGroup
			results := make(chan error, 8)
			for i := range 8 {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					key := "confirmed"
					if !sameKey {
						key += "-" + string(rune('a'+i))
					}
					_, err := f.s.confirmLocalDeployment(ctx, f.c, f.t, "admin", key, p.Token)
					results <- err
				}(i)
			}
			wg.Wait()
			close(results)
			won := 0
			for err := range results {
				if err == nil {
					won++
				} else if !errors.Is(err, ErrDeploymentPreview) {
					t.Fatal(err)
				}
			}
			if sameKey && won != 8 || !sameKey && won != 1 || tableCount(t, f.s, "v3_deployment_jobs") != 1 {
				t.Fatal("confirmation race", won)
			}
		})
	}
}

func TestDeploymentPreviewAuditFailureRollsBackAndRetrySucceeds(t *testing.T) {
	f, _, p := preparedPreviewFixture(t)
	mustHistoryExec(t, f.s.DB, `CREATE FUNCTION reject_preview_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='confirm-deployment' THEN RAISE EXCEPTION 'isolated audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_preview_audit BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION reject_preview_audit()`)
	if _, err := f.s.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "retryable", p.Token); err == nil {
		t.Fatal("audit failure ignored")
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 0 || tableCount(t, f.s, "v3_deployment_logs") != 0 {
		t.Fatal("partial task committed")
	}
	mustHistoryExec(t, f.s.DB, "DROP TRIGGER reject_preview_audit ON v3_audit;DROP FUNCTION reject_preview_audit()")
	if _, err := f.s.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "retryable", p.Token); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentPreviewUnrelatedTelemetryDoesNotInvalidate(t *testing.T) {
	f, _, p := preparedPreviewFixture(t)
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_status(node,sampled_at,metrics) VALUES('node-a',1,'{"cpu":1}')`)
	if err := f.s.PutNode(context.Background(), nodeFixture("unrelated"), 0, 256); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "unrelated-activity", p.Token); err != nil {
		t.Fatal("ordinary telemetry invalidated preview", err)
	}
}

// Synthetic DB baselines exercise preview policy only. They are not evidence
// that an SSH installer or a remote service completed any lifecycle phase.
func previewBaseline(t *testing.T, f provisioningFixture, in DeploymentRequest, release, sum, mode string) {
	t.Helper()
	in.Release, in.SHA256 = release, sum
	job := createDeployment(t, f.s, in, "synthetic-baseline")
	plan := job.Plan
	plan.Node.Mode = mode
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var canonical []byte
	if err = f.s.DB.QueryRow("SELECT $1::jsonb", raw).Scan(&canonical); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, "UPDATE v3_deployment_jobs SET plan=$2,plan_digest=$3,status='succeeded',step=6,finished_at=clock_timestamp() WHERE id=$1", job.ID, canonical, digest(canonical))
	mustHistoryExec(t, f.s.DB, "UPDATE v3_nodes SET applied_version=version")
}

func TestDeploymentPreviewUpgradePolicy(t *testing.T) {
	for _, name := range []string{"same", "downgrade", "mode-change", "newer", "missing-baseline", "same-version-new-content"} {
		t.Run(name, func(t *testing.T) {
			f := localProvisioningFixture(t)
			in, err := f.s.prepareLocalDeployment(context.Background(), f.c, f.t, f.in)
			if err != nil {
				t.Fatal(err)
			}
			oldRelease, oldSum, mode := in.Release, in.SHA256, "native"
			switch name {
			case "downgrade":
				oldRelease = "v4.0.0"
			case "mode-change":
				mode = "docker"
			case "newer":
				oldRelease = "v2.0.46"
			case "same-version-new-content":
				oldSum = strings.Repeat("b", 64)
			}
			if name == "missing-baseline" {
				mustHistoryExec(t, f.s.DB, "UPDATE v3_nodes SET applied_version=1")
			} else {
				previewBaseline(t, f, in, oldRelease, oldSum, mode)
			}
			in.Kind = "upgrade"
			p, err := f.s.previewLocalDeployment(context.Background(), f.c, f.t, "admin", in)
			switch name {
			case "same":
				if !errors.Is(err, ErrDeploymentUnnecessary) {
					t.Fatal(err)
				}
			case "downgrade":
				if !errors.Is(err, ErrDeploymentDowngrade) {
					t.Fatal(err)
				}
			case "mode-change":
				if !errors.Is(err, ErrDeploymentModeMigration) {
					t.Fatal(err)
				}
			case "newer":
				if err != nil || p.Comparison != "newer" || p.Current == nil {
					t.Fatal(p, err)
				}
			case "missing-baseline":
				if err != nil || p.Comparison != "unknown" || p.Current != nil {
					t.Fatal(p, err)
				}
			case "same-version-new-content":
				if err != nil || p.Comparison != "same-version" || p.Current == nil {
					t.Fatal(p, err)
				}
			}
		})
	}
}

func TestDeploymentPreviewSemverComparison(t *testing.T) {
	for _, c := range []struct {
		a, b  string
		order int
		known bool
	}{
		{"v3.0.0", "v2.9.99", 1, true}, {"v3.0.0", "v3.0.0-rc.1", 1, true},
		{"v3.0.0-alpha.9", "v3.0.0-alpha.10", -1, true}, {"v3.0.0-alpha", "v3.0.0-alpha.1", -1, true},
		{"v3.0.0-alpha.1", "v3.0.0-alpha.a", -1, true}, {"v3.0.0-beta", "v3.0.0-alpha", 1, true},
		{"v3.0.0", "v3.0.0", 0, true}, {"v999999999999999999999.0.0", "v4.0.0", 1, true},
		{"v03.0.0", "v3.0.0", 0, false}, {"v3.0.0-rc.01", "v3.0.0", 0, false},
		{"v3.0.0-..", "v3.0.0", 0, false}, {"v3.0", "v3.0.0", 0, false},
	} {
		if got, known := compareDeploymentRelease(c.a, c.b); got != c.order || known != c.known {
			t.Fatalf("%s %s: %d %v", c.a, c.b, got, known)
		}
	}
}

func TestDeploymentPreviewConcurrentLimitAndExpiredCollection(t *testing.T) {
	f, in, p := preparedPreviewFixture(t)
	// Populate valid metadata, not random unsigned deployment requests.
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_previews(token_hash,username,account_revision,node,request,request_digest,state_digest,credential_revision) SELECT md5(i::text)||md5(i::text),p.username,p.account_revision,p.node,p.request,p.request_digest,p.state_digest,p.credential_revision FROM v3_deployment_previews p CROSS JOIN generate_series(1,98) i WHERE p.token_hash=$1`, digest([]byte(p.Token)))
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.s.previewLocalDeployment(context.Background(), f.c, f.t, "admin", in)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	won := 0
	for err := range results {
		if err == nil {
			won++
		} else if !strings.Contains(err.Error(), "预览过多") {
			t.Fatal(err)
		}
	}
	if won != 1 || tableCount(t, f.s, "v3_deployment_previews") != 100 {
		t.Fatal("preview limit race", won)
	}
	// Consumed capabilities must survive expiry cleanup for request replay.
	if _, err := f.s.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "retained", p.Token); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, "UPDATE v3_deployment_jobs SET status='failed',finished_at=clock_timestamp()")
	mustHistoryExec(t, f.s.DB, "UPDATE v3_deployment_previews SET expires_at=clock_timestamp()-interval '1 second'")
	if _, err := f.s.previewLocalDeployment(context.Background(), f.c, f.t, "admin", in); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, f.s, "v3_deployment_previews") != 2 {
		t.Fatal("expired unused previews not collected or consumed receipt removed")
	}
	if _, err := f.s.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "retained", p.Token); err != nil {
		t.Fatal("collection lost replay", err)
	}
}

func TestDeploymentPreviewExpiryDuringNodeLockWait(t *testing.T) {
	f, _, p := preparedPreviewFixture(t)
	tx, err := f.s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec("SELECT id FROM v3_nodes WHERE id='node-a' FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, "UPDATE v3_deployment_previews SET expires_at=clock_timestamp()+interval '2 seconds'")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := f.s.confirmLocalDeployment(ctx, f.c, f.t, "admin", "lock-expiry", p.Token)
		result <- err
	}()
	// Wait for the real row lock, then wait on database time rather than
	// relying on a scheduler delay to claim the request crossed its deadline.
	locked := false
	for i := 0; i < 100; i++ {
		if err = f.s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id,name,endpoint,%FOR UPDATE%')`).Scan(&locked); err != nil {
			t.Fatal(err)
		}
		if locked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !locked {
		t.Fatal("confirmation did not wait on node")
	}
	for {
		var expired bool
		if err = f.s.DB.QueryRow("SELECT expires_at<=clock_timestamp() FROM v3_deployment_previews").Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, ErrDeploymentPreview) {
		t.Fatal("lock wait extended preview lifetime", err)
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 0 {
		t.Fatal("expired preview created task")
	}
}

func TestDeploymentPreviewBackupRestoreAndSchema12Upgrade(t *testing.T) {
	t.Run("pending-and-consumed", func(t *testing.T) {
		f, in, p := preparedPreviewFixture(t)
		other, err := f.s.previewLocalDeployment(context.Background(), f.c, f.t, "admin", in)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := f.s.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "before-backup", p.Token)
		if err != nil {
			t.Fatal(err)
		}
		path, err := f.s.BackupPostgres(context.Background(), privateTestDir(t))
		if err != nil {
			t.Fatal(err)
		}
		restored := emptyTestStore(t)
		if err = restored.RestorePostgres(context.Background(), path); err != nil {
			t.Fatal(err)
		}
		replay, err := restored.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "before-backup", p.Token)
		if err != nil || !sameProvisioningResponse(receipt, replay) {
			t.Fatal("lost consumed preview/receipt", err)
		}
		if _, err = restored.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "other-preview", other.Token); !errors.Is(err, ErrDeploymentBusy) {
			t.Fatal("restored preview ignored task", err)
		}
	})
	t.Run("backup-required", func(t *testing.T) {
		f := localProvisioningFixture(t)
		dropConfigurationBackupsForTest(t, f.s)
		mustHistoryExec(t, f.s.DB, "DROP TABLE v3_deployment_previews;DROP INDEX v3_deployment_node_history;DELETE FROM v3_schema WHERE version=13")
		if err := f.s.Migrate(context.Background()); err == nil {
			t.Fatal("migration without backup")
		}
		bad := filepath.Join(privateTestDir(t), "file")
		if err := os.WriteFile(bad, []byte("file"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := f.s.Upgrade(context.Background(), bad); err == nil {
			t.Fatal("backup failure ignored")
		}
		if version, err := currentSchema(context.Background(), f.s.DB); err != nil || version != 12 {
			t.Fatal(version, err)
		}
		dir := privateTestDir(t)
		if err := f.s.Upgrade(context.Background(), dir); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatal("missing migration backup", err)
		}
		header, err := inspectPGBackup(filepath.Join(dir, entries[0].Name()))
		if err != nil || header.Version != 12 {
			t.Fatal(header, err)
		}
		if version, err := currentSchema(context.Background(), f.s.DB); err != nil || version != SchemaVersion {
			t.Fatal(version, err)
		}
	})
}
