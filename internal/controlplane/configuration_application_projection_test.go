package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func projectionAPI(t *testing.T, s *Store, f configurationLocalFixture) (*API, func(string) *httptest.ResponseRecorder) {
	t.Helper()
	a := NewAPI(s, f.c)
	session := token()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,'admin',1,'projection-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(session)))
	return a, func(path string) *httptest.ResponseRecorder {
		return restoreAPICall(a, "GET", "configuration-restores"+path, "", session, "", "", true)
	}
}

func assertApplicationProjection(t *testing.T, call func(string) *httptest.ResponseRecorder, p privateConfigurationApplication, message string) {
	t.Helper()
	for _, path := range []string{"?limit=20", "/" + p.Stage} {
		w := call(path)
		if w.Code != 200 {
			t.Fatal("projection unavailable", path, w.Code, w.Body.String())
		}
		var stage configurationRestoreStage
		if strings.HasPrefix(path, "?") {
			var page struct {
				Items []configurationRestoreStage `json:"items"`
			}
			if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 {
				t.Fatal("wrong list")
			}
			stage = page.Items[0]
		} else {
			var detail configurationRestoreDetail
			if json.Unmarshal(w.Body.Bytes(), &detail) != nil || detail.CanContinue || detail.CanCancel || detail.Revision == nil {
				t.Fatal("read projection granted execution or lost revision")
			}
			stage = detail.Stage
			if detail.Revision.Message != stage.Message {
				t.Fatal("revision has stale application description")
			}
		}
		if stage.Status != "saved" || stage.Application == nil || stage.Application.ID != p.ID || stage.Application.Status != p.Status || stage.Application.Phase != p.phase() || stage.Application.LogCursor != p.LogCursor || !strings.Contains(stage.Message, message) {
			t.Fatalf("wrong stage projection: %+v", stage)
		}
		for _, private := range []string{p.planProof, p.sourceProof, p.stateProof, p.member, "private-dsn-password"} {
			if private != "" && strings.Contains(w.Body.String(), private) {
				t.Fatal("private application material escaped")
			}
		}
	}
}

func TestConfigurationApplicationProjectionFollowsJournalWithoutRewritingReceipts(t *testing.T) {
	s, f, public := applicationFixture(t)
	_, call := projectionAPI(t, s, f)
	ctx := context.Background()
	var original, after string
	if err := s.DB.QueryRow(`SELECT result::text FROM v3_configuration_restore_commits WHERE stage=$1`, public.Stage).Scan(&original); err != nil {
		t.Fatal(err)
	}
	p := privateApplicationForTest(t, s, f.v, public.ID)
	assertApplicationProjection(t, call, p, "尚未完成生效验收")
	p = claimApplicationForTest(t, s, f, "projection-worker")
	assertApplicationProjection(t, call, p, "尚未完成生效验收")
	if err := s.failConfigurationApplication(ctx, f.v, p, "environment-failed"); err != nil {
		t.Fatal(err)
	}
	p = privateApplicationForTest(t, s, f.v, public.ID)
	assertApplicationProjection(t, call, p, "未进入运行切换")
	if _, err := s.controlConfigurationApplication(ctx, f.v, "admin", "projection-cancel", p.ID, "cancel"); err != nil {
		t.Fatal(err)
	}
	p = privateApplicationForTest(t, s, f.v, public.ID)
	assertApplicationProjection(t, call, p, "应用已取消")
	if err := s.DB.QueryRow(`SELECT result::text FROM v3_configuration_restore_commits WHERE stage=$1`, public.Stage).Scan(&after); err != nil || original != after {
		t.Fatal("projection rewrote original receipt", err)
	}
	var receipt configurationSavedReceipt
	if json.Unmarshal([]byte(after), &receipt) != nil || receipt.Status != "saved_pending_application" {
		t.Fatal("saving receipt no longer immutable")
	}
}

// Real environment/settings/verification adapters and Serve(all), empty nodes.
// The metrics HTTP fixture is synthetic; this is not remote installation.
func TestConfigurationApplicationProjectionActualCompletionAndRollback(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		name := "complete"
		if rollback {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			s, f, runtime, id, _ := applicationVerificationFixture(t)
			_, call := projectionAPI(t, s, f)
			p := advanceVerificationFixture(t, s, f, runtime, "verify")
			ctx := context.Background()
			if rollback {
				if err := s.failConfigurationApplication(ctx, f.v, p, "verification-failed"); err != nil {
					t.Fatal(err)
				}
				assertApplicationProjection(t, call, privateApplicationForTest(t, s, f.v, id), "需继续或回退")
				if _, err := s.controlConfigurationApplication(ctx, f.v, "admin", "projection-rollback", id, "rollback"); err != nil {
					t.Fatal(err)
				}
				assertApplicationProjection(t, call, privateApplicationForTest(t, s, f.v, id), "回退中")
				for range configurationApplicationRollback {
					p = claimApplicationForTest(t, s, f, "projection-rollback-worker")
					if err := s.executeConfigurationApplication(ctx, f.v, p, runtime); err != nil {
						t.Fatal(err)
					}
				}
				assertApplicationProjection(t, call, privateApplicationForTest(t, s, f.v, id), "已回退并验收")
			} else {
				for _, phase := range []string{"verify", "finalize"} {
					if p.phase() != phase {
						t.Fatal("wrong phase")
					}
					if err := s.executeConfigurationApplication(ctx, f.v, p, runtime); err != nil {
						t.Fatal(err)
					}
					if phase == "verify" {
						p = claimApplicationForTest(t, s, f, "projection-final")
					}
				}
				assertApplicationProjection(t, call, privateApplicationForTest(t, s, f.v, id), "不代表当前配置版本")
			}
		})
	}
}

func TestConfigurationApplicationProjectionRejectsMissingKeysAndForgedState(t *testing.T) {
	s, f, p := applicationFixture(t)
	_, call := projectionAPI(t, s, f)
	key := f.c.DeploymentTrust.VaultKeyFile
	if err := os.Rename(key, key+".held"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Rename(key+".held", key) })
	for _, path := range []string{"?limit=20", "/" + p.Stage} {
		if w := call(path); w.Code != 503 || strings.Contains(w.Body.String(), f.f.root) {
			t.Fatal("missing key looked like pending/success or leaked path", w.Code)
		}
	}
	if err := os.Rename(key+".held", key); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET recovery_hold=true WHERE id=$1`, p.ID)
	assertApplicationProjection(t, call, privateApplicationForTest(t, s, f.v, p.ID), "应用任务已冻结")
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET status='succeeded',step=6,finished_at=clock_timestamp() WHERE id=$1`, p.ID)
	for _, path := range []string{"?limit=20", "/" + p.Stage} {
		if w := call(path); w.Code != 503 || !strings.Contains(w.Body.String(), "configuration_application_unverified") {
			t.Fatal("forged success escaped", w.Code, w.Body.String())
		}
	}
}

func TestConfigurationApplicationProjectionUsesOneSnapshotAndLazyKey(t *testing.T) {
	s, f, public := applicationFixture(t)
	tx, err := s.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stage, err := scanConfigurationStage(tx.QueryRow(`SELECT `+configurationStageColumns+` FROM v3_configuration_restore_stages WHERE id=$1`, public.Stage))
	if err != nil {
		t.Fatal(err)
	}
	_ = claimApplicationForTest(t, s, f, "projection-snapshot")
	items := []configurationRestoreStage{stage}
	calls := 0
	load := func() (*Vault, error) { calls++; return f.v, nil }
	if err = projectConfigurationApplicationsTx(context.Background(), tx, items, load); err != nil || calls != 1 || items[0].Application == nil || items[0].Application.Status != "queued" {
		t.Fatal("mixed MVCC snapshots", calls, err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	detail, err := s.configurationRestoreDetail(context.Background(), "admin", public.Stage, load)
	if err != nil || detail.Stage.Application.Status != "running" {
		t.Fatal("new read missed claim", err)
	}

	a, _, pending, sessions := restoreAPIFixture(t)
	a.Config.DeploymentTrust.VaultKeyFile = "/does-not-exist/projection.key"
	for _, path := range []string{"?limit=20", "/" + pending.ID} {
		w := restoreAPICall(a, "GET", "configuration-restores"+path, "", sessions["admin"], "", "", true)
		if w.Code != 200 || strings.Contains(w.Body.String(), `"application"`) {
			t.Fatal("non-application read required keys", w.Code, w.Body.String())
		}
	}
}
