package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"webscan/internal/common"
	"webscan/internal/nodeconfig"
)

// Internal lifecycle callers read the same decorated Node as the public API,
// then replace its private settings. Its public monitoring view is read-only.
func TestMonitoringCompatibilityTrustedSavePreservesCompletePrivateConfig(t *testing.T) {
	for _, source := range []string{"legacy", "inherited", "independent"} {
		t.Run(source, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			settings := nodeconfig.DefaultSettings()
			root := map[string]any{}
			if json.Unmarshal(common.JSON(settings), &root) != nil {
				t.Fatal("settings fixture")
			}
			root["private"] = map[string]any{"opaque": "isolated-preserved-value"}
			if source != "legacy" {
				root["monitoring_policy"] = map[string]string{"source": source, "rules_version": "3"}
			}
			n := nodeFixture("trusted-monitoring")
			n.Config = common.JSON(root)
			if e := s.PutNode(ctx, n, 0, 256); e != nil {
				t.Fatal(e)
			}
			active := runtimeNodeForTest(t, s, n.ID)
			scanned := publicMonitoringNode(t, s, n.ID)
			if scanned.Monitoring == nil {
				t.Fatal("fixture omitted decorated monitoring view")
			}
			settings.RetentionDays = 23
			settings.ProbeSeconds = 120
			settings.Resources.MemoryMiB = 512
			settings.Resources.GoMemoryMiB = 128
			settings.Transport.QueueMiB = 2048
			settings.Scan.YARA.TimeoutSeconds = 25
			settings.Scan.ClamAV.Enabled = true
			settings.Monitor.Roots = []string{"/srv/internal-new-root"}
			settings.Monitor.Extensions = []string{".js"}
			settings.Monitor.Reconciliation.IntervalHours = 19
			settings.Monitor.Reconciliation.Nice = 10
			settings.ProbeDirectory = "/srv/internal-new-root/.webscan-probe"
			if settings.Validate() != nil {
				t.Fatal("invalid updated fixture")
			}
			if json.Unmarshal(common.JSON(settings), &root) != nil {
				t.Fatal("updated settings fixture")
			}
			wanted := common.JSON(root)
			scanned.Config = wanted
			raw, e := s.SaveNode(ctx, "admin", "trusted-full-config", scanned, scanned.Version, 256)
			if e != nil {
				t.Fatal("trusted save", e)
			}
			saved := publicMonitoringNode(t, s, n.ID)
			if saved.Version != 2 || !configurationJSONEqual(saved.Config, wanted) {
				t.Fatal("public decoration overwrote trusted private configuration")
			}
			got, e := nodeRuntimeSettings(saved.Config)
			if e != nil || !reflect.DeepEqual(got, settings) {
				t.Fatal("trusted settings were rewritten", e)
			}
			if current := runtimeNodeForTest(t, s, n.ID); !reflect.DeepEqual(current, active) {
				t.Fatal("trusted save prematurely published runtime")
			}
			again, e := s.SaveNode(ctx, "admin", "trusted-full-config", scanned, scanned.Version, 256)
			if e != nil || !configurationJSONEqual(raw, again) || publicMonitoringNode(t, s, n.ID).Version != 2 {
				t.Fatal("trusted-save retry changed configuration", e)
			}
		})
	}
}

// These rows deliberately have no usable cryptographic plan or remote target.
// They exercise only the persistent reservation gate, never a worker runtime.
func reserveMonitoringCompatibilityNode(t *testing.T, s *Store, node string) string {
	t.Helper()
	id := token()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_monitoring_applications(id,username,account_revision,controller,controller_revision,global_generation,manifest_sha256,release,status,plan_digest,key_id,nonce,ciphertext,proof,token_hash) VALUES($1,'admin',1,'admin',1,'0',$2,'v3.1.0','paused',$2,'isolated-test',$3,$3,'isolated-unexecuted',$2)`, id, digest([]byte("isolated-monitoring-reservation")), []byte{1})
	mustHistoryExec(t, s.DB, `INSERT INTO v3_monitoring_application_nodes(application,node,ordinal,batch_index,reserved) VALUES($1,$2,0,0,true)`, id, node)
	return id
}

func TestMonitoringCompatibilityFullRestoreRevalidationHonorsReservation(t *testing.T) {
	s, f, stage := configurationRevisionFixture(t, false)
	if _, e := revalidateConfigurationStageForTest(t, s, f.v, f.c, stage.ID); e != nil {
		t.Fatal("unreserved fixture cannot revalidate", e)
	}
	parent := reserveMonitoringCompatibilityNode(t, s, "revision-node")
	nodes := publicMonitoringRows(t, s, "v3_nodes", "id")
	backups := tableCount(t, s, "v3_configuration_backups")
	if _, e := revalidateConfigurationStageForTest(t, s, f.v, f.c, stage.ID); !errors.Is(e, ErrDeploymentBusy) {
		t.Fatal("full restore ignored reserved rule application", e)
	}
	if nodes != publicMonitoringRows(t, s, "v3_nodes", "id") || backups != tableCount(t, s, "v3_configuration_backups") {
		t.Fatal("rejected revalidation changed saved configuration")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_monitoring_application_nodes SET reserved=false WHERE application=$1`, parent)
	if _, e := revalidateConfigurationStageForTest(t, s, f.v, f.c, stage.ID); e != nil {
		t.Fatal("released reservation still blocks restore", e)
	}
}

func TestMonitoringCompatibilityFullRestoreQueueHonorsReservation(t *testing.T) {
	s, f, stage, revision := commitSavedFixture(t)
	ctx := context.Background()
	raw, e := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "commit-before-reservation", stage.ID, revision.Generation)
	_ = savedReceipt(t, raw, e)
	parent := reserveMonitoringCompatibilityNode(t, s, "revision-node")
	before := settingsStateForTest(t, s)
	if _, e = s.queueConfigurationApplication(ctx, f.v, f.c, "admin", "queue-after-reservation", stage.ID, revision.Generation); !errors.Is(e, ErrDeploymentBusy) {
		t.Fatal("full configuration queue bypassed monitoring reservation", e)
	}
	if tableCount(t, s, "v3_configuration_applications") != 0 || !configurationJSONEqual(settingsStateForTest(t, s).Desired, before.Desired) {
		t.Fatal("rejected queue changed settings or started work")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_monitoring_application_nodes SET reserved=false WHERE application=$1`, parent)
	if raw, e = s.queueConfigurationApplication(ctx, f.v, f.c, "admin", "queue-after-reservation", stage.ID, revision.Generation); e != nil {
		t.Fatal("same-key queue retry failed after reservation released", e)
	}
	_ = applicationReceipt(t, raw, e)
}
