package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

// The parent reservation exists before any child deployment is materialized.
// These checks deliberately do not run the batch worker or a remote adapter.
func monitoringInterlockRootInput(t *testing.T, f *monitoringApplicationFixture) []rootRotationNodeInput {
	t.Helper()
	dir := filepath.Join(privateTestDir(t), "collector")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// The baseline runner clears transient bundle keys; reload this isolated
	// fixture's persistent collector key instead of reusing its zeroed slice.
	bundle := nodepki.Bundle{}
	for path, dest := range map[string]*[]byte{f.c.Collector.CAFile: &bundle.CA, f.c.Collector.CertFile: &bundle.Certificate, f.c.Collector.KeyFile: &bundle.Key} {
		var err error
		*dest, err = os.ReadFile(path)
		if err != nil {
			t.Fatal("read isolated collector identity", err)
		}
	}
	defer clear(bundle.Key)
	ca := filepath.Join(dir, "ca.crt")
	localWrite(t, ca, bundle.CA)
	f.c.Collector.IdentityFile = filepath.Join(dir, "active.pem")
	f.c.Collector.CertFile, f.c.Collector.KeyFile = "", ""
	if _, err := nodepki.PublishIdentity(context.Background(), ca, f.c.Collector.IdentityFile, nodepki.Collector, "collector-a", "", bundle, time.Now()); err != nil {
		t.Fatal("publish isolated collector identity", err)
	}
	if _, err := nodepki.NewPersistentFileTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, f.c.Collector.RevocationStateDirectory, time.Now()); err != nil {
		t.Fatal(err)
	}
	b, err := f.s.readNodeIdentity(context.Background(), f.c, f.t.vault, f.in.IdentityID, f.in.Node)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	return []rootRotationNodeInput{{Node: f.in.Node, Credential: f.in.Credential, Certificate: b.Certificate}}
}

func monitoringInterlockState(t *testing.T, s *Store) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range []string{
		"v3_root_rotations", "v3_root_identity_issuances", "v3_pki_authorities", "v3_node_certificates",
		"v3_node_history_retirements", "v3_node_runtime", "v3_node_configurations", "v3_nodes",
		"v3_monitoring_applications", "v3_monitoring_application_nodes", "v3_deployment_jobs", "v3_audit",
	} {
		var raw []byte
		if err := s.DB.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM ` + table + ` r`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		out[table] = digest(raw)
	}
	return out
}

func requireMonitoringInterlockState(t *testing.T, s *Store, before map[string]string) {
	t.Helper()
	for table, after := range monitoringInterlockState(t, s) {
		if before[table] != after {
			t.Fatalf("rejected operation changed %s", table)
		}
	}
}

func requireMonitoringInterlockParentOnly(t *testing.T, f monitoringApplicationFixture, p monitoringApplication) {
	t.Helper()
	var reserved bool
	var children int
	if err := f.s.DB.QueryRow(`SELECT bool_and(reserved),count(child) FROM v3_monitoring_application_nodes WHERE application=$1`, p.ID).Scan(&reserved, &children); err != nil || !reserved || children != 0 {
		t.Fatal("fixture must reserve the selected node without materializing a child", err)
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 1 {
		t.Fatal("only the completed baseline deployment should exist")
	}
}

func TestMonitoringInterlocksParentReservationBlocksRootRotation(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	in := monitoringInterlockRootInput(t, &f)
	p := f.confirmed(t)
	requireMonitoringInterlockParentOnly(t, f, p)
	before := monitoringInterlockState(t, f.s)
	if _, err := f.s.prepareRootRotation(context.Background(), f.c, f.t.vault, "admin", "monitoring-blocked-root", f.t.release, in); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("root rotation ignored the parent-only reservation", err)
	}
	requireMonitoringInterlockState(t, f.s, before)
	if _, err := os.Stat(nodepki.SuccessorAuthorityDirectory(f.c.NodePKI.AuthorityDirectory)); !os.IsNotExist(err) {
		t.Fatal("rejected root preparation created a successor authority")
	}
}

func TestMonitoringInterlocksParentReservationBlocksHistoryRetirement(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_configurations SELECT 'monitoring-interlock-history',node,version,name,endpoint,'retired.example.test',false,mode,shard,config FROM v3_node_configurations WHERE id=(SELECT snapshot FROM v3_node_runtime WHERE node=$1)`, f.in.Node)
	in := nodeHistoryRetirementInput{Node: f.in.Node, Expected: 1, Snapshots: []string{"monitoring-interlock-history"}}
	preview, err := f.s.previewNodeHistoryRetirement(ctx, "admin", in)
	if err != nil {
		t.Fatal("unreserved history should be eligible for an explicit retirement preview", err)
	}
	in.Confirm, in.PreviewSHA256 = true, preview.PreviewSHA256
	p := f.confirmed(t)
	requireMonitoringInterlockParentOnly(t, f, p)
	before := monitoringInterlockState(t, f.s)
	if _, err := f.s.previewNodeHistoryRetirement(ctx, "admin", in); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("history preview ignored the parent-only reservation", err)
	}
	if _, err := f.s.retireNodeHistory(ctx, "admin", "monitoring-blocked-retirement", in); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("previously authorized history retirement ignored the new reservation", err)
	}
	requireMonitoringInterlockState(t, f.s, before)
}

func TestMonitoringInterlocksRootTaskBlocksBatchPreviewAndConfirmation(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	ctx := context.Background()
	in := monitoringInterlockRootInput(t, &f)
	p, token := f.preview(t)
	if _, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "root-before-monitoring", f.t.release, in); err != nil {
		t.Fatal("valid unreserved root preparation failed", err)
	}
	before := monitoringInterlockState(t, f.s)
	if _, _, err := f.s.previewMonitoringApplication(ctx, f.t, "admin", "monitoring-after-root", f.request); !errors.Is(err, errRootRotationTask) {
		t.Fatal("active root task allowed a new monitoring preview", err)
	}
	if _, err := f.s.confirmMonitoringApplication(ctx, f.t, "admin", "monitoring-confirm-after-root", p.ID, token); !errors.Is(err, errRootRotationTask) {
		t.Fatal("active root task allowed a previously previewed monitoring batch", err)
	}
	requireMonitoringInterlockState(t, f.s, before)
}
