package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSinglePKIMaintenanceStatusUsesVerifiedPublicEvidence(t *testing.T) {
	store := testStore(t)
	spec, _, _ := prepareSinglePKIFixture(t)
	ctx := context.Background()
	if err := recordSinglePKIMaintenance(ctx, store, spec, nodeRenewalSigningResult{Signed: 2}, nil); err != nil {
		t.Fatal(err)
	}
	var details []byte
	var reason string
	if err := store.DB.QueryRow(`SELECT error,details FROM v3_role_status WHERE role='pki-maintenance' AND instance=$1`, spec.Instance).Scan(&reason, &details); err != nil || reason != "" {
		t.Fatal("missing successful heartbeat", err)
	}
	var metadata map[string]any
	if json.Unmarshal(details, &metadata) != nil || metadata["collector_expires_at"] == nil || metadata["ca_expires_at"] == nil || metadata["signed"] != float64(2) {
		t.Fatal("missing verified expiry or counts")
	}
	if bytes.Contains(details, []byte("PRIVATE KEY")) || bytes.Contains(details, []byte(spec.Root)) {
		t.Fatal("private PKI metadata exposed")
	}
	if err := recordSinglePKIMaintenance(ctx, store, spec, nodeRenewalSigningResult{}, errors.New("private-dsn-password")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.dashboardSnapshot(ctx, dashboardSnapshot{}, 30)
	if err != nil || snapshot.Sections["certificates"].Error != "" {
		t.Fatal(err)
	}
	var section struct {
		Maintenance struct {
			Fresh    bool `json:"fresh"`
			HasError bool `json:"has_error"`
		}
	}
	if json.Unmarshal(snapshot.Sections["certificates"].Data, &section) != nil || !section.Maintenance.Fresh || !section.Maintenance.HasError || bytes.Contains(snapshot.Sections["certificates"].Data, []byte("private-dsn-password")) {
		t.Fatal("maintenance failure hidden or private error exposed")
	}
	mustHistoryExec(t, store.DB, `UPDATE v3_role_status SET heartbeat=clock_timestamp()-interval '71 minutes' WHERE role='pki-maintenance'`)
	snapshot, _ = store.dashboardSnapshot(ctx, dashboardSnapshot{}, 30)
	if json.Unmarshal(snapshot.Sections["certificates"].Data, &section) != nil || section.Maintenance.Fresh {
		t.Fatal("expired maintenance heartbeat presented as fresh")
	}
	// A missing identity is not a healthy current observation and cannot
	// overwrite the previous heartbeat with invented expiry metadata.
	if err := os.Remove(filepath.Join(spec.Root, "collector-pki", "collector.pem")); err != nil {
		t.Fatal(err)
	}
	if err := recordSinglePKIMaintenance(ctx, store, spec, nodeRenewalSigningResult{}, nil); err == nil {
		t.Fatal("missing identity reported healthy")
	}
	snapshot, _ = store.dashboardSnapshot(ctx, dashboardSnapshot{}, 30)
	if json.Unmarshal(snapshot.Sections["certificates"].Data, &section) != nil || section.Maintenance.Fresh {
		t.Fatal("failed observation advanced heartbeat")
	}
}

func TestSinglePKIMaintenanceStatusIsNotRestoredAsLiveEvidence(t *testing.T) {
	store := testStore(t)
	spec, _, _ := prepareSinglePKIFixture(t)
	ctx := context.Background()
	if err := recordSinglePKIMaintenance(ctx, store, spec, nodeRenewalSigningResult{}, nil); err != nil {
		t.Fatal(err)
	}
	backup, err := store.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := target.DB.QueryRow(`SELECT count(*) FROM v3_role_status WHERE role='pki-maintenance'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("backup heartbeat certified current maintenance", err)
	}
	if err := recordSinglePKIMaintenance(ctx, target, spec, nodeRenewalSigningResult{}, nil); err != nil {
		t.Fatal("fresh observation could not republish", err)
	}
}
