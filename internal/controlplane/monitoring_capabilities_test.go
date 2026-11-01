package controlplane

import (
	"context"
	"testing"
)

func TestMonitoringCapabilitiesRequireMatchingLiveHostWorkers(t *testing.T) {
	f := webDeployFixture(t)
	ctx := context.Background()
	availability := func() featureAvailability {
		return f.api.monitoringApplicationAvailability(ctx, f.api.deploymentAvailability(ctx))
	}
	if got := availability(); got.Available || got.Reason == "" {
		t.Fatal("missing monitoring worker reported ready", got)
	}
	for _, tc := range []struct{ name, change string }{
		{"stale", "heartbeat=clock_timestamp()-interval '30 seconds'"},
		{"wrong_manifest", "details=jsonb_set(details,'{manifest}','\"different\"')"},
		{"wrong_vault", "details=jsonb_set(details,'{vault}','\"different\"')"},
		{"issuer_missing", "details=jsonb_set(details,'{issuer}','false')"},
		{"rules_missing", "details=jsonb_set(details,'{rules}','false')"},
		{"error", "error='unavailable'"},
		{"different_instance", "instance='other-host'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustHistoryExec(t, f.s.DB, `DELETE FROM v3_role_status WHERE role='monitoring-applications'`)
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_role_status(role,instance,heartbeat,details) VALUES('monitoring-applications',$1,clock_timestamp(),jsonb_build_object('manifest',$2::text,'vault',$3::text,'issuer',true,'rules',true))`, f.worker.instance, f.t.release.SHA256(), f.t.vault.active)
			if !availability().Available {
				t.Fatal("matching healthy workers not ready")
			}
			mustHistoryExec(t, f.s.DB, `UPDATE v3_role_status SET `+tc.change+` WHERE role='monitoring-applications'`)
			if got := availability(); got.Available || got.Reason == "" {
				t.Fatal("invalid heartbeat reported ready", got)
			}
		})
	}
}
