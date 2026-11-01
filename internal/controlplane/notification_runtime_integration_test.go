package controlplane

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Exercise real Serve workers rather than just a channel helper: adding a
// worker must neither deadlock shutdown nor disable business notifications
// when the optional administrator-test Vault has not been configured.
func TestNotificationRuntimeActualServeAllAndMissingOptionalVault(t *testing.T) {
	for _, withVault := range []bool{true, false} {
		name := "without-test-vault"
		if withVault {
			name = "all-workers"
		}
		t.Run(name, func(t *testing.T) {
			s, f := newSavedConfigurationStore(t)
			vm := httptest.NewServer(http.HandlerFunc(environmentMetrics))
			defer vm.Close()
			f.c.Metrics.QueryURL, f.c.Metrics.WriteURL = vm.URL, vm.URL
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			f.c.Central.Listen = l.Addr().String()
			l.Close()
			localWrite(t, f.c.Database.DSNFile, environmentDSN(t, s))
			if withVault {
				f.c.Executor.ApplicationsEnabled = true
			} else {
				f.c.DeploymentTrust = DeploymentTrustConfig{}
				f.c.Executor = ExecutorConfig{}
				f.c.NodePKI = NodePKIConfig{}
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- Serve(ctx, f.c, "all") }()
			stopped := false
			defer func() {
				cancel()
				if !stopped {
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("real workers did not drain")
					}
				}
			}()
			ready := false
			for until := time.Now().Add(10 * time.Second); time.Now().Before(until); {
				var business, tests int
				err = s.DB.QueryRow(`SELECT count(*) FILTER(WHERE role IN ('server-health','website-notifications') AND error=''),count(*) FILTER(WHERE role='notification-tests' AND ((error='')=$1)) FROM v3_role_status`, withVault).Scan(&business, &tests)
				if err != nil {
					t.Fatal(err)
				}
				if business == 2 && tests == 1 {
					ready = true
					break
				}
				select {
				case err := <-done:
					stopped = true
					t.Fatal("Serve exited before notifier readiness", err)
				case <-time.After(20 * time.Millisecond):
				}
			}
			if !ready {
				t.Fatal("optional test Vault blocked business notifier readiness")
			}
			cancel()
			select {
			case err = <-done:
				stopped = true
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Serve all shutdown deadlocked")
			}
		})
	}
}
