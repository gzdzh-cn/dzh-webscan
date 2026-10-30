//go:build linux

package agent

import (
	"context"
	"path/filepath"
	"testing"

	"webscan/internal/common"
	"webscan/internal/pull"
)

func TestIdentityRenewalRequiresManagedTLSAndPersistentPolicy(t *testing.T) {
	for _, scenario := range []string{"no-listener", "no-tls", "no-state", "no-revocation", "no-identity", "unmanaged-path", "split-key"} {
		t.Run(scenario, func(t *testing.T) {
			a, _ := newTestAgent(t)
			var err error
			a.Pull, err = pull.New(a.DB, "node-a", "v3-test", &a.writeMu)
			if err != nil {
				t.Fatal(err)
			}
			a.C["metrics"] = common.Map{"port": 19100, "tls_enabled": true, "identity_file": filepath.Join(a.Data, "pki-identity", "active.pem")}
			a.C["pull"] = common.Map{"identity_renewal": true, "revocation_file": "/not-used/seed.crl", "revocation_state_directory": filepath.Join(a.Data, "trust")}
			pc, metrics := common.M(a.C["pull"]), common.M(a.C["metrics"])
			switch scenario {
			case "no-listener":
				a.Pull = nil
			case "no-tls":
				metrics["tls_enabled"] = false
			case "no-state":
				delete(pc, "revocation_state_directory")
			case "no-revocation":
				delete(pc, "revocation_file")
			case "no-identity":
				delete(metrics, "identity_file")
			case "unmanaged-path":
				metrics["identity_file"] = filepath.Join(a.Data, "elsewhere.pem")
			case "split-key":
				metrics["cert_file"] = "/not-used/cert.pem"
			}
			if err := a.startMetrics(context.Background()); err == nil {
				t.Fatal("unsafe renewal configuration started a listener")
			}
		})
	}
}
