package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

func TestIdentityRecoveryReconcileBothSidesOfActivation(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, active := range []bool{false, true} {
			name := mode + "/before-activation"
			if active {
				name = mode + "/after-activation"
			}
			t.Run(name, func(t *testing.T) {
				f := signedHelperRecovery(t, mode, active)
				m := recoveryServiceMachine(t, f)
				oldRequest, err := nodepki.ParseNodeRecoveryRequest(f.in.Request)
				if err != nil {
					t.Fatal(err)
				}
				activePath := filepath.Join(f.w.managedDataDirectory(), "pki-identity", "active.pem")
				before, err := os.ReadFile(activePath)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(before)
				intent, err := nodepki.NewNodeRecoveryIntent(f.in.Intent.Node, f.in.Intent.AuthoritySHA256, f.in.Intent.CertificateSHA256, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				f.in.Operation, f.in.Intent, f.in.Request = "reconcile", intent, nil
				out, err := f.w.identityRecoveryWithHost(context.Background(), f.in, m.host)
				if err != nil || out.Operation != "reconcile" || out.Challenge != intent.Challenge || out.CertificateSHA256 != "" {
					t.Fatal("controlled reconciliation failed", err)
				}
				r, err := nodepki.ParseNodeRecoveryRequest(out.Request)
				if err != nil || r.Renewal.SHA256() != oldRequest.Renewal.SHA256() || active != (len(r.ContinuationCertificate) != 0) {
					t.Fatal("reconciliation changed CSR or wrong proof owner", err)
				}
				after, err := os.ReadFile(activePath)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("preparation changed active identity", err)
				}
				clear(after)
				if len(m.calls) != 0 {
					t.Fatal("reconciliation operated service manager", m.calls)
				}
				f.in.Operation, f.in.Request = "activate", out.Request
				if _, err := f.w.identityRecoveryWithHost(context.Background(), f.in, m.host); err != nil {
					t.Fatal("fresh activation/reconciliation failed", err)
				}
				f.in.Operation = "start"
				for i := 0; i < 2; i++ {
					out, err := f.w.identityRecoveryWithHost(context.Background(), f.in, m.host)
					if err != nil || out.CertificateSHA256 != sha(recoveryTestCertificate(t, f.in.Certificate).Raw) {
						t.Fatal("fresh startup/retry failed", err)
					}
				}
				starts := 0
				for _, call := range m.calls {
					if strings.Contains(call, " start ") {
						starts++
					}
				}
				if starts != 1 {
					t.Fatal("startup retry repeated service operation", starts)
				}
			})
		}
	}
}

func TestIdentityRecoveryReconcileRejectsMalformedAndUnownedIdentity(t *testing.T) {
	for _, scenario := range []string{"missing-certificate", "unexpected-request", "wrong-receipt", "wrong-parent", "expired-intent"} {
		t.Run(scenario, func(t *testing.T) {
			f := signedHelperRecovery(t, "native", true)
			m := recoveryServiceMachine(t, f)
			intent, err := nodepki.NewNodeRecoveryIntent(f.in.Intent.Node, f.in.Intent.AuthoritySHA256, f.in.Intent.CertificateSHA256, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			oldRequest := f.in.Request
			f.in.Operation, f.in.Intent, f.in.Request = "reconcile", intent, nil
			switch scenario {
			case "missing-certificate":
				f.in.Certificate = nil
			case "unexpected-request":
				f.in.Request = oldRequest
			case "wrong-receipt":
				f.in.Certificate = f.expired.Certificate
			case "wrong-parent":
				f.in.Intent.CertificateSHA256 = strings.Repeat("a", 64)
			case "expired-intent":
				f.in.Intent.IssuedAt = time.Now().Add(-11 * time.Minute)
				f.in.Intent.ExpiresAt = time.Now().Add(-time.Minute)
			}
			raw, _ := json.Marshal(f.in)
			if scenario == "missing-certificate" || scenario == "unexpected-request" {
				if _, err := decodeIdentityRecovery(bytes.NewReader(raw)); err == nil {
					t.Fatal("malformed reconciliation accepted")
				}
			}
			if _, err := f.w.identityRecoveryWithHost(context.Background(), f.in, m.host); err == nil {
				t.Fatal("unowned reconciliation accepted")
			}
			if len(m.calls) != 0 {
				t.Fatal("rejected reconciliation changed services")
			}
		})
	}
}
