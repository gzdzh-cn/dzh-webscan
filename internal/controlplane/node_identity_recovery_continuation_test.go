package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"webscan/internal/nodeops"
	"webscan/internal/nodepki"
)

func activatedRecoveryFixture(t *testing.T, credentials ...SSHCredential) (identityRecoveryFixture, string, signedNodeRenewal) {
	t.Helper()
	f := newIdentityRecoveryFixture(t, credentials...)
	admitRecoveryFixture(t, f)
	signed, err := f.s.signNodeIdentityRecovery(context.Background(), f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	floor := filepath.Join(filepath.Dir(f.identity), "continuation-trust")
	if _, err := nodepki.NewReceiverTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, floor, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.ActivateNodeRecovery(context.Background(), f.c.Collector.CAFile, f.identity, floor, f.request, f.job.Intent, signed.Certificate, time.Now()); err != nil {
		t.Fatal(err)
	}
	return f, floor, signed
}

func freshActivatedRecovery(t *testing.T, f identityRecoveryFixture) nodeIdentityRecoveryJob {
	t.Helper()
	if _, err := f.s.cancelNodeIdentityRecovery(context.Background(), "admin", "cancel-activated-task", f.job.ID); err != nil {
		t.Fatal(err)
	}
	j, err := f.s.prepareNodeIdentityRecovery(context.Background(), f.c, f.t.vault, "admin", "reauthorize-activated-task", f.input)
	if err != nil || j.ID == f.job.ID || j.Intent.Challenge == f.job.Intent.Challenge {
		t.Fatal("fresh authorization missing", err)
	}
	return j
}

func TestNodeIdentityRecoveryContinuationRequiresExactCommittedIssuance(t *testing.T) {
	for _, scenario := range []string{"success", "missing-ledger", "different-certificate", "different-csr", "different-lifetime", "old-intent", "expired-lease", "cannot-issue-if-ledger-lost"} {
		t.Run(scenario, func(t *testing.T) {
			f, floor, signed := activatedRecoveryFixture(t)
			j := freshActivatedRecovery(t, f)
			ctx := context.Background()
			r, err := nodepki.PrepareNodeRecoveryContinuation(ctx, f.c.Collector.CAFile, f.identity, floor, f.crl, j.Intent, signed.Certificate, time.Now())
			if err != nil || r.Renewal.SHA256() != f.request.Renewal.SHA256() {
				t.Fatal("prepare current-key continuation", err)
			}
			switch scenario {
			case "missing-ledger":
				mustHistoryExec(t, f.s.DB, `DELETE FROM v3_node_certificate_renewals WHERE node=$1`, j.Node)
			case "different-certificate":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET certificate=certificate || $2::bytea WHERE node=$1`, j.Node, []byte("\n"))
			case "different-csr":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET request_sha256=$2 WHERE node=$1`, j.Node, strings.Repeat("a", 64))
			case "different-lifetime":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET lifetime_hours=lifetime_hours+1 WHERE node=$1`, j.Node)
			case "old-intent":
				r, err = nodepki.PrepareNodeRecoveryContinuation(ctx, f.c.Collector.CAFile, f.identity, floor, f.crl, f.job.Intent, signed.Certificate, time.Now())
				if err != nil {
					t.Fatal(err)
				}
			case "expired-lease":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, f.lease.Resource)
			}
			raw, _ := json.Marshal(r)
			admitted, err := f.s.admitNodeIdentityRecovery(ctx, f.t.vault, f.lease, j.ID, raw)
			if scenario != "success" && scenario != "cannot-issue-if-ledger-lost" {
				if err == nil {
					t.Fatal("unbound continuation entered task")
				}
				var status string
				if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_identity_recoveries WHERE id=$1`, j.ID).Scan(&status); err != nil || status != "prepared" {
					t.Fatal("rejected proof changed task", err)
				}
				return
			}
			if err != nil || admitted.Status != "requested" {
				t.Fatal("current-key continuation not admitted", err)
			}
			if scenario == "cannot-issue-if-ledger-lost" {
				mustHistoryExec(t, f.s.DB, `DELETE FROM v3_node_certificate_renewals WHERE node=$1`, j.Node)
				out, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, j.ID)
				requireEmptyRenewalFailure(t, out, err)
				if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
					t.Fatal("continuation recreated missing ledger")
				}
				return
			}
			// Replay needs only public receipt/trust, not offline signing keys.
			if err := os.Remove(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				out, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, j.ID)
				if err != nil || out.Receipt != signed.Receipt || !bytes.Equal(out.Certificate, signed.Certificate) || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
					t.Fatal("continuation duplicated/changed original issuance", err)
				}
			}
			peer, _ := provisioningCertificate(signed.Certificate)
			if err := f.s.confirmNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, j.ID, peer); err != nil {
				t.Fatal("fresh task confirmation failed", err)
			}
			if _, err := f.s.nodeIdentityRecovery(ctx, f.t.vault, f.job.ID); err == nil {
				t.Fatal("old canceled authorization revived")
			}
		})
	}
}

// Real pinned loopback SSH and private node PKI, with fixed service operations
// explicitly simulated here. This is not combined systemd/Docker acceptance.
func TestNodeIdentityRecoverySSHReconcilesAlreadyActiveReplacement(t *testing.T) {
	ctx := context.Background()
	helper := []byte("isolated checksum-pinned continuation helper fixture")
	var f identityRecoveryFixture
	var floor string
	var worker *sshNodeIdentityRecovery
	var mu sync.Mutex
	var operations []string
	rpc := startNodeRPC(t, func(command string, ch ssh.Channel) {
		raw, err := io.ReadAll(io.LimitReader(ch, nodeops.MaxIdentityRecoveryBytes+1))
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if command == helperInstallCommand(worker.release.manifest.Helper) {
			if !bytes.Equal(raw, helper) {
				t.Error("helper bytes changed")
				return
			}
			io.WriteString(ch, "helper-ready\n")
		} else {
			want := strings.TrimSuffix(helperRunCommand(worker.release.manifest.Helper), "\n") + " --identity-recovery\n"
			if command != want {
				t.Error("unfixed recovery command")
				return
			}
			var in nodeops.IdentityRecoveryInput
			if json.Unmarshal(raw, &in) != nil || in.Intent != f.job.Intent {
				t.Error("wrong authorization over SSH")
				return
			}
			out := nodeops.IdentityRecoveryOutput{Format: 1, Operation: in.Operation, Node: in.Intent.Node, Challenge: in.Intent.Challenge}
			operations = append(operations, in.Operation)
			if in.Operation == "reconcile" {
				r, err := nodepki.PrepareNodeRecoveryContinuation(ctx, f.c.Collector.CAFile, f.identity, floor, in.CRL, in.Intent, in.Certificate, time.Now())
				if err != nil {
					t.Error(err)
					return
				}
				out.Request, _ = json.Marshal(r)
			} else {
				r, err := nodepki.ParseNodeRecoveryRequest(in.Request)
				if err != nil {
					t.Error(err)
					return
				}
				if in.Operation == "activate" {
					record, err := nodepki.ActivateNodeRecovery(ctx, f.c.Collector.CAFile, f.identity, floor, r, in.Intent, in.Certificate, time.Now())
					if err != nil || record.Changed {
						t.Error("continuation changed identity", err)
						return
					}
					out.CertificateSHA256 = record.CertificateSHA256
				} else if in.Operation == "start" {
					err := nodepki.WithRecoveredNodeIdentity(ctx, f.c.Collector.CAFile, f.identity, floor, r, in.Intent, in.Certificate, time.Now(), func(record nodepki.IdentityRecord) error {
						out.CertificateSHA256 = record.CertificateSHA256
						return nil
					})
					if err != nil {
						t.Error(err)
						return
					}
				} else {
					t.Error("unexpected recovery operation")
					return
				}
			}
			json.NewEncoder(ch).Encode(out)
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	})
	var signed signedNodeRenewal
	f, floor, signed = activatedRecoveryFixture(t, rpc.credential)
	f.job = freshActivatedRecovery(t, f)
	worker = identityRecoverySSHWorker(t, f, helper)
	if err := os.Remove(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")); err != nil {
		t.Fatal(err)
	}
	admitted, err := worker.prepare(ctx, f.lease, f.job.ID)
	if err != nil || admitted.Status != "requested" {
		t.Fatal("SSH reconciliation not admitted", err)
	}
	for i := 0; i < 2; i++ {
		if err := worker.activate(ctx, f.lease, f.job.ID); err != nil {
			t.Fatal("activation replay under fresh intent", err)
		}
		if err := worker.start(ctx, f.lease, f.job.ID); err != nil {
			t.Fatal("controlled startup delivery", err)
		}
	}
	replayed, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil || replayed.Receipt != signed.Receipt || !bytes.Equal(replayed.Certificate, signed.Certificate) {
		t.Fatal("transport changed original receipt", err)
	}
	j, err := f.s.nodeIdentityRecovery(ctx, f.t.vault, f.job.ID)
	if err != nil || j.Status != "signed" {
		t.Fatal("SSH claim falsely completed task", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(operations, ",") != "reconcile,activate,start,activate,start" {
		t.Fatal("unexpected continuation phases", operations)
	}
}
