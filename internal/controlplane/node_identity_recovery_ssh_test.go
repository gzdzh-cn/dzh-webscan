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

	"golang.org/x/crypto/ssh"
	"webscan/internal/nodeops"
)

func identityRecoverySSHWorker(t *testing.T, f identityRecoveryFixture, helper []byte) *sshNodeIdentityRecovery {
	t.Helper()
	path := filepath.Join(filepath.Dir(f.identity), "test-helper")
	if err := os.WriteFile(path, helper, 0600); err != nil {
		t.Fatal(err)
	}
	return &sshNodeIdentityRecovery{store: f.s, vault: f.t.vault, config: f.c, localHelper: path, release: &TrustedRelease{manifest: ReleaseManifest{Helper: ReleaseArtifact{SHA256: digest(helper), Bytes: uint64(len(helper))}}}}
}

func TestNodeIdentityRecoverySSHTransportPinsHelperAndPublicPhases(t *testing.T) {
	ctx := context.Background()
	helper := []byte("isolated checksum-pinned helper transport fixture")
	var f identityRecoveryFixture
	var worker *sshNodeIdentityRecovery
	var mu sync.Mutex
	var calls []string
	rpc := startNodeRPC(t, func(command string, channel ssh.Channel) {
		raw, err := io.ReadAll(io.LimitReader(channel, nodeops.MaxIdentityRecoveryBytes+1))
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if command == helperInstallCommand(worker.release.manifest.Helper) {
			if !bytes.Equal(raw, helper) {
				t.Error("unverified helper bytes delivered")
				return
			}
			calls = append(calls, "provision")
			io.WriteString(channel, "helper-ready\n")
		} else {
			want := strings.TrimSuffix(helperRunCommand(worker.release.manifest.Helper), "\n") + " --identity-recovery\n"
			if command != want {
				t.Error("unexpected remote command")
				return
			}
			var in nodeops.IdentityRecoveryInput
			if json.Unmarshal(raw, &in) != nil || in.Intent != f.job.Intent || !bytes.Equal(in.CRL, f.crl) {
				t.Error("wrong task/trust")
				return
			}
			out := nodeops.IdentityRecoveryOutput{Format: 1, Operation: in.Operation, Node: in.Intent.Node, Challenge: in.Intent.Challenge}
			if in.Operation == "prepare" {
				calls = append(calls, "prepare")
				if len(in.Certificate) != 0 || len(in.Request) != 0 {
					t.Error("prepare contains activation material")
				}
				out.Request, _ = json.Marshal(f.request)
			} else if in.Operation == "activate" || in.Operation == "start" || in.Operation == "verify" {
				calls = append(calls, in.Operation)
				if !bytes.Equal(in.Request, mustRecoveryRequestJSON(t, f)) {
					t.Error("stored public request changed")
				}
				cert, err := provisioningCertificate(in.Certificate)
				if err != nil {
					t.Error(err)
					return
				}
				out.CertificateSHA256 = digest(cert.Raw)
				out.ResourcesVerified = in.Operation == "verify"
			} else {
				t.Error("unexpected recovery operation")
				return
			}
			json.NewEncoder(channel).Encode(out)
		}
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	})
	f = newIdentityRecoveryFixture(t, rpc.credential)
	worker = identityRecoverySSHWorker(t, f, helper)
	j, err := worker.prepare(ctx, f.lease, f.job.ID)
	if err != nil || j.Status != "requested" {
		t.Fatal("pinned SSH request admission", err)
	}
	if _, err := worker.prepare(ctx, f.lease, f.job.ID); err != nil {
		t.Fatal("admission replay", err)
	}
	if err := worker.activate(ctx, f.lease, f.job.ID); err != nil {
		t.Fatal("activation delivery", err)
	}
	if err := worker.activate(ctx, f.lease, f.job.ID); err != nil {
		t.Fatal("activation replay", err)
	}
	for i := 0; i < 2; i++ {
		if err := worker.start(ctx, f.lease, f.job.ID); err != nil {
			t.Fatal("owned service start delivery/replay", err)
		}
	}
	if err := worker.verify(ctx, f.lease, f.job.ID); err != nil {
		t.Fatal("resource verification delivery", err)
	}
	j, err = f.s.nodeIdentityRecovery(ctx, f.t.vault, f.job.ID)
	if err != nil || j.Status != "signed" || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("SSH JSON claim completed task or duplicated issuance", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(calls, ",") != "provision,prepare,provision,activate,provision,activate,provision,start,provision,start,provision,verify" {
		t.Fatal("unexpected phases", calls)
	}
}

func mustRecoveryRequestJSON(t *testing.T, f identityRecoveryFixture) []byte {
	t.Helper()
	raw, err := json.Marshal(f.request)
	if err != nil {
		t.Error(err)
	}
	return raw
}

func TestNodeIdentityRecoverySSHResourceReceiptCannotStandInForReadiness(t *testing.T) {
	for _, scenario := range []string{"missing-proof", "spurious-activation-proof", "wrong-certificate", "request-in-receipt", "lost-lease", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			var f identityRecoveryFixture
			var worker *sshNodeIdentityRecovery
			helper := []byte("isolated verified resource helper")
			rpc := startNodeRPC(t, func(command string, ch ssh.Channel) {
				raw, err := io.ReadAll(ch)
				if err != nil {
					t.Error(err)
					return
				}
				if command == helperInstallCommand(worker.release.manifest.Helper) {
					io.WriteString(ch, "helper-ready\n")
				} else {
					var in nodeops.IdentityRecoveryInput
					if json.Unmarshal(raw, &in) != nil {
						t.Error("invalid helper input")
						return
					}
					cert, err := provisioningCertificate(in.Certificate)
					if err != nil {
						t.Error(err)
						return
					}
					out := nodeops.IdentityRecoveryOutput{Format: 1, Operation: in.Operation, Node: in.Intent.Node, Challenge: in.Intent.Challenge, CertificateSHA256: digest(cert.Raw), ResourcesVerified: in.Operation == "verify"}
					switch scenario {
					case "missing-proof":
						out.ResourcesVerified = false
					case "spurious-activation-proof":
						out.ResourcesVerified = true
					case "wrong-certificate":
						out.CertificateSHA256 = strings.Repeat("0", 64)
					case "request-in-receipt":
						out.Request = mustRecoveryRequestJSON(t, f)
					case "lost-lease":
						if _, err := f.s.DB.Exec(`UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, f.lease.Resource); err != nil {
							t.Error(err)
						}
					}
					json.NewEncoder(ch).Encode(out)
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			})
			f = newIdentityRecoveryFixture(t, rpc.credential)
			admitRecoveryFixture(t, f)
			worker = identityRecoverySSHWorker(t, f, helper)
			var err error
			if scenario == "spurious-activation-proof" {
				err = worker.activate(context.Background(), f.lease, f.job.ID)
			} else {
				err = worker.verify(context.Background(), f.lease, f.job.ID)
			}
			if (err == nil) != (scenario == "valid") {
				t.Fatal("resource receipt acceptance", err)
			}
			j, e := f.s.nodeIdentityRecovery(context.Background(), f.t.vault, f.job.ID)
			if e != nil || j.Status != "signed" || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
				t.Fatal("SSH receipt completed recovery or duplicated issuance", e)
			}
		})
	}
}

func TestNodeIdentityRecoverySSHTransportRejectsStaleAndUnboundResponses(t *testing.T) {
	for _, scenario := range []string{"wrong-challenge", "wrong-operation", "unknown-field", "trailing-json", "failed-exit", "lost-lease", "helper-mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			var f identityRecoveryFixture
			var worker *sshNodeIdentityRecovery
			helper := []byte("isolated helper")
			rpc := startNodeRPC(t, func(command string, ch ssh.Channel) {
				io.Copy(io.Discard, ch)
				status := uint32(0)
				if command == helperInstallCommand(worker.release.manifest.Helper) {
					io.WriteString(ch, "helper-ready\n")
				} else {
					out := nodeops.IdentityRecoveryOutput{Format: 1, Operation: "prepare", Node: f.job.Node, Challenge: f.job.Intent.Challenge, Request: mustRecoveryRequestJSON(t, f)}
					if scenario == "wrong-challenge" {
						out.Challenge = strings.Repeat("0", 64)
					}
					if scenario == "wrong-operation" {
						out.Operation = "activate"
					}
					if scenario == "lost-lease" {
						_, err := f.s.DB.Exec(`UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, f.lease.Resource)
						if err != nil {
							t.Error(err)
						}
					}
					raw, _ := json.Marshal(out)
					if scenario == "unknown-field" {
						raw = append(raw[:len(raw)-1], []byte(`,"private_key":"not-accepted"}`)...)
					}
					ch.Write(raw)
					if scenario == "trailing-json" {
						io.WriteString(ch, `{}`)
					}
					if scenario == "failed-exit" {
						status = 1
					}
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			})
			f = newIdentityRecoveryFixture(t, rpc.credential)
			worker = identityRecoverySSHWorker(t, f, helper)
			if scenario == "helper-mismatch" {
				if err := os.WriteFile(worker.localHelper, []byte("tampered helper"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := worker.prepare(context.Background(), f.lease, f.job.ID); err == nil {
				t.Fatal("untrusted transport response admitted")
			}
			var status string
			if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_identity_recoveries WHERE id=$1`, f.job.ID).Scan(&status); err != nil || status != "prepared" || tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("failed transport changed recovery/issuance", err)
			}
			if scenario == "helper-mismatch" && rpc.connections.Load() != 0 {
				t.Fatal("corrupt local helper opened SSH")
			}
		})
	}
}
