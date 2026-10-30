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

func nameChangeSSHWorker(t *testing.T, f nameChangeRegistryFixture, helper []byte) *sshNodeNameChange {
	t.Helper()
	path := filepath.Join(filepath.Dir(f.identity), "test-helper")
	if err := os.WriteFile(path, helper, 0600); err != nil {
		t.Fatal(err)
	}
	return &sshNodeNameChange{store: f.s, vault: f.t.vault, config: f.c, localHelper: path, release: &TrustedRelease{manifest: ReleaseManifest{Helper: ReleaseArtifact{SHA256: digest(helper), Bytes: uint64(len(helper))}}}}
}

func TestNodeNameChangeSSHTransportPinsHelperAndPublicPhases(t *testing.T) {
	ctx := context.Background()
	helper := []byte("isolated checksum-pinned helper transport fixture")
	var f nameChangeRegistryFixture
	var worker *sshNodeNameChange
	var mu sync.Mutex
	var calls []string
	rpc := startNodeRPC(t, func(command string, channel ssh.Channel) {
		raw, err := io.ReadAll(io.LimitReader(channel, nodeops.MaxNameChangeBytes+1))
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
			want := strings.TrimSuffix(helperRunCommand(worker.release.manifest.Helper), "\n") + " --identity-name-change\n"
			if command != want {
				t.Error("unexpected remote command")
				return
			}
			var in nodeops.NameChangeInput
			if json.Unmarshal(raw, &in) != nil || in.Intent != f.job.Intent || !bytes.Equal(in.CRL, f.crl) {
				t.Error("wrong task/trust")
				return
			}
			out := nodeops.NameChangeOutput{Format: 1, Operation: in.Operation, Node: in.Intent.Node, Challenge: in.Intent.Challenge}
			if in.Operation == "prepare" {
				calls = append(calls, "prepare")
				if len(in.Certificate) != 0 || len(in.Request) != 0 {
					t.Error("prepare contains activation material")
				}
				out.Request, _ = json.Marshal(f.request)
			} else if in.Operation == "activate" || in.Operation == "verify" {
				calls = append(calls, in.Operation)
				if !bytes.Equal(in.Request, f.requestBytes(t)) {
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
	f = nameChangeSSHFixture(t, rpc.credential)
	worker = nameChangeSSHWorker(t, f, helper)
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
	if err := worker.verify(ctx, f.lease, f.job.ID); err != nil {
		t.Fatal("resource verification delivery", err)
	}
	j, err = f.s.nodeNameChange(ctx, f.t.vault, f.job.ID)
	if err != nil || j.Status != "signed" || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("SSH JSON claim completed task or duplicated issuance", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(calls, ",") != "provision,prepare,provision,activate,provision,activate,provision,verify" {
		t.Fatal("unexpected phases", calls)
	}
}

func TestNodeNameChangeSSHResourceReceiptCannotStandInForReadiness(t *testing.T) {
	for _, scenario := range []string{"missing-proof", "spurious-activation-proof", "wrong-certificate", "request-in-receipt", "lost-lease", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			var f nameChangeRegistryFixture
			var worker *sshNodeNameChange
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
					var in nodeops.NameChangeInput
					if json.Unmarshal(raw, &in) != nil {
						t.Error("invalid helper input")
						return
					}
					cert, err := provisioningCertificate(in.Certificate)
					if err != nil {
						t.Error(err)
						return
					}
					out := nodeops.NameChangeOutput{Format: 1, Operation: in.Operation, Node: in.Intent.Node, Challenge: in.Intent.Challenge, CertificateSHA256: digest(cert.Raw), ResourcesVerified: in.Operation == "verify"}
					switch scenario {
					case "missing-proof":
						out.ResourcesVerified = false
					case "spurious-activation-proof":
						out.ResourcesVerified = true
					case "wrong-certificate":
						out.CertificateSHA256 = strings.Repeat("0", 64)
					case "request-in-receipt":
						out.Request = f.requestBytes(t)
					case "lost-lease":
						if _, err := f.s.DB.Exec(`UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, f.lease.Resource); err != nil {
							t.Error(err)
						}
					}
					if scenario == "duplicate-field" {
						raw, _ := json.Marshal(out)
						ch.Write(append(raw[:len(raw)-1], []byte(`,"format":1}`)...))
					} else {
						json.NewEncoder(ch).Encode(out)
					}
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			})
			f = nameChangeSSHFixture(t, rpc.credential)
			f.admit(t)
			worker = nameChangeSSHWorker(t, f, helper)
			var err error
			if scenario == "spurious-activation-proof" {
				err = worker.activate(context.Background(), f.lease, f.job.ID)
			} else {
				err = worker.verify(context.Background(), f.lease, f.job.ID)
			}
			if (err == nil) != (scenario == "valid") {
				t.Fatal("resource receipt acceptance", err)
			}
			j, e := f.s.nodeNameChange(context.Background(), f.t.vault, f.job.ID)
			if e != nil || j.Status != "signed" || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
				t.Fatal("SSH receipt completed recovery or duplicated issuance", e)
			}
		})
	}
}

func TestNodeNameChangeSSHTransportRejectsStaleAndUnboundResponses(t *testing.T) {
	for _, scenario := range []string{"wrong-challenge", "wrong-operation", "unknown-field", "trailing-json", "failed-exit", "lost-lease", "helper-mismatch", "duplicate-field"} {
		t.Run(scenario, func(t *testing.T) {
			var f nameChangeRegistryFixture
			var worker *sshNodeNameChange
			helper := []byte("isolated helper")
			rpc := startNodeRPC(t, func(command string, ch ssh.Channel) {
				io.Copy(io.Discard, ch)
				status := uint32(0)
				if command == helperInstallCommand(worker.release.manifest.Helper) {
					io.WriteString(ch, "helper-ready\n")
				} else {
					out := nodeops.NameChangeOutput{Format: 1, Operation: "prepare", Node: f.job.Node, Challenge: f.job.Intent.Challenge, Request: f.requestBytes(t)}
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
					if scenario == "duplicate-field" {
						raw = append(raw[:len(raw)-1], []byte(`,"format":1}`)...)
					}
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
			f = nameChangeSSHFixture(t, rpc.credential)
			worker = nameChangeSSHWorker(t, f, helper)
			if scenario == "helper-mismatch" {
				if err := os.WriteFile(worker.localHelper, []byte("tampered helper"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := worker.prepare(context.Background(), f.lease, f.job.ID); err == nil {
				t.Fatal("untrusted transport response admitted")
			}
			var status string
			if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_changes WHERE id=$1`, f.job.ID).Scan(&status); err != nil || status != "prepared" || tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("failed transport changed recovery/issuance", err)
			}
			if scenario == "helper-mismatch" && rpc.connections.Load() != 0 {
				t.Fatal("corrupt local helper opened SSH")
			}
		})
	}
}

func nameChangeSSHFixture(t *testing.T, c SSHCredential) nameChangeRegistryFixture {
	t.Helper()
	return nameChangeRegistryFixtureWith(t, func(f *provisioningFixture) {
		raw, err := f.s.AddCredential(context.Background(), f.t.vault, "admin", "name-change-pinned-ssh", f.in.Node, 1, c)
		if err != nil {
			t.Fatal(err)
		}
		var ref struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &ref) != nil || ref.ID == "" {
			t.Fatal("missing credential reference")
		}
		f.in.Credential = ref.ID
	})
}

func TestNodeNameChangeSSHChecksAuthorizationBeforeContact(t *testing.T) {
	for _, scenario := range []string{"expired-lease", "expired-intent", "actor-revision", "saved-config", "runtime-epoch", "credential", "canceled", "wrong-pin"} {
		t.Run(scenario, func(t *testing.T) {
			rpc := startNodeRPC(t, func(_ string, _ ssh.Channel) { t.Error("unauthorized operation sent remote command") })
			credential := rpc.credential
			if scenario == "wrong-pin" {
				credential.Fingerprint = credentialFixture().Fingerprint
			}
			f := nameChangeSSHFixture(t, credential)
			ctx := context.Background()
			switch scenario {
			case "expired-lease":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
			case "expired-intent":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET expires_at=clock_timestamp()-interval '1 second'`)
			case "actor-revision":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "saved-config":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET config='{"changed":true}'`)
			case "runtime-epoch":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1`)
			case "credential":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_credentials SET ciphertext=decode('deadbeef','hex') WHERE id=$1`, f.input.Credential)
			case "canceled":
				if _, err := f.s.cancelNodeNameChange(ctx, "admin", "cancel-before-ssh", f.job.ID); err != nil {
					t.Fatal(err)
				}
			}
			if remote, err := f.s.connectNodeNameChangeSSH(ctx, f.t.vault, f.lease, f.job.ID); err == nil {
				remote.Close()
				t.Fatal("unauthorized SSH connected")
			}
			if scenario != "wrong-pin" && rpc.connections.Load() != 0 {
				t.Fatal("contacted remote before rejecting stale authorization")
			}
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("failed SSH signed certificate")
			}
		})
	}
}

func TestNodeNameChangeSSHReauthorizationReplaysExactReceipt(t *testing.T) {
	for _, active := range []bool{false, true} {
		label := "pending"
		if active {
			label = "active"
		}
		t.Run(label, func(t *testing.T) {
			ctx := context.Background()
			helper := []byte("isolated checksum-pinned name reconciliation helper")
			var f nameChangeRegistryFixture
			var worker *sshNodeNameChange
			var first signedNodeRenewal
			var original []byte
			var mu sync.Mutex
			var calls []string
			activations := 0
			rpc := startNodeRPC(t, func(command string, ch ssh.Channel) {
				raw, err := io.ReadAll(io.LimitReader(ch, nodeops.MaxNameChangeBytes+1))
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				status := uint32(0)
				if command == helperInstallCommand(worker.release.manifest.Helper) {
					if !bytes.Equal(raw, helper) {
						t.Error("unverified helper delivered")
						return
					}
					calls = append(calls, "provision")
					io.WriteString(ch, "helper-ready\n")
				} else {
					want := strings.TrimSuffix(helperRunCommand(worker.release.manifest.Helper), "\n") + " --identity-name-change\n"
					if command != want {
						t.Error("unexpected remote command")
						return
					}
					var in nodeops.NameChangeInput
					if json.Unmarshal(raw, &in) != nil || in.Intent != f.job.Intent || !bytes.Equal(in.Certificate, first.Certificate) {
						t.Error("reconciliation task/receipt mismatch")
						return
					}
					out := nodeops.NameChangeOutput{Format: 1, Operation: in.Operation, Node: f.job.Node, Challenge: f.job.Intent.Challenge}
					calls = append(calls, in.Operation)
					if in.Operation == "reconcile" {
						if !bytes.Equal(in.Request, original) {
							t.Error("not the original immutable public request")
							return
						}
						out.Request = f.requestBytes(t)
					} else if in.Operation == "activate" || in.Operation == "verify" {
						if !bytes.Equal(in.Request, f.requestBytes(t)) {
							t.Error("fresh task proof changed")
							return
						}
						out.CertificateSHA256 = first.Receipt.CertificateSHA256
						out.ResourcesVerified = in.Operation == "verify"
						if in.Operation == "activate" {
							activations++
							if activations == 1 {
								status = 1
							}
						}
					} else {
						t.Error("unexpected operation")
						return
					}
					json.NewEncoder(ch).Encode(out)
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			})
			f = nameChangeSSHFixture(t, rpc.credential)
			f.admit(t)
			var err error
			first, err = f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				t.Fatal(err)
			}
			original = f.requestBytes(t)
			originalRequest := f.request
			if active {
				if _, err := nodepki.ActivateNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.request, f.job.Intent, first.Certificate, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			f.job = freshNameChangeTask(t, f, "fresh-ssh-name")
			f.request, err = nodepki.PrepareNodeNameChangeContinuation(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.crl, f.job.Intent, originalRequest, first.Certificate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")); err != nil {
				t.Fatal(err)
			}
			worker = nameChangeSSHWorker(t, f, helper)
			admitted, err := worker.prepare(ctx, f.lease, f.job.ID)
			if err != nil || admitted.Status != "requested" {
				t.Fatal("SSH reconciliation admission", err)
			}
			if _, err := worker.prepare(ctx, f.lease, f.job.ID); err != nil {
				t.Fatal("admission replay", err)
			}
			if err := worker.activate(ctx, f.lease, f.job.ID); err == nil {
				t.Fatal("lost activation response treated as success")
			}
			if err := worker.activate(ctx, f.lease, f.job.ID); err != nil {
				t.Fatal("activation replay", err)
			}
			if err := worker.verify(ctx, f.lease, f.job.ID); err != nil {
				t.Fatal("resource receipt", err)
			}
			var status string
			if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_changes WHERE id=$1`, f.job.ID).Scan(&status); err != nil || status != "signed" || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
				t.Fatal("SSH JSON completed task or duplicated issuance", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if strings.Join(calls, ",") != "provision,reconcile,provision,activate,provision,activate,provision,verify" {
				t.Fatal("wrong reconciliation phases", calls)
			}
		})
	}
}
