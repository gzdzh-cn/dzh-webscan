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

func namePruningSSHWorker(t *testing.T, f namePruningRegistryFixture, helper []byte) *sshNodeNamePruning {
	t.Helper()
	path := filepath.Join(filepath.Dir(f.identity), "test-pruning-helper")
	if err := os.WriteFile(path, helper, 0600); err != nil {
		t.Fatal(err)
	}
	return &sshNodeNamePruning{store: f.s, vault: f.t.vault, config: f.c, localHelper: path, release: &TrustedRelease{manifest: ReleaseManifest{Helper: ReleaseArtifact{SHA256: digest(helper), Bytes: uint64(len(helper))}}}}
}

func namePruningSSHFixture(t *testing.T, c SSHCredential) namePruningRegistryFixture {
	t.Helper()
	return namePruningRegistryFixtureWith(t, func(f *provisioningFixture) {
		raw, err := f.s.AddCredential(context.Background(), f.t.vault, "admin", "pruning-pinned-ssh", f.in.Node, 1, c)
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

func TestNodeNamePruningSSHUsesPinnedHelperAndDoesNotTrustActivationReceipt(t *testing.T) {
	ctx := context.Background()
	helper := []byte("isolated checksum-pinned pruning transport")
	var f namePruningRegistryFixture
	var worker *sshNodeNamePruning
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
				t.Error("unverified helper transferred")
				return
			}
			calls = append(calls, "provision")
			io.WriteString(channel, "helper-ready\n")
		} else {
			if command != strings.TrimSuffix(helperRunCommand(worker.release.manifest.Helper), "\n")+" --identity-name-pruning\n" {
				t.Error("unexpected helper command")
				return
			}
			var in nodeops.NamePruningInput
			if json.Unmarshal(raw, &in) != nil || in.Intent.SHA256() != f.job.Intent.SHA256() || !bytes.Equal(in.CRL, f.crl) {
				t.Error("intent/trust changed")
				return
			}
			calls = append(calls, in.Operation)
			out := nodeops.NamePruningOutput{Format: 1, Operation: in.Operation, Node: in.Intent.Node, Challenge: in.Intent.Challenge}
			if in.Operation == "prepare" {
				if len(in.Request) != 0 || len(in.Certificate) != 0 {
					t.Error("preparation received activation data")
					return
				}
				out.Request, _ = json.Marshal(f.request)
			} else if in.Operation == "activate" || in.Operation == "verify" {
				request, _ := json.Marshal(f.request)
				cert, err := provisioningCertificate(in.Certificate)
				if err != nil || !bytes.Equal(request, in.Request) {
					t.Error("wrong stored issuance/request")
					return
				}
				out.CertificateSHA256 = digest(cert.Raw)
				out.ResourcesVerified = in.Operation == "verify"
			} else {
				t.Error("arbitrary operation sent")
				return
			}
			json.NewEncoder(channel).Encode(out)
		}
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	})
	f = namePruningSSHFixture(t, rpc.credential)
	worker = namePruningSSHWorker(t, f, helper)
	for range 2 {
		j, err := worker.prepare(ctx, f.lease, f.job.ID)
		if err != nil || j.Status != "requested" {
			t.Fatal("request admission/replay", err)
		}
	}
	for range 2 {
		if err := worker.activate(ctx, f.lease, f.job.ID); err != nil {
			t.Fatal("activate/replay", err)
		}
	}
	if err := worker.verify(ctx, f.lease, f.job.ID); err != nil {
		t.Fatal("resource receipt", err)
	}
	j, err := f.s.nodeNamePruning(ctx, f.c, f.t.vault, f.job.ID)
	if err != nil || j.Status != "signed" || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("helper receipt completed task or duplicated issuance", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(calls, ",") != "provision,prepare,provision,activate,provision,activate,provision,verify" {
		t.Fatal("wrong phase sequence", calls)
	}
}

func TestNodeNamePruningSSHChecksAuthorizationBeforeContact(t *testing.T) {
	for _, scenario := range []string{"expired-lease", "expired-intent", "actor-revision", "saved-config", "runtime-epoch", "credential", "canceled", "wrong-pin"} {
		t.Run(scenario, func(t *testing.T) {
			rpc := startNodeRPC(t, func(_ string, _ ssh.Channel) { t.Error("unauthorized operation sent remote command") })
			credential := rpc.credential
			if scenario == "wrong-pin" {
				credential.Fingerprint = credentialFixture().Fingerprint
			}
			f := namePruningSSHFixture(t, credential)
			ctx := context.Background()
			switch scenario {
			case "expired-lease":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
			case "expired-intent":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_prunings SET expires_at=clock_timestamp()-interval '1 second'`)
			case "actor-revision":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "saved-config":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET config='{"changed":true}'`)
			case "runtime-epoch":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1`)
			case "credential":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_credentials SET ciphertext=decode('deadbeef','hex') WHERE id=$1`, f.input.Credential)
			case "canceled":
				if _, err := f.s.cancelNodeNamePruning(ctx, "admin", "cancel-before-ssh", f.job.ID); err != nil {
					t.Fatal(err)
				}
			}
			if remote, err := f.s.connectNodeNamePruningSSH(ctx, f.c, f.t.vault, f.lease, f.job.ID); err == nil {
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

func TestNodeNamePruningSSHReauthorizationReplaysExactReceipt(t *testing.T) {
	for _, active := range []bool{false, true} {
		label := "pending"
		if active {
			label = "active"
		}
		t.Run(label, func(t *testing.T) {
			ctx := context.Background()
			helper := []byte("isolated checksum-pinned name reconciliation helper")
			var f namePruningRegistryFixture
			var worker *sshNodeNamePruning
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
					want := strings.TrimSuffix(helperRunCommand(worker.release.manifest.Helper), "\n") + " --identity-name-pruning\n"
					if command != want {
						t.Error("unexpected remote command")
						return
					}
					var in nodeops.NamePruningInput
					if json.Unmarshal(raw, &in) != nil || in.Intent.SHA256() != f.job.Intent.SHA256() || !bytes.Equal(in.Certificate, first.Certificate) {
						t.Error("reconciliation task/receipt mismatch")
						return
					}
					out := nodeops.NamePruningOutput{Format: 1, Operation: in.Operation, Node: f.job.Node, Challenge: f.job.Intent.Challenge}
					calls = append(calls, in.Operation)
					if in.Operation == "reconcile" {
						if !bytes.Equal(in.Request, original) {
							t.Error("not the original immutable public request")
							return
						}
						out.Request = namePruningRequestBytes(t, f)
					} else if in.Operation == "activate" || in.Operation == "verify" {
						if !bytes.Equal(in.Request, namePruningRequestBytes(t, f)) {
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
			f = namePruningSSHFixture(t, rpc.credential)
			f.admit(t)
			var err error
			first, err = f.s.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				t.Fatal(err)
			}
			original = namePruningRequestBytes(t, f)
			originalRequest := f.request
			if active {
				if _, err := nodepki.ActivateNodeNamePruning(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.request, f.job.Intent, first.Certificate, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			f.job = freshNamePruningTask(t, f, "fresh-ssh-name")
			f.request, err = nodepki.PrepareNodeNamePruningContinuation(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.crl, f.job.Intent, originalRequest, first.Certificate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")); err != nil {
				t.Fatal(err)
			}
			worker = namePruningSSHWorker(t, f, helper)
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
			if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_prunings WHERE id=$1`, f.job.ID).Scan(&status); err != nil || status != "signed" || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
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

func namePruningRequestBytes(t *testing.T, f namePruningRegistryFixture) []byte {
	t.Helper()
	raw, err := json.Marshal(f.request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
