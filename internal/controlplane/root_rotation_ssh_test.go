package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
	"webscan/internal/nodeops"
)

func TestRootSSHUsesFixedVerifiedHelperAndRejectsFalseReceipt(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-certificate", "duplicate", "changed-helper", "wrong-host-pin"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			var f renewalRegistryFixture
			var worker *sshRootRotation
			var expectedHelper []byte
			var calls atomic.Int32
			rpc := startNodeRPC(t, func(command string, channel ssh.Channel) {
				defer channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				calls.Add(1)
				raw, err := io.ReadAll(io.LimitReader(channel, nodeops.MaxRootRotationBytes+1))
				if err != nil {
					t.Error(err)
					return
				}
				if command == helperInstallCommand(worker.release.manifest.Helper) {
					if !bytes.Equal(raw, expectedHelper) {
						t.Error("unverified helper sent")
						return
					}
					io.WriteString(channel, "helper-ready\n")
					return
				}
				if command != strings.TrimSuffix(helperRunCommand(worker.release.manifest.Helper), "\n")+" --identity-root-rotation\n" {
					t.Error("arbitrary remote command")
					return
				}
				var in nodeops.RootRotationInput
				if json.Unmarshal(raw, &in) != nil || in.Operation != "trust" || in.Node != f.in.Request.Node || in.Delivery == nil || in.Configuration != digest(runtimeNodeForTest(t, f.s, in.Node).Config) {
					t.Error("task binding lost")
					return
				}
				out := nodeops.RootRotationOutput{Format: 1, Operation: in.Operation, Node: in.Node, Snapshot: digest(in.Snapshot), Phase: "dual", CertificateSHA256: in.Expected}
				if scenario == "wrong-certificate" {
					out.CertificateSHA256 = strings.Repeat("f", 64)
				}
				if scenario == "duplicate" {
					io.WriteString(channel, `{"format":1,"format":1}`)
					return
				}
				json.NewEncoder(channel).Encode(out)
			})
			credential := rpc.credential
			// Use a syntactically valid different host key for the pin case.
			if scenario == "wrong-host-pin" {
				other := startNodeRPC(t, func(string, ssh.Channel) {})
				credential.Fingerprint = other.credential.Fingerprint
			}
			var inputs []rootRotationNodeInput
			f, inputs = rootTaskFixtureWith(t, func(f *provisioningFixture) {
				raw, err := f.s.AddCredential(ctx, f.t.vault, "admin", "root-ssh-credential", f.in.Node, 1, credential)
				if err != nil {
					t.Fatal(err)
				}
				var ref struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(raw, &ref) != nil || ref.ID == "" {
					t.Fatal("credential missing")
				}
				f.in.Credential = ref.ID
			})
			j, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "root-ssh-task", f.t.release, inputs)
			if err != nil {
				t.Fatal(err)
			}
			l, err := f.s.Acquire(ctx, "pki-root-rotation", "root-ssh-test")
			if err != nil {
				t.Fatal(err)
			}
			defer f.s.Release(ctx, l)
			j, err = f.s.authorizeRootTask(ctx, f.c, f.t.vault, l, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			worker = &sshRootRotation{store: f.s, vault: f.t.vault, config: f.c, release: f.t.release, localHelper: f.t.config.HelperFile}
			expectedHelper, err = os.ReadFile(worker.localHelper)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "changed-helper" {
				if err := os.WriteFile(worker.localHelper, []byte("replaced"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			index := -1
			for i, m := range j.Members {
				if m.ID == inputs[0].Node {
					index = i
				}
			}
			_, err = worker.operation(ctx, l, j.ID, index, "trust")
			if scenario == "valid" {
				if err != nil || calls.Load() != 2 {
					t.Fatal("fixed SSH delivery failed", err, calls.Load())
				}
			} else if err == nil {
				t.Fatal("invalid receipt/pin/artifact accepted")
			}
			if (scenario == "changed-helper" || scenario == "wrong-host-pin") && calls.Load() != 0 {
				t.Fatal("unauthorized remote command executed")
			}
			current, _, err := f.s.readRootTask(ctx, f.t.vault, j.ID)
			if err != nil || current.Status != "dual" || current.State[index].Trust || !current.State[index].ObservedAt.IsZero() {
				t.Fatal("SSH receipt forged durable readiness", err)
			}
		})
	}
}
