package controlplane

import (
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

// Real SSH, PostgreSQL, local immutable files and remote SQLite journal;
// service actions and collector readiness are explicit controlled evidence.
// This exercises the shipped lifecycle transport, not a phase-support wrapper.
func TestLifecycleSSHRunnerReconcilesResponseLossAndCanRollback(t *testing.T) {
	for _, test := range []struct {
		name, direction, lostPhase string
		missingEvidence            bool
	}{
		{name: "forward", direction: "forward", lostPhase: "backup"},
		{name: "rollback", direction: "rollback", lostPhase: "backup"},
		{name: "lost-final-receipt", direction: "forward", lostPhase: "finalize"},
		{name: "missing-final-evidence", missingEvidence: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			root := privateTestDir(t)
			h := &rpcNodeHandler{calls: map[string]int{}}
			journal, err := nodeops.Open(filepath.Join(root, "journal"), h)
			if err != nil {
				t.Fatal(err)
			}
			configuration := []byte("private runtime fixture is sent only over SSH staging")
			artifact := ReleaseArtifact{SHA256: digest(configuration), Bytes: uint64(len(configuration))}
			var mu sync.Mutex
			var dropped bool
			var invalid []string
			var uploads int
			f := startNodeRPC(t, func(command string, ch ssh.Channel) {
				if strings.Contains(command, "artifact-missing") {
					io.WriteString(ch, "artifact-missing\n")
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				}
				raw, err := io.ReadAll(io.LimitReader(ch, nodeops.MaxRequestBytes+1))
				if err != nil {
					return
				}
				if strings.Contains(command, "configuration-ready") {
					mu.Lock()
					uploads++
					if digest(raw) != artifact.SHA256 {
						invalid = append(invalid, "wrong staged configuration")
					}
					mu.Unlock()
					io.WriteString(ch, "configuration-ready\n")
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				}
				mu.Lock()
				if !strings.HasSuffix(command, "exec \"$target/webscan\" node-v3 --lifecycle\n") || strings.Contains(string(raw), "private runtime fixture") || strings.Contains(string(raw), "never-in-node-rpc") {
					invalid = append(invalid, "invalid command or leaked material")
				}
				mu.Unlock()
				var request nodeops.Request
				if json.Unmarshal(raw, &request) != nil || request.Spec.RuntimeSHA256 != artifact.SHA256 || request.Spec.RuntimeBytes != artifact.Bytes {
					mu.Lock()
					invalid = append(invalid, "invalid RPC request")
					mu.Unlock()
					return
				}
				response := journal.Handle(request)
				// This transport fixture does not run a service lifecycle. Supply
				// explicitly synthetic installation digests only for its final
				// receipt; nodeops tests authenticate real immutable captures.
				if !test.missingEvidence && request.Phase == "finalize" && response.Code == "ok" && response.State == "complete" {
					response.Installation = &nodeops.InstallationEvidence{CaptureSHA256: strings.Repeat("c", 64), ActiveSHA256: strings.Repeat("d", 64)}
				}
				mu.Lock()
				lose := !dropped && request.Operation == "apply" && request.Phase == test.lostPhase
				if lose {
					dropped = true
				}
				mu.Unlock()
				if lose {
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
					return
				}
				finishRPC(ch, response)
			})
			f.runtimeArtifact = &artifact
			job, runtime := setupRPCJob(t, s, f)
			configs := filepath.Join(root, "configs")
			if err := os.Mkdir(configs, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := writeNodeConfiguration(configs, artifact, configuration); err != nil {
				t.Fatal(err)
			}
			runtime.Lifecycle, runtime.ConfigurationDirectory = true, configs
			runner := &DeploymentRunner{Store: s, Vault: runtime.Vault, Runtime: readinessFixtureRuntime{runtime, t, s}}
			if err := runner.Execute(ctx, job); err == nil {
				t.Fatal("response loss ignored")
			}
			failed := reloadDeployment(t, s, job.ID)
			wantStep := 2
			if test.lostPhase == "finalize" || test.missingEvidence {
				wantStep = 5
			}
			if !failed.CanRecover() || failed.Step != wantStep || h.count("backup") != 1 {
				t.Fatal("missing recovery obligation", failed.Status, failed.Step, failed.ErrorCode, "backup calls", h.count("backup"), invalid)
			}
			if test.missingEvidence {
				if failed.ErrorCode != "remote-state-unknown" || tableCount(t, s, "v3_deployment_installations") != 0 {
					t.Fatal("missing evidence certified successful installation")
				}
				return
			}
			if _, err := s.RecoverDeployment(ctx, "admin", "lifecycle-recover", job.ID, test.direction, failed.PlanDigest, failed.LogCursor); err != nil {
				t.Fatal(err)
			}
			next := claimDeployment(t, s, "lifecycle-takeover")
			if err := runner.Execute(ctx, next); err != nil {
				t.Fatal(err)
			}
			finished := reloadDeployment(t, s, job.ID)
			want := "succeeded"
			if test.direction == "rollback" {
				want = "rolled_back"
			}
			if finished.Status != want || h.count("backup") != 1 {
				t.Fatal("lost checkpoint replayed", finished.Status)
			}
			if test.direction == "forward" {
				row, err := installationRow(t, s, runtime.Vault, finished)
				if err != nil || row.Evidence.CaptureSHA256 != strings.Repeat("c", 64) || row.Spec.RuntimeSHA256 != artifact.SHA256 || row.Epoch != finished.Epoch {
					t.Fatal("SSH installation receipt not committed with task", err)
				}
			} else if tableCount(t, s, "v3_deployment_installations") != 0 {
				t.Fatal("rollback fabricated installation evidence")
			}
			if test.lostPhase == "finalize" && h.count("finalize") != 1 {
				t.Fatal("lost final receipt caused repeated remote finalization")
			}
			if test.direction == "rollback" && (h.count("restore") != 1 || h.count("verify-rollback") != 1 || h.count("activate") != 0) {
				t.Fatal("invalid rollback sequence")
			}
			mu.Lock()
			defer mu.Unlock()
			if uploads != 1 || len(invalid) != 0 {
				t.Fatal("unsafe transport", uploads, invalid)
			}
		})
	}
}
