package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodeops"
	"webscan/internal/nodepki"
)

type runtimeConfigurationFixture struct {
	provisioningFixture
	job                        DeploymentJob
	runtime                    *SSHNodeRuntime
	raw, currentCRL, successor []byte
	calls                      *atomic.Int32
}

func resumedRuntimeConfigurationFixture(t *testing.T, format int) runtimeConfigurationFixture {
	t.Helper()
	ctx := context.Background()
	f := localProvisioningFixture(t, time.Now().Add(-48*time.Hour))
	enableRegistryIssuer(t, &f)
	record := issuedNode(t, f, "runtime-seed")
	seed, err := f.s.readNodeIdentity(ctx, f.c, f.t.vault, record.ID, f.in.Node)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed.Key)
	_, public := renewalPendingForTest(t, f, seed, "runtime-current-node")
	var snapshot string
	if err := f.s.DB.QueryRow(`SELECT snapshot FROM v3_node_runtime WHERE node=$1`, f.in.Node).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	l, err := f.s.Acquire(ctx, nodeRenewalResource(f.in.Node), "runtime-issuer")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.s.signNodeRenewal(ctx, f.c, l, nodeRenewalSigningInput{Snapshot: snapshot, RuntimeEpoch: 1, LifetimeHours: 72, Request: public})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-36 * time.Hour)
	oldSeed, err := f.ca.Issue(nodepki.Node, f.in.Node, []string{"192.0.2.1"}, past, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(oldSeed.Key)
	oldCRL, err := f.ca.Revoke(nil, nil, past, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.ca.Revoke(oldCRL, [][]byte{oldSeed.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, f.c.Collector.RevocationFile, current)
	localWrite(t, filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"), current)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, current)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET applied_version=version WHERE id=$1`, f.in.Node)
	n, err := scanNode(f.s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, f.in.Node))
	if err != nil {
		t.Fatal(err)
	}
	m, err := nodeConfigurationMaterial(n, f.t.release, NodeConfigurationInput{Node: n.ID, Expected: n.Version, Identity: nodepki.Bundle{CA: seed.CA}, CRL: current, Collectors: f.in.Collectors, Rules: []byte("rule resume { condition: false }"), ManagedIdentity: true})
	if err != nil {
		t.Fatal(err)
	}
	m.Format, m.CRL = format, oldCRL
	if format == 2 {
		m.Certificate, m.Key = oldSeed.Certificate, oldSeed.Key
	}
	raw, _ := json.Marshal(m)
	if _, err := nodeconfig.Decode(raw, now); err == nil {
		t.Fatal("fixture needs expired static material")
	}
	a := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
	if _, err := writeNodeConfiguration(f.c.Executor.ConfigurationDirectory, a, raw); err != nil {
		t.Fatal(err)
	}
	backend := &rpcNodeHandler{calls: map[string]int{}}
	journal, err := nodeops.Open(filepath.Join(privateTestDir(t), "journal"), backend)
	if err != nil {
		t.Fatal(err)
	}
	calls := &atomic.Int32{}
	rpc := startNodeRPC(t, func(command string, channel ssh.Channel) {
		calls.Add(1)
		body, err := io.ReadAll(io.LimitReader(channel, nodeops.MaxRequestBytes+1))
		if err != nil {
			return
		}
		if !strings.HasSuffix(command, `node-v3 --lifecycle`+"\n") || bytes.Contains(body, []byte("PRIVATE KEY")) || bytes.Contains(body, []byte("never-in-node-rpc")) {
			t.Error("unsafe remote request")
			return
		}
		var request nodeops.Request
		if json.Unmarshal(body, &request) != nil || request.Spec.RuntimeSHA256 != a.SHA256 {
			t.Error("remote request not bound to immutable artifact")
			return
		}
		finishRPC(channel, journal.Handle(request))
	})
	credential, err := f.s.AddCredential(ctx, f.t.vault, "admin", "runtime-ssh", n.ID, n.Version, rpc.credential)
	if err != nil {
		t.Fatal(err)
	}
	var reference struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(credential, &reference) != nil {
		t.Fatal("credential reference")
	}
	request := DeploymentRequest{Node: n.ID, Expected: n.Version, Kind: "upgrade", Credential: reference.ID, Release: f.t.release.manifest.Release, SHA256: f.t.release.manifest.Native.SHA256, ManifestSHA256: f.t.release.SHA256(), RuntimeArtifact: &a}
	// This reconstructs a previously admitted immutable task whose seed has
	// since expired. Current public preparation deliberately cannot admit it.
	createDeployment(t, f.s, request, "historical-runtime")
	j := claimDeployment(t, f.s, "resumed-executor")
	runner, err := newDeploymentExecutor(ctx, f.s, f.c)
	if err != nil {
		t.Fatal(err)
	}
	w, ok := runner.Runtime.(*SSHNodeRuntime)
	if !ok || w.ValidateTaskConfiguration == nil {
		t.Fatal("production task validation not installed")
	}
	return runtimeConfigurationFixture{f, j, w, raw, current, signed.Certificate, calls}
}

func TestDeploymentRuntimeResumesExpiredStaticIdentityOverPinnedSSH(t *testing.T) {
	for _, format := range []int{2, 3} {
		t.Run(string(rune('0'+format)), func(t *testing.T) {
			f := resumedRuntimeConfigurationFixture(t, format)
			before := f.job.Plan.Request.RuntimeArtifact.SHA256
			proof, err := f.runtime.phase(context.Background(), f.job, "apply")
			if err != nil || proof.State != "complete" || !proof.matches(f.job) || f.calls.Load() != 1 {
				t.Fatal("existing task could not cross production validation and SSH", proof, err)
			}
			if f.job.Plan.Request.RuntimeArtifact.SHA256 != before {
				t.Fatal("resume rewrote immutable plan")
			}
			path := filepath.Join(f.c.Executor.ConfigurationDirectory, before, "node.json")
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, f.raw) {
				t.Fatal("resume rewrote private configuration", err)
			}
			// Public preparation remains strict even after the leased task was
			// inspected; this is not a new installation authorization.
			if _, err := f.s.localDeploymentMaterial(context.Background(), f.c, f.t, f.job.Plan.Request); err == nil {
				t.Fatal("historical task bypass leaked into new deployment preparation")
			}
		})
	}
}

func TestDeploymentRuntimeRejectsUntrustedOrStaleResumeBeforeSSH(t *testing.T) {
	for _, scenario := range []string{"lease-expired", "node-version", "missing-successor", "revoked-successor", "revoked-collector", "crl-rollback", "wrong-host", "artifact-changed"} {
		t.Run(scenario, func(t *testing.T) {
			f := resumedRuntimeConfigurationFixture(t, 2)
			switch scenario {
			case "lease-expired":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()-interval '1 second'`)
			case "node-version":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET version=version+1 WHERE id=$1`, f.job.Node)
			case "missing-successor":
				mustHistoryExec(t, f.s.DB, `DELETE FROM v3_node_certificate_renewals`)
			case "revoked-successor", "revoked-collector":
				certificate := f.successor
				if scenario == "revoked-collector" {
					certificate = f.collector.Certificate
				}
				next, err := f.ca.Revoke(f.currentCRL, [][]byte{certificate}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				localWrite(t, f.c.Collector.RevocationFile, next)
			case "crl-rollback":
				localWrite(t, f.c.Collector.RevocationFile, f.crl)
			case "wrong-host":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET server_name='wrong.test' WHERE id=$1`, f.job.Node)
			case "artifact-changed":
				localWrite(t, filepath.Join(f.c.Executor.ConfigurationDirectory, f.job.Plan.Request.RuntimeArtifact.SHA256, "node.json"), []byte("tampered"))
			}
			if _, err := f.runtime.phase(context.Background(), f.job, "apply"); err == nil {
				t.Fatal("invalid recovery reached SSH", scenario)
			}
			if f.calls.Load() != 0 {
				t.Fatal("SSH contacted despite failed trust/fencing")
			}
		})
	}
}
