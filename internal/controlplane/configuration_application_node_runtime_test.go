package controlplane

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type orderedApplicationNodeRuntime struct {
	calls    []string
	fail     string
	runtimes map[string]*fakeDeploymentRuntime
}

func (r *orderedApplicationNodeRuntime) remote(j DeploymentJob) *fakeDeploymentRuntime {
	if r.runtimes == nil {
		r.runtimes = map[string]*fakeDeploymentRuntime{}
	}
	if r.runtimes[j.ID] == nil {
		r.runtimes[j.ID] = &fakeDeploymentRuntime{}
	}
	return r.runtimes[j.ID]
}

func (r *orderedApplicationNodeRuntime) Inspect(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	return r.remote(j).Inspect(ctx, j)
}
func (r *orderedApplicationNodeRuntime) Apply(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	r.calls = append(r.calls, j.Node+":"+j.Phase())
	if r.fail == j.Node+":"+j.Phase() {
		return RemoteDeploymentCheckpoint{}, DeploymentFailure{"remote-unavailable"}
	}
	return r.remote(j).Apply(ctx, j)
}

func TestConfigurationApplicationNodeRuntimeSequentialApplyAndReverseRollback(t *testing.T) {
	s, f, trust, p, requests := applicationNodesFixture(t, []string{"node-a", "node-b"})
	ctx := context.Background()
	remote := &orderedApplicationNodeRuntime{}
	prepared := []string{}
	runtime := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c, trust: trust, runtime: readinessFixtureRuntime{remote, t, s}, prepare: func(_ context.Context, _ privateConfigurationApplication, node string) (DeploymentRequest, error) {
		prepared = append(prepared, node)
		for _, in := range requests {
			if in.Node == node {
				return in, nil
			}
		}
		return DeploymentRequest{}, errors.New("unexpected node")
	}}
	proof, err := runtime.InspectConfigurationPhase(ctx, p)
	if err != nil || proof.State != "absent" || tableCount(t, s, "v3_deployment_jobs") != 0 {
		t.Fatal("inspection performed work or misreported pending nodes", err)
	}
	proof, err = runtime.ApplyConfigurationPhase(ctx, p)
	if err != nil || !proof.matches(p) || !reflect.DeepEqual(prepared, []string{"node-a", "node-b"}) {
		t.Fatal("real adapter failed to execute sequential child journals", proof.State, err, prepared)
	}
	forwardCalls := len(remote.calls)
	if _, err = runtime.ApplyConfigurationPhase(ctx, p); err != nil || len(remote.calls) != forwardCalls || len(prepared) != 2 {
		t.Fatal("completed phase replayed remote work", err)
	}
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, proof); err != nil {
		t.Fatal(err)
	}
	p = claimApplicationForTest(t, s, f, "after-node-runtime-test")
	p = rollbackApplicationNodesForTest(t, s, f, p)
	runtime.prepare = nil // Original child plans suffice for rollback.
	proof, err = runtime.ApplyConfigurationPhase(ctx, p)
	if err != nil || !proof.matches(p) {
		t.Fatal("real node adapter rollback failed", proof.State, err)
	}
	want := []string{"node-b:restore", "node-b:verify-rollback", "node-a:restore", "node-a:verify-rollback"}
	if !reflect.DeepEqual(remote.calls[forwardCalls:], want) {
		t.Fatal("rollback did not use reverse order", remote.calls[forwardCalls:])
	}
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, proof); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationApplicationNodeRuntimeStopsAndResumesOriginalChild(t *testing.T) {
	s, f, trust, p, requests := applicationNodesFixture(t, []string{"node-a", "node-b"})
	ctx := context.Background()
	remote := &orderedApplicationNodeRuntime{fail: "node-a:activate"}
	prepared := 0
	runtime := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c, trust: trust, runtime: readinessFixtureRuntime{remote, t, s}, prepare: func(_ context.Context, _ privateConfigurationApplication, node string) (DeploymentRequest, error) {
		prepared++
		for _, in := range requests {
			if in.Node == node {
				return in, nil
			}
		}
		return DeploymentRequest{}, ErrConflict
	}}
	if _, err := runtime.ApplyConfigurationPhase(ctx, p); err == nil {
		t.Fatal("failed child reported parent phase complete")
	}
	if tableCount(t, s, "v3_deployment_jobs") != 1 || prepared != 1 {
		t.Fatal("failure did not stop later node")
	}
	var original string
	if err := s.DB.QueryRow(`SELECT id FROM v3_deployment_jobs`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	remote.fail = ""
	proof, err := runtime.ApplyConfigurationPhase(ctx, p)
	if err != nil || !proof.matches(p) || prepared != 2 || tableCount(t, s, "v3_deployment_jobs") != 2 {
		t.Fatal("resume did not reuse original child", err)
	}
	if j := reloadDeployment(t, s, original); j.Status != "succeeded" || j.Epoch != 2 {
		t.Fatal("original failed child was replaced")
	}
}

func TestConfigurationApplicationNodeRuntimeRejectsUnverifiedOrMissingEvidence(t *testing.T) {
	s, f, trust, p, in := applicationNodeFixture(t)
	ctx := context.Background()
	runtime := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c, trust: trust, runtime: readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, s}}
	if _, err := runtime.ApplyConfigurationPhase(ctx, p); err == nil || tableCount(t, s, "v3_deployment_jobs") != 0 {
		t.Fatal("missing preparation created a child")
	}
	runtime.prepare = func(context.Context, privateConfigurationApplication, string) (DeploymentRequest, error) {
		return in, nil
	}
	if _, err := runtime.ApplyConfigurationPhase(ctx, p); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `DELETE FROM v3_node_readiness WHERE node=$1 AND kind='events'`, in.Node)
	if _, err := runtime.InspectConfigurationPhase(ctx, p); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("terminal child bypassed actual readiness checks", err)
	}
	if runtime.SupportsConfigurationPhase("bootstrap") || runtime.SupportsConfigurationPhase("verify") || runtime.SupportsConfigurationPhase("finalize") {
		t.Fatal("partial node adapter claimed complete application support")
	}
}
