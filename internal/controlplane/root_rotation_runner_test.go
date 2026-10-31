package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/nodeops"
	"webscan/internal/nodepki"
)

// This fixture exercises real node-local PKI and durable SQL orchestration.
// It is not SSH, a kernel resource proof, or a fresh gRPC acceptance gate.
type rootRunnerFixture struct {
	t            *testing.T
	f            renewalRegistryFixture
	floor        string
	fail         string
	observations int
	operations   []string
}

func (r *rootRunnerFixture) operation(ctx context.Context, l Lease, id string, index int, operation string) (nodeops.RootRotationOutput, error) {
	r.t.Helper()
	j, err := r.f.s.checkRootTask(ctx, r.f.c, r.f.t.vault, l, id)
	if err != nil {
		return nodeops.RootRotationOutput{}, err
	}
	m, state := j.Members[index], j.State[index]
	r.operations = append(r.operations, operation)
	raw, _ := json.Marshal(j.Roots)
	if _, err := nodepki.PublishRootSet(ctx, r.floor, j.Anchor, raw, time.Now()); err != nil {
		return nodeops.RootRotationOutput{}, err
	}
	out := nodeops.RootRotationOutput{Format: 1, Operation: operation, Node: m.ID, Snapshot: digest(raw), Phase: "dual"}
	if j.Roots.Final != nil {
		out.Phase = "new-only"
	}
	expected, _ := rootMemberCertificateSHA(m)
	switch operation {
	case "prepare":
		request, err := nodepki.PrepareRootIdentity(ctx, r.f.c.Collector.CAFile, r.f.identity, r.floor, nodepki.Node, m.ID, nodepki.RootAuthorizationSHA256(j.Roots.Dual), expected, time.Now())
		if err != nil {
			return out, err
		}
		out.Request, _ = json.Marshal(request)
	case "activate":
		request, err := nodepki.ParseRootIdentityRequest(state.Request)
		if err != nil {
			return out, err
		}
		if _, err := nodepki.ActivateRootIdentity(ctx, r.f.c.Collector.CAFile, r.f.identity, r.floor, nodepki.Node, m.ID, request.Authorization, expected, request.SHA256(), state.Certificate, time.Now()); err != nil {
			return out, err
		}
	case "verify":
		out.ResourcesVerified = true
	case "trust":
	default:
		return out, errors.New("unfixed operation")
	}
	if r.fail == operation {
		return out, errors.New("isolated response lost after " + operation)
	}
	return out, nil
}

func (r *rootRunnerFixture) observe(ctx context.Context, l Lease, id string, index int) (*x509.Certificate, error) {
	r.observations++
	if r.fail == "observe" {
		return nil, errors.New("isolated collection unavailable")
	}
	j, err := r.f.s.checkRootTask(ctx, r.f.c, r.f.t.vault, l, id)
	if err != nil {
		return nil, err
	}
	b, _, err := nodepki.ReadIdentityWithRootState(r.f.c.Collector.CAFile, r.f.identity, r.floor, nodepki.Node, j.Members[index].ID, time.Now())
	defer clear(b.Key)
	if err != nil {
		return nil, err
	}
	return provisioningCertificate(b.Certificate)
}

func newRootRunnerFixture(t *testing.T) (rootRotationRunner, *rootRunnerFixture, rootRotationTask) {
	t.Helper()
	f, in := rootTaskFixture(t)
	floor := filepath.Join(filepath.Dir(f.identity), "root-node-floor")
	if _, err := nodepki.NewReceiverTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, floor, time.Now()); err != nil {
		t.Fatal(err)
	}
	j, err := f.s.prepareRootRotation(context.Background(), f.c, f.t.vault, "admin", "root-runner", f.t.release, in)
	if err != nil {
		t.Fatal(err)
	}
	r := &rootRunnerFixture{t: t, f: f, floor: floor}
	return rootRotationRunner{store: f.s, vault: f.t.vault, config: f.c, release: f.t.release, runtime: r}, r, j
}

func TestRootRunnerLostActivationResponseResumesExactIssuanceAndFinalizesSeparately(t *testing.T) {
	w, r, j := newRootRunnerFixture(t)
	ctx := context.Background()
	var progress []rootRotationProgress
	report := func(p rootRotationProgress) error { progress = append(progress, p); return nil }
	if err := w.run(ctx, "admin", j.ID, true, report); err == nil {
		t.Fatal("old root retired before an explicit ready task")
	}
	r.fail = "activate"
	if err := w.run(ctx, "admin", j.ID, false, report); err == nil {
		t.Fatal("lost SSH response marked complete")
	}
	partial, _, err := r.f.s.readRootTask(ctx, w.vault, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if partial.Status != "dual" || partial.Roots.Final != nil {
		t.Fatal("partial rollout removed old root")
	}
	var issued []byte
	for i, m := range partial.Members {
		if m.Role == nodepki.Node {
			issued = append([]byte(nil), partial.State[i].Certificate...)
			if partial.State[i].Activated || len(issued) == 0 {
				t.Fatal("lost response forged activation")
			}
		}
	}
	r.fail = ""
	if err := w.run(ctx, "admin", j.ID, false, report); err != nil {
		t.Fatal("resume", err)
	}
	ready, _, err := r.f.s.readRootTask(ctx, w.vault, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Status != "ready" || ready.Roots.Final != nil || r.observations == 0 || tableCount(t, r.f.s, "v3_root_identity_issuances") != 2 {
		t.Fatal("missing durable dual rollout")
	}
	for i, m := range ready.Members {
		if m.Role == nodepki.Node && !bytes.Equal(ready.State[i].Certificate, issued) {
			t.Fatal("response loss reissued a leaf")
		}
	}
	if err := w.run(ctx, "admin", j.ID, true, report); err != nil {
		t.Fatal("finalize", err)
	}
	final, _, err := r.f.s.readRootTask(ctx, w.vault, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != "completed" || final.Roots.Final == nil {
		t.Fatal("not finalized")
	}
	// A last heartbeat racing the final checkpoint must not turn a committed
	// success into an error. Ordinary host work remains forbidden afterwards.
	l, err := r.f.s.Acquire(ctx, "pki-root-rotation", "final-heartbeat")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.f.s.renewRootTaskLease(ctx, w.config, w.vault, l, j.ID); err != nil {
		t.Fatal("completion heartbeat race", err)
	}
	if _, err := r.f.s.checkRootTask(ctx, w.config, w.vault, l, j.ID); err == nil {
		t.Fatal("completed task authorized further host work")
	}
	if err := r.f.s.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	for _, state := range final.State {
		if !state.Final || state.ObservedAt.IsZero() {
			t.Fatal("unconfirmed member finalized")
		}
	}
	if err := w.run(ctx, "admin", j.ID, false, report); err != nil {
		t.Fatal("completed replay", err)
	}
	_, receipt, err := nodepki.ReadRootSet(r.floor, j.Anchor, time.Now())
	if err != nil || receipt.Phase != "new-only" {
		t.Fatal("node old root not retired", err)
	}
	_, receipt, err = nodepki.ReadRootSet(w.config.Collector.RevocationStateDirectory, j.Anchor, time.Now())
	if err != nil || receipt.Phase != "new-only" {
		t.Fatal("collector old root not retired", err)
	}
	if tableCount(t, r.f.s, "v3_root_identity_issuances") != 2 {
		t.Fatal("finalization duplicated issuance")
	}
}

func TestRootRunnerResourceOrCollectionFailureCannotFinalize(t *testing.T) {
	for _, failure := range []string{"verify", "observe"} {
		t.Run(failure, func(t *testing.T) {
			w, r, j := newRootRunnerFixture(t)
			r.fail = failure
			if err := w.run(context.Background(), "admin", j.ID, false, func(rootRotationProgress) error { return nil }); err == nil {
				t.Fatal("failed readiness accepted")
			}
			current, _, err := r.f.s.readRootTask(context.Background(), w.vault, j.ID)
			if err != nil || current.Status != "dual" || current.Roots.Final != nil {
				t.Fatal("failed task retired old root", err)
			}
		})
	}
}

func TestRootTaskBackupKeepsIssuancesButRequiresNewAuthorization(t *testing.T) {
	w, r, j := newRootRunnerFixture(t)
	ctx := context.Background()
	if err := w.run(ctx, "admin", j.ID, false, func(rootRotationProgress) error { return nil }); err != nil {
		t.Fatal(err)
	}
	backup, err := r.f.s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, backup); err != nil {
		t.Fatal("restore dual-root task", err)
	}
	restored, hold, err := target.readRootTask(ctx, w.vault, j.ID)
	if err != nil || !hold || restored.Status != "ready" || tableCount(t, target, "v3_root_identity_issuances") != 2 {
		t.Fatal("restore lost ancestry or permission hold", err)
	}
	r.f.s = target
	w.store = target
	if err := w.run(ctx, "admin", j.ID, false, func(rootRotationProgress) error { return nil }); err == nil {
		t.Fatal("archived task resumed without new authorization")
	}
	mustHistoryExec(t, target.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second';UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
	restored, err = target.controlRootTask(ctx, w.config, w.vault, "admin", "reauthorize-after-restore", j.ID, false)
	if err != nil {
		t.Fatal("reauthorize", err)
	}
	if restored.MembersSHA256 != j.MembersSHA256 {
		t.Fatal("reauthorization changed members")
	}
	if err := w.run(ctx, "admin", j.ID, true, func(rootRotationProgress) error { return nil }); err != nil {
		t.Fatal("restored finalization", err)
	}
	if tableCount(t, target, "v3_root_identity_issuances") != 2 {
		t.Fatal("restore reissued a leaf")
	}
}
