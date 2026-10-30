package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNodeNameChangeLeaseRenewalCannotResurrectOrReacquire(t *testing.T) {
	for _, scenario := range []string{"valid", "expired", "successor", "wrong-owner", "wrong-epoch", "changed-actor", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeRegistryFixture(t)
			l := f.lease
			switch scenario {
			case "expired", "successor":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, l.Resource)
				if scenario == "successor" {
					if _, err := f.s.Acquire(context.Background(), l.Resource, "isolated-successor"); err != nil {
						t.Fatal(err)
					}
				}
			case "wrong-owner":
				l.Owner = "wrong-owner"
			case "wrong-epoch":
				l.Epoch++
			case "changed-actor":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "canceled":
				if _, err := f.s.cancelNodeNameChange(context.Background(), "admin", "cancel-before-heartbeat", f.job.ID); err != nil {
					t.Fatal(err)
				}
			}
			var beforeOwner string
			var beforeEpoch int64
			var beforeExpires time.Time
			if err := f.s.DB.QueryRow(`SELECT owner,epoch,expires_at FROM v3_leases WHERE resource=$1`, l.Resource).Scan(&beforeOwner, &beforeEpoch, &beforeExpires); err != nil {
				t.Fatal(err)
			}
			err := f.s.renewNodeNameChangeLease(context.Background(), f.t.vault, l, f.job.ID)
			var owner string
			var epoch int64
			var expires time.Time
			if e := f.s.DB.QueryRow(`SELECT owner,epoch,expires_at FROM v3_leases WHERE resource=$1`, l.Resource).Scan(&owner, &epoch, &expires); e != nil {
				t.Fatal(e)
			}
			if scenario == "valid" {
				if err != nil || owner != l.Owner || epoch != l.Epoch || !expires.After(beforeExpires) || expires.After(f.job.ExpiresAt) {
					t.Fatal("live lease not renewed within intent", err)
				}
			} else if err == nil || owner != beforeOwner || epoch != beforeEpoch || !expires.Equal(beforeExpires) {
				t.Fatal("failed heartbeat mutated or resurrected lease", err)
			}
		})
	}
}

type nameChangeRunnerFixtureRuntime struct {
	f          nameChangeRegistryFixture
	signed     signedNodeRenewal
	calls      []string
	fail       string
	claimed    Lease
	startBlock chan struct{}
	hook       func(string, Lease)
}

func (r *nameChangeRunnerFixtureRuntime) prepare(ctx context.Context, l Lease, id string) (nodeNameChangeJob, error) {
	r.calls = append(r.calls, "prepare")
	r.claimed = l
	raw, err := json.Marshal(r.f.request)
	if err != nil {
		return nodeNameChangeJob{}, err
	}
	return r.f.s.admitNodeNameChange(ctx, r.f.t.vault, l, id, raw)
}

// This fixture tests durable orchestration, not SSH, a real service manager or
// mTLS. Those have independent transport, readiness and kernel acceptance tests.
func (r *nameChangeRunnerFixtureRuntime) stage(name string, l Lease) error {
	r.calls = append(r.calls, name)
	if r.hook != nil {
		r.hook(name, l)
	}
	if r.fail == name {
		return errors.New("isolated " + name + " failure")
	}
	return nil
}

func (r *nameChangeRunnerFixtureRuntime) activate(ctx context.Context, l Lease, id string) error {
	signed, err := r.f.s.signNodeNameChange(ctx, r.f.c, r.f.t.vault, l, id)
	if err != nil {
		return err
	}
	r.signed = signed
	if err := r.stage("activate", l); err != nil {
		return err
	}
	if r.startBlock != nil {
		close(r.startBlock)
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (r *nameChangeRunnerFixtureRuntime) verify(_ context.Context, l Lease, _ string) error {
	return r.stage("resources", l)
}

func (r *nameChangeRunnerFixtureRuntime) observeAndConfirm(ctx context.Context, l Lease, id string) error {
	if err := r.stage("readiness", l); err != nil {
		return err
	}
	if r.fail == "false-completion" {
		return nil
	}
	peer, err := provisioningCertificate(r.signed.Certificate)
	if err != nil {
		return err
	}
	return r.f.s.confirmNodeNameChange(ctx, r.f.c, r.f.t.vault, l, id, peer)
}

func newNameChangeRunner(t *testing.T) (nodeNameChangeRunner, *nameChangeRunnerFixtureRuntime) {
	t.Helper()
	f := newNameChangeRegistryFixture(t)
	if err := f.s.Release(context.Background(), f.lease); err != nil {
		t.Fatal(err)
	}
	r := &nameChangeRunnerFixtureRuntime{f: f}
	return nodeNameChangeRunner{store: f.s, vault: f.t.vault, runtime: r}, r
}

func TestNodeNameChangeRunnerResumesExactIssuanceAndCompletesDurably(t *testing.T) {
	w, r := newNameChangeRunner(t)
	ctx := context.Background()
	var progress []nameChangeProgress
	report := func(p nameChangeProgress) error { progress = append(progress, p); return nil }
	r.fail = "activate" // Signing committed, but the remote response was lost.
	if err := w.run(ctx, "admin", r.f.job.ID, report); err == nil {
		t.Fatal("lost response accepted")
	}
	first := append([]byte(nil), r.signed.Certificate...)
	if len(first) == 0 {
		t.Fatal("fixture did not commit issuance")
	}
	r.fail = ""
	r.calls = nil
	if err := w.run(ctx, "admin", r.f.job.ID, report); err != nil {
		t.Fatal("resume", err)
	}
	if !bytes.Equal(first, r.signed.Certificate) || tableCount(t, r.f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("resume replaced committed issuance")
	}
	want := []string{"prepare", "activate", "resources", "readiness"}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatal("wrong phase sequence", r.calls)
	}
	j, err := r.f.s.nodeNameChange(ctx, r.f.t.vault, r.f.job.ID)
	if err != nil || j.Status != "completed" || progress[len(progress)-1].Status != "completed" {
		t.Fatal("not durably completed", err)
	}
	var audits int
	if err := r.f.s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='complete-node-name-change'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("completion audit", err, audits)
	}
	r.calls = nil
	if err := w.run(ctx, "admin", j.ID, report); err != nil || len(r.calls) != 0 {
		t.Fatal("completed replay touched remote", err)
	}
}

func TestNodeNameChangeRunnerStopsAtFailedEvidenceOrFence(t *testing.T) {
	for _, scenario := range []string{"resources", "false-completion", "progress", "wrong-actor", "lost-lease", "changed-actor"} {
		t.Run(scenario, func(t *testing.T) {
			w, r := newNameChangeRunner(t)
			user := "admin"
			if scenario == "resources" || scenario == "false-completion" {
				r.fail = scenario
			}
			if scenario == "wrong-actor" {
				user = "other-admin"
			}
			r.hook = func(phase string, l Lease) {
				if phase != "activate" {
					return
				}
				if scenario == "lost-lease" {
					mustHistoryExec(t, r.f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, l.Resource)
				}
				if scenario == "changed-actor" {
					mustHistoryExec(t, r.f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
				}
			}
			err := w.run(context.Background(), user, r.f.job.ID, func(p nameChangeProgress) error {
				if scenario == "progress" && p.Phase == "activate" {
					return errors.New("output closed")
				}
				return nil
			})
			if err == nil {
				t.Fatal("unproved recovery completed")
			}
			var status string
			e := r.f.s.DB.QueryRow(`SELECT status FROM v3_node_name_changes WHERE id=$1`, r.f.job.ID).Scan(&status)
			if e != nil || status == "completed" {
				t.Fatal("failed run recorded completion", e)
			}
			calls := strings.Join(r.calls, ",")
			if scenario == "wrong-actor" && calls != "" {
				t.Fatal("wrong actor reached remote")
			}
			if scenario == "progress" && calls != "prepare" {
				t.Fatal("ignored progress failure", calls)
			}
			if scenario != "false-completion" && strings.Contains(calls, "readiness") {
				t.Fatal("continued after failed proof", calls)
			}
		})
	}
}

func TestNodeNameChangeRunnerLostLeaseCancelsBlockedRemote(t *testing.T) {
	w, r := newNameChangeRunner(t)
	r.startBlock = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.run(ctx, "admin", r.f.job.ID, func(nameChangeProgress) error { return nil }) }()
	select {
	case <-r.startBlock:
	case err := <-done:
		t.Fatal("did not reach blocking remote", err)
	case <-ctx.Done():
		t.Fatal("no remote startup")
	}
	mustHistoryExec(t, r.f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, r.claimed.Resource)
	select {
	case err := <-done:
		if !errors.Is(err, ErrLeaseLost) {
			t.Fatal("heartbeat lost cancellation cause", err)
		}
	case <-ctx.Done():
		t.Fatal("lost lease did not cancel remote")
	}
	if strings.Contains(strings.Join(r.calls, ","), "resources") {
		t.Fatal("continued after cancellation")
	}
}
