package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNodeIdentityRecoveryHeartbeatCancelsWithoutOverlap(t *testing.T) {
	failed := errors.New("isolated renewal failed")
	var calls, active, maximum atomic.Int32
	err := withRecoveryHeartbeat(context.Background(), time.Now().Add(time.Second), 2*time.Millisecond, 100*time.Millisecond, func(ctx context.Context) error {
		n := active.Add(1)
		defer active.Add(-1)
		if n > maximum.Load() {
			maximum.Store(n)
		}
		count := calls.Add(1)
		if count == 1 {
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		if count == 4 {
			return failed
		}
		return nil
	}, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, failed) || calls.Load() != 4 || maximum.Load() != 1 || active.Load() != 0 {
		t.Fatal("heartbeat overlapped, lost cause or leaked renewal", err, calls.Load(), maximum.Load(), active.Load())
	}
}

func TestNodeIdentityRecoveryHeartbeatInitialFenceAndAbsoluteExpiry(t *testing.T) {
	for _, scenario := range []string{"renewal-failed", "parent-canceled", "intent-expired", "absolute-deadline", "work-failed", "finished"} {
		t.Run(scenario, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			expires := time.Now().Add(time.Second)
			if scenario == "parent-canceled" {
				cancel()
			}
			if scenario == "intent-expired" {
				expires = time.Now().Add(-time.Second)
			}
			if scenario == "absolute-deadline" {
				expires = time.Now().Add(20 * time.Millisecond)
			}
			failed := errors.New("isolated failure")
			calls := 0
			err := withRecoveryHeartbeat(parent, expires, time.Hour, 50*time.Millisecond, func(context.Context) error {
				if scenario == "renewal-failed" {
					return failed
				}
				return nil
			}, func(ctx context.Context) error {
				calls++
				if scenario == "absolute-deadline" {
					<-ctx.Done()
					return ctx.Err()
				}
				if scenario == "work-failed" {
					return failed
				}
				return nil
			})
			if scenario == "finished" {
				if err != nil || calls != 1 {
					t.Fatal("successful work failed", err)
				}
			} else if err == nil {
				t.Fatal("lost heartbeat/deadline/work error")
			}
			if scenario == "renewal-failed" || scenario == "parent-canceled" || scenario == "intent-expired" {
				if calls != 0 {
					t.Fatal("unfenced work began")
				}
			}
		})
	}
}

func TestNodeIdentityRecoveryLeaseRenewalCannotResurrectOrReacquire(t *testing.T) {
	for _, scenario := range []string{"valid", "expired", "successor", "wrong-owner", "wrong-epoch", "changed-actor", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newIdentityRecoveryFixture(t)
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
				if _, err := f.s.cancelNodeIdentityRecovery(context.Background(), "admin", "cancel-before-heartbeat", f.job.ID); err != nil {
					t.Fatal(err)
				}
			}
			var beforeOwner string
			var beforeEpoch int64
			var beforeExpires time.Time
			if err := f.s.DB.QueryRow(`SELECT owner,epoch,expires_at FROM v3_leases WHERE resource=$1`, l.Resource).Scan(&beforeOwner, &beforeEpoch, &beforeExpires); err != nil {
				t.Fatal(err)
			}
			err := f.s.renewNodeIdentityRecoveryLease(context.Background(), f.t.vault, l, f.job.ID)
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

type recoveryRunnerFixtureRuntime struct {
	f          identityRecoveryFixture
	signed     signedNodeRenewal
	calls      []string
	fail       string
	claimed    Lease
	startBlock chan struct{}
	hook       func(string, Lease)
}

func (r *recoveryRunnerFixtureRuntime) prepare(ctx context.Context, l Lease, id string) (nodeIdentityRecoveryJob, error) {
	r.calls = append(r.calls, "prepare")
	r.claimed = l
	raw, err := json.Marshal(r.f.request)
	if err != nil {
		return nodeIdentityRecoveryJob{}, err
	}
	return r.f.s.admitNodeIdentityRecovery(ctx, r.f.t.vault, l, id, raw)
}

// This fixture tests durable orchestration, not SSH, a real service manager or
// mTLS. Those have independent transport, readiness and kernel acceptance tests.
func (r *recoveryRunnerFixtureRuntime) stage(name string, l Lease) error {
	r.calls = append(r.calls, name)
	if r.hook != nil {
		r.hook(name, l)
	}
	if r.fail == name {
		return errors.New("isolated " + name + " failure")
	}
	return nil
}

func (r *recoveryRunnerFixtureRuntime) activate(ctx context.Context, l Lease, id string) error {
	signed, err := r.f.s.signNodeIdentityRecovery(ctx, r.f.c, r.f.t.vault, l, id)
	if err != nil {
		return err
	}
	r.signed = signed
	return r.stage("activate", l)
}

func (r *recoveryRunnerFixtureRuntime) start(ctx context.Context, l Lease, id string) error {
	if err := r.stage("start", l); err != nil {
		return err
	}
	if r.startBlock != nil {
		close(r.startBlock)
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (r *recoveryRunnerFixtureRuntime) verify(_ context.Context, l Lease, _ string) error {
	return r.stage("resources", l)
}

func (r *recoveryRunnerFixtureRuntime) observeAndConfirm(ctx context.Context, l Lease, id string) error {
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
	return r.f.s.confirmNodeIdentityRecovery(ctx, r.f.c, r.f.t.vault, l, id, peer)
}

func newRecoveryRunner(t *testing.T) (nodeIdentityRecoveryRunner, *recoveryRunnerFixtureRuntime) {
	t.Helper()
	f := newIdentityRecoveryFixture(t)
	if err := f.s.Release(context.Background(), f.lease); err != nil {
		t.Fatal(err)
	}
	r := &recoveryRunnerFixtureRuntime{f: f}
	return nodeIdentityRecoveryRunner{store: f.s, vault: f.t.vault, runtime: r}, r
}

func TestNodeIdentityRecoveryRunnerResumesExactIssuanceAndCompletesDurably(t *testing.T) {
	w, r := newRecoveryRunner(t)
	ctx := context.Background()
	var progress []identityRecoveryProgress
	report := func(p identityRecoveryProgress) error { progress = append(progress, p); return nil }
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
	want := []string{"prepare", "activate", "start", "resources", "readiness"}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatal("wrong phase sequence", r.calls)
	}
	j, err := r.f.s.nodeIdentityRecovery(ctx, r.f.t.vault, r.f.job.ID)
	if err != nil || j.Status != "completed" || progress[len(progress)-1].Status != "completed" {
		t.Fatal("not durably completed", err)
	}
	var audits int
	if err := r.f.s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='complete-node-identity-recovery'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("completion audit", err, audits)
	}
	r.calls = nil
	if err := w.run(ctx, "admin", j.ID, report); err != nil || len(r.calls) != 0 {
		t.Fatal("completed replay touched remote", err)
	}
}

func TestNodeIdentityRecoveryRunnerStopsAtFailedEvidenceOrFence(t *testing.T) {
	for _, scenario := range []string{"resources", "false-completion", "progress", "wrong-actor", "lost-lease", "changed-actor"} {
		t.Run(scenario, func(t *testing.T) {
			w, r := newRecoveryRunner(t)
			user := "admin"
			if scenario == "resources" || scenario == "false-completion" {
				r.fail = scenario
			}
			if scenario == "wrong-actor" {
				user = "other-admin"
			}
			r.hook = func(phase string, l Lease) {
				if phase != "start" {
					return
				}
				if scenario == "lost-lease" {
					mustHistoryExec(t, r.f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, l.Resource)
				}
				if scenario == "changed-actor" {
					mustHistoryExec(t, r.f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
				}
			}
			err := w.run(context.Background(), user, r.f.job.ID, func(p identityRecoveryProgress) error {
				if scenario == "progress" && p.Phase == "activate" {
					return errors.New("output closed")
				}
				return nil
			})
			if err == nil {
				t.Fatal("unproved recovery completed")
			}
			var status string
			e := r.f.s.DB.QueryRow(`SELECT status FROM v3_node_identity_recoveries WHERE id=$1`, r.f.job.ID).Scan(&status)
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

func TestNodeIdentityRecoveryRunnerLostLeaseCancelsBlockedRemote(t *testing.T) {
	w, r := newRecoveryRunner(t)
	r.startBlock = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.run(ctx, "admin", r.f.job.ID, func(identityRecoveryProgress) error { return nil }) }()
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
