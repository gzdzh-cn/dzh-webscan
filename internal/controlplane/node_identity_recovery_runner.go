package controlplane

import (
	"context"
	"errors"
	"time"
)

// Renew only a still-live, exact owner/epoch. Acquire is deliberately NOT a
// heartbeat: it could resurrect an expired lease and overlap its successor.
func (s *Store) renewNodeIdentityRecoveryLease(ctx context.Context, v *Vault, l Lease, id string) error {
	j, err := s.nodeIdentityRecovery(ctx, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) {
		return errNodeIdentityRecovery
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return err
	}
	if err := recoveryActorTx(ctx, tx, j); err != nil {
		return err
	}
	if _, err := checkNodeIdentityRecoveryTx(ctx, tx, v, j); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE v3_leases SET expires_at=LEAST(clock_timestamp()+interval '30 seconds',$4) WHERE resource=$1 AND owner=$2 AND epoch=$3 AND expires_at>clock_timestamp()`, l.Resource, l.Owner, l.Epoch, j.ExpiresAt)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrLeaseLost
	}
	return tx.Commit()
}

// Keep cancellation tied to the absolute intent deadline. Renewal errors
// immediately cancel remote work; requests never pile up or overlap. The short
// timing parameters are private test seams, not administrator configuration.
func withRecoveryHeartbeat(parent context.Context, expires time.Time, interval, timeout time.Duration, renew func(context.Context) error, work func(context.Context) error) error {
	if interval <= 0 || timeout <= 0 || renew == nil || work == nil || !time.Now().Before(expires) {
		return errNodeIdentityRecovery
	}
	deadline, stop := context.WithDeadline(parent, expires)
	defer stop()
	ctx, cancel := context.WithCancelCause(deadline)
	defer cancel(nil)
	if err := ctx.Err(); err != nil {
		return err
	}
	initial, finish := context.WithTimeout(ctx, timeout)
	err := renew(initial)
	finish()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				call, finish := context.WithTimeout(ctx, timeout)
				err := renew(call)
				finish()
				if err != nil {
					if ctx.Err() == nil {
						cancel(err)
					}
					return
				}
			}
		}
	}()
	err = work(ctx)
	cause := context.Cause(ctx)
	cancel(nil)
	<-done
	if cause != nil {
		return cause
	}
	return err
}

type identityRecoveryRuntime interface {
	prepare(context.Context, Lease, string) (nodeIdentityRecoveryJob, error)
	activate(context.Context, Lease, string) error
	start(context.Context, Lease, string) error
	verify(context.Context, Lease, string) error
	observeAndConfirm(context.Context, Lease, string) error
}

type identityRecoveryProgress struct {
	ID        string    `json:"id"`
	Node      string    `json:"node"`
	Phase     string    `json:"phase"`
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
}

// A runner executes only a previously saved administrator intent. The runtime
// uses checksum-pinned fixed commands and confirms the actual mTLS peer; no
// browser endpoint can inject an operation, destination, service or command.
// Every invocation repeats idempotent phases and re-proves readiness; it does
// not infer progress from a lost SSH response or a node's JSON claim.
type nodeIdentityRecoveryRunner struct {
	store   *Store
	vault   *Vault
	runtime identityRecoveryRuntime
}

func (w nodeIdentityRecoveryRunner) run(parent context.Context, user, id string, report func(identityRecoveryProgress) error) error {
	if w.store == nil || w.vault == nil || w.runtime == nil || report == nil || !identifier.MatchString(user) || !identifier.MatchString(id) {
		return errNodeIdentityRecovery
	}
	j, err := w.store.nodeIdentityRecovery(parent, w.vault, id)
	if err != nil || j.User != user {
		return errNodeIdentityRecovery
	}
	emit := func(phase, state string) error {
		return report(identityRecoveryProgress{j.ID, j.Node, phase, state, time.Now().UTC()})
	}
	if j.Status == "completed" {
		return emit("complete", "completed")
	}
	l, err := w.store.Acquire(parent, nodeRenewalResource(j.Node), "node-recovery-"+token())
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer stop()
		_ = w.store.Release(cleanup, l)
	}()
	return withRecoveryHeartbeat(parent, j.ExpiresAt, 10*time.Second, 3*time.Second, func(ctx context.Context) error {
		return w.store.renewNodeIdentityRecoveryLease(ctx, w.vault, l, id)
	}, func(ctx context.Context) error {
		phases := []struct {
			name string
			run  func(context.Context, Lease, string) error
		}{
			{"prepare", func(ctx context.Context, l Lease, id string) error {
				_, err := w.runtime.prepare(ctx, l, id)
				return err
			}},
			{"activate", w.runtime.activate},
			{"start", w.runtime.start},
			{"resources", w.runtime.verify},
			{"readiness", func(ctx context.Context, l Lease, id string) error {
				ready, stop := context.WithTimeout(ctx, 90*time.Second)
				defer stop()
				for {
					err := w.runtime.observeAndConfirm(ready, l, id)
					if !errors.Is(err, errNodeIdentityRecoveryNotReady) {
						return err
					}
					if _, err := w.store.checkNodeIdentityRecoveryLease(ready, w.vault, l, id); err != nil {
						return err
					}
					timer := time.NewTimer(3 * time.Second)
					select {
					case <-ready.Done():
						timer.Stop()
						return ready.Err()
					case <-timer.C:
					}
				}
			}},
		}
		for _, p := range phases {
			if _, err := w.store.checkNodeIdentityRecoveryLease(ctx, w.vault, l, id); err != nil {
				return err
			}
			if err := emit(p.name, "running"); err != nil {
				return err
			}
			if err := p.run(ctx, l, id); err != nil {
				_ = emit(p.name, "interrupted")
				return err
			}
			if err := emit(p.name, "passed"); err != nil {
				return err
			}
		}
		completed, err := w.store.nodeIdentityRecovery(ctx, w.vault, id)
		if err != nil || completed.Status != "completed" {
			return errNodeIdentityRecovery
		}
		return emit("complete", "completed")
	})
}
