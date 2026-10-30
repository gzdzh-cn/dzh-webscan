package controlplane

import (
	"context"
	"errors"
	"time"
)

// Renew only a still-live, exact owner/epoch. Acquire is deliberately NOT a
// heartbeat: it could resurrect an expired lease and overlap its successor.
func (s *Store) renewNodeNameChangeLease(ctx context.Context, v *Vault, l Lease, id string) error {
	j, err := s.nodeNameChange(ctx, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) {
		return errNodeNameChange
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return err
	}
	if err := nameChangeActorTx(ctx, tx, j); err != nil {
		return err
	}
	if _, err := checkNodeNameChangeTx(ctx, tx, v, j); err != nil {
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

type nameChangeRuntime interface {
	prepare(context.Context, Lease, string) (nodeNameChangeJob, error)
	activate(context.Context, Lease, string) error
	verify(context.Context, Lease, string) error
	observeAndConfirm(context.Context, Lease, string) error
}

type nameChangeProgress struct {
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
type nodeNameChangeRunner struct {
	store   *Store
	vault   *Vault
	runtime nameChangeRuntime
}

func (w nodeNameChangeRunner) run(parent context.Context, user, id string, report func(nameChangeProgress) error) error {
	if w.store == nil || w.vault == nil || w.runtime == nil || report == nil || !identifier.MatchString(user) || !identifier.MatchString(id) {
		return errNodeNameChange
	}
	j, err := w.store.nodeNameChange(parent, w.vault, id)
	if err != nil || j.User != user {
		return errNodeNameChange
	}
	emit := func(phase, state string) error {
		return report(nameChangeProgress{j.ID, j.Node, phase, state, time.Now().UTC()})
	}
	if j.Status == "completed" {
		return emit("complete", "completed")
	}
	l, err := w.store.Acquire(parent, nodeRenewalResource(j.Node), "node-name-change-"+token())
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer stop()
		_ = w.store.Release(cleanup, l)
	}()
	return withRecoveryHeartbeat(parent, j.ExpiresAt, 10*time.Second, 3*time.Second, func(ctx context.Context) error {
		return w.store.renewNodeNameChangeLease(ctx, w.vault, l, id)
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
			{"resources", w.runtime.verify},
			{"readiness", func(ctx context.Context, l Lease, id string) error {
				ready, stop := context.WithTimeout(ctx, 90*time.Second)
				defer stop()
				for {
					err := w.runtime.observeAndConfirm(ready, l, id)
					if !errors.Is(err, errNodeNameChangeNotReady) {
						return err
					}
					if _, err := w.store.checkNodeNameChangeLease(ready, w.vault, l, id); err != nil {
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
			if _, err := w.store.checkNodeNameChangeLease(ctx, w.vault, l, id); err != nil {
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
		completed, err := w.store.nodeNameChange(ctx, w.vault, id)
		if err != nil || completed.Status != "completed" {
			return errNodeNameChange
		}
		return emit("complete", "completed")
	})
}
