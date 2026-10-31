package controlplane

import (
	"context"
	"errors"
	"time"
)

// Renew only a still-live, exact owner/epoch. Acquire is deliberately NOT a
// heartbeat: it could resurrect an expired lease and overlap its successor.
func (s *Store) renewNodeNamePruningLease(ctx context.Context, c Config, v *Vault, l Lease, id string) error {
	j, err := s.nodeNamePruning(ctx, c, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) {
		return errNodeNamePruning
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return err
	}
	if err := pruningActorTx(ctx, tx, j); err != nil {
		return err
	}
	if _, err := checkNodeNamePruningTx(ctx, tx, c, v, j); err != nil {
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

type namePruningRuntime interface {
	prepare(context.Context, Lease, string) (nodeNamePruningJob, error)
	activate(context.Context, Lease, string) error
	verify(context.Context, Lease, string) error
	observeAndConfirm(context.Context, Lease, string) error
}

type namePruningProgress struct {
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
type nodeNamePruningRunner struct {
	config  Config
	store   *Store
	vault   *Vault
	runtime namePruningRuntime
}

func (w nodeNamePruningRunner) run(parent context.Context, user, id string, report func(namePruningProgress) error) error {
	if w.store == nil || w.vault == nil || w.runtime == nil || report == nil || !identifier.MatchString(user) || !identifier.MatchString(id) {
		return errNodeNamePruning
	}
	j, err := w.store.nodeNamePruning(parent, w.config, w.vault, id)
	if err != nil || j.User != user {
		return errNodeNamePruning
	}
	emit := func(phase, state string) error {
		return report(namePruningProgress{j.ID, j.Node, phase, state, time.Now().UTC()})
	}
	if j.Status == "completed" {
		return emit("complete", "completed")
	}
	l, err := w.store.Acquire(parent, nodeRenewalResource(j.Node), "node-name-pruning-"+token())
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer stop()
		_ = w.store.Release(cleanup, l)
	}()
	return withRecoveryHeartbeat(parent, j.ExpiresAt, 10*time.Second, 3*time.Second, func(ctx context.Context) error {
		return w.store.renewNodeNamePruningLease(ctx, w.config, w.vault, l, id)
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
					if !errors.Is(err, errNodeNamePruningNotReady) {
						return err
					}
					if _, err := w.store.checkNodeNamePruningLease(ready, w.config, w.vault, l, id); err != nil {
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
			if _, err := w.store.checkNodeNamePruningLease(ctx, w.config, w.vault, l, id); err != nil {
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
		completed, err := w.store.nodeNamePruning(ctx, w.config, w.vault, id)
		if err != nil || completed.Status != "completed" {
			return errNodeNamePruning
		}
		return emit("complete", "completed")
	})
}
