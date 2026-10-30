package controlplane

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Private adapters only. An implementation must durably fence the job/epoch
// before inspecting side effects, revalidate its live inputs, and return
// complete only after the actual phase receipts have been verified. A center
// restart needs a durable handoff; returning from a restart request is not a
// bootstrap completion receipt. No public submission accepts these objects.
type configurationApplicationRuntime interface {
	SupportsConfigurationPhase(string) bool
	InspectConfigurationPhase(context.Context, privateConfigurationApplication) (configurationApplicationCheckpoint, error)
	ApplyConfigurationPhase(context.Context, privateConfigurationApplication) (configurationApplicationCheckpoint, error)
}

func configurationApplicationFailure(phase string) string {
	switch phase {
	case "environment":
		return "environment-failed"
	case "nodes", "restore-nodes":
		return "deployment-failed"
	case "bootstrap", "restore-bootstrap":
		return "bootstrap-failed"
	case "settings", "restore-settings":
		return "settings-failed"
	default:
		return "verification-failed"
	}
}

// Implemented by the composed production runtime for verification phases. Its
// final SQL checks and checkpoint must share one transaction, rather than trust
// an earlier inspection across a race window.
type configurationApplicationAtomicCheckpoint interface {
	checkpointConfigurationPhase(context.Context, privateConfigurationApplication, configurationApplicationCheckpoint) error
}

// Execute one phase, renewing ownership throughout network/remote work. The
// next phase is claimed/executed from its durable state, not an in-memory loop.
// A partial adapter can run harmless checks but cannot arm any switching until
// every remaining phase AND every rollback phase is actually supported.
func (s *Store) executeConfigurationApplication(ctx context.Context, v *Vault, j privateConfigurationApplication, r configurationApplicationRuntime) error {
	if r == nil || !r.SupportsConfigurationPhase(j.phase()) {
		if e := s.failConfigurationApplication(ctx, v, j, "runtime-unavailable"); e != nil {
			return e
		}
		return errConfigurationApplication
	}
	if j.Direction == "rollback" {
		for _, phase := range configurationApplicationRollback[j.rollbackStep:] {
			if !r.SupportsConfigurationPhase(phase) {
				if e := s.failConfigurationApplication(ctx, v, j, "runtime-unavailable"); e != nil {
					return e
				}
				return errConfigurationApplication
			}
		}
	}
	if j.Direction == "forward" && j.step > 0 {
		for _, p := range append(append([]string{}, configurationApplicationForward[j.step:]...), configurationApplicationRollback...) {
			if !r.SupportsConfigurationPhase(p) {
				if e := s.failConfigurationApplication(ctx, v, j, "runtime-unavailable"); e != nil {
					return e
				}
				return errConfigurationApplication
			}
		}
		var e error
		j, e = s.armConfigurationApplication(ctx, v, j)
		if e != nil {
			return e
		}
	} else if e := s.renewConfigurationApplication(ctx, v, j); e != nil {
		return e
	}
	op, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	lost := make(chan error, 1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-op.Done():
				return
			case <-tick.C:
				probe, stop := context.WithTimeout(op, 5*time.Second)
				e := s.renewConfigurationApplication(probe, v, j)
				stop()
				if e != nil {
					lost <- e
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); wg.Wait() }()
	p, e := r.InspectConfigurationPhase(op, j)
	if e == nil {
		if p.Job != j.ID || p.Plan != j.planProof || p.Phase != j.phase() || p.Epoch != j.epoch {
			e = errConfigurationApplication
		} else if p.State == "absent" {
			p, e = r.ApplyConfigurationPhase(op, j)
		} else if p.State != "complete" && !(p.State == "pending" && (j.phase() == "bootstrap" || j.phase() == "restore-bootstrap")) {
			e = errConfigurationApplication
		}
	}
	// Stop renewal before committing a new phase, otherwise an old step's
	// renewal could race the new step and falsely cancel a completed operation.
	cancel()
	wg.Wait()
	select {
	case leaseError := <-lost:
		return leaseError
	default:
	}
	if ctx.Err() != nil {
		return ctx.Err()
	} // Expired lease is recovered by a new fenced owner.
	if e == nil && p.Job == j.ID && p.Plan == j.planProof && p.Phase == j.phase() && p.Epoch == j.epoch && p.State == "pending" && (j.phase() == "bootstrap" || j.phase() == "restore-bootstrap") {
		// Durable handoff already owns recovery responsibility. The departing
		// process leaves its lease to expire; a fresh owner must inspect actual
		// role receipts before checkpointing. Do not claim restart as success.
		return errBootstrapHandoff
	}
	if e != nil || !p.matches(j) {
		if fail := s.failConfigurationApplication(ctx, v, j, configurationApplicationFailure(j.phase())); fail != nil {
			return fail
		}
		return errConfigurationApplication
	}
	if atomic, ok := r.(configurationApplicationAtomicCheckpoint); ok {
		return atomic.checkpointConfigurationPhase(ctx, j, p)
	}
	_, e = s.checkpointConfigurationApplication(ctx, v, j, p)
	return e
}

// The first real adapter executes only the nonmutating environment phase. It
// deliberately declares every switching phase unsupported; it is NOT installed
// in Serve and cannot be used to mark an application complete. Full runtime
// adapters must implement nodes, bootstrap, settings, verification and rollback.
type configurationEnvironmentRuntime struct {
	store     *Store
	vault     *Vault
	bootstrap Config
}

func (r configurationEnvironmentRuntime) SupportsConfigurationPhase(phase string) bool {
	return phase == "environment"
}
func (r configurationEnvironmentRuntime) InspectConfigurationPhase(_ context.Context, j privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "absent", j.epoch}, nil
}
func (r configurationEnvironmentRuntime) ApplyConfigurationPhase(ctx context.Context, j privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	if r.store == nil || r.vault == nil || j.phase() != "environment" || j.Direction != "forward" || j.member != r.bootstrap.Central.Instance {
		return configurationApplicationCheckpoint{}, errConfigurationApplication
	}
	out, e := r.store.inspectApplicationEnvironment(ctx, r.vault, r.bootstrap, j.Username, j.Stage, &j)
	if e != nil || !out.PreflightPassed || out.Generation != j.Generation {
		return configurationApplicationCheckpoint{}, errors.New("应用前环境诊断未通过")
	}
	return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "complete", j.epoch}, nil
}
