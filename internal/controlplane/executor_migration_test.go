package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestExecutorPausesDuringMigrationWithoutRemoteEffectsOrTaskFailure(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := deploymentFixture(t, s)
	createDeployment(t, s, in, "migration-executor")
	mustHistoryExec(t, s.DB, "INSERT INTO v3_migration_domains(domain,source) VALUES('fixture',$1)", strings.Repeat("a", 64))
	if _, err := s.ClaimDeployment(ctx, "executor"); !errors.Is(err, ErrMigrationPending) {
		t.Fatal("claimed during migration", err)
	}
	jobs, err := s.Deployments(ctx, time.Time{}, "", "", 20)
	if err != nil || len(jobs) != 1 || jobs[0].Status != "queued" || jobs[0].Epoch != 0 {
		t.Fatal("paused task changed", err)
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_migration_domains SET pending=false")
	j := claimDeployment(t, s, "executor")
	mustHistoryExec(t, s.DB, "UPDATE v3_migration_domains SET pending=true")
	remote := &fakeDeploymentRuntime{}
	if err := (&DeploymentRunner{Store: s, Runtime: remote}).Execute(ctx, j); !errors.Is(err, ErrMigrationPending) {
		t.Fatal("freeze ignored", err)
	}
	if len(remote.calls) != 0 {
		t.Fatal("connected during migration")
	}
	if err := s.CompleteDeploymentPhase(ctx, j); !errors.Is(err, ErrMigrationPending) {
		t.Fatal("advanced during migration", err)
	}
	paused := reloadDeployment(t, s, j.ID)
	if paused.Status != "running" || paused.Step != 0 || paused.ErrorCode != "" || paused.RecoveryRequired {
		t.Fatal("freeze caused destructive failure state")
	}
	// Once the freeze ends the same task is eligible for normal continuation;
	// no explicit failure recovery is needed, and the checkpoint was preserved.
	mustHistoryExec(t, s.DB, "UPDATE v3_migration_domains SET pending=false")
	if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
}
