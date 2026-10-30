package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func restoreDeploymentEvidenceForTest(t *testing.T, s *Store) (json.RawMessage, error) {
	t.Helper()
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	return configurationRestoreDeployments(context.Background(), tx)
}

// Uses the durable SQL journal and real readiness checks with an explicitly
// synthetic remote adapter. This is not native/Docker installation acceptance.
func TestDeploymentTerminalRecoveryProtection(t *testing.T) {
	for _, outcome := range []string{"succeeded", "rolled_back"} {
		t.Run(outcome, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			in := deploymentFixture(t, s)
			createDeployment(t, s, in, "terminal")
			j := claimDeployment(t, s, "terminal-owner")
			remote := &fakeDeploymentRuntime{}
			if outcome == "rolled_back" {
				remote.failPhase = "activate"
			}
			runner := DeploymentRunner{Store: s, Runtime: readinessFixtureRuntime{remote, t, s}}
			err := runner.Execute(ctx, j)
			if outcome == "rolled_back" {
				if err == nil {
					t.Fatal("synthetic activation failure ignored")
				}
				j = reloadDeployment(t, s, j.ID)
				if !j.RecoveryRequired || !j.CanRecover() {
					t.Fatal("failed deployment lost recovery responsibility")
				}
				if _, err = restoreDeploymentEvidenceForTest(t, s); !errors.Is(err, ErrDeploymentBusy) {
					t.Fatal("failed deployment allowed restore", err)
				}
				if _, err = s.RecoverDeployment(ctx, "admin", "terminal-rollback", j.ID, "rollback", j.PlanDigest, j.LogCursor); err != nil {
					t.Fatal(err)
				}
				remote.failPhase = ""
				j = claimDeployment(t, s, "rollback-terminal-owner")
				err = runner.Execute(ctx, j)
			}
			if err != nil {
				t.Fatal(err)
			}
			j = reloadDeployment(t, s, j.ID)
			var rawRecovery bool
			if err = s.DB.QueryRow(`SELECT recovery_required FROM v3_deployment_jobs WHERE id=$1`, j.ID).Scan(&rawRecovery); err != nil {
				t.Fatal(err)
			}
			if j.Status != outcome || rawRecovery || j.RecoveryRequired || j.CanRecover() || j.FinishedAt == nil || j.LeaseUntil.Valid {
				t.Fatal("terminal task retained recovery responsibility")
			}
			if evidence, err := restoreDeploymentEvidenceForTest(t, s); err != nil || len(evidence) == 0 {
				t.Fatal("terminal deployment blocks configuration restore", err)
			}
			// Old rows may still carry the historical flag. Reads normalize it,
			// while restore evidence retains their identity and terminal outcome.
			mustHistoryExec(t, s.DB, `UPDATE v3_deployment_jobs SET recovery_required=true WHERE id=$1`, j.ID)
			if old := reloadDeployment(t, s, j.ID); old.RecoveryRequired || old.CanRecover() {
				t.Fatal("historical terminal flag exposed as unfinished recovery")
			}
			if evidence, err := restoreDeploymentEvidenceForTest(t, s); err != nil || len(evidence) == 0 {
				t.Fatal("historical terminal flag blocks configuration restore", err)
			}
		})
	}
}

func TestDeploymentTerminalRollbackRestoresAppliedVersion(t *testing.T) {
	s, old, j := nodeRuntimeDeploymentFixture(t)
	ctx := context.Background()
	// Reproduce a target that reached its applied marker before rollback is
	// requested by a later parent phase. Desired version must remain pending.
	mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET applied_version=2 WHERE id=$1`, j.Node)
	if err := s.FailDeployment(ctx, j, "interrupted"); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	if _, err := s.RecoverDeployment(ctx, "admin", "terminal-applied-rollback", j.ID, "rollback", j.PlanDigest, j.LogCursor); err != nil {
		t.Fatal(err)
	}
	j = claimDeployment(t, s, "terminal-applied-owner")
	for j.Phase() != "complete" {
		if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, s, j.ID)
	}
	var desired, applied int64
	if err := s.DB.QueryRow(`SELECT version,applied_version FROM v3_nodes WHERE id=$1`, j.Node).Scan(&desired, &applied); err != nil {
		t.Fatal(err)
	}
	if desired != 2 || applied != old.AppliedVersion || j.RecoveryRequired || j.Status != "rolled_back" {
		t.Fatal("rollback falsely applied saved draft", desired, applied, j.Status)
	}
	active := runtimeNodeForTest(t, s, j.Node)
	if active.Version != old.Version || active.Endpoint != old.Endpoint {
		t.Fatal("rollback lost original runtime")
	}
}
