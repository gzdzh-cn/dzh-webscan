package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestConfigurationOperationGateBlocksIndependentDeployment(t *testing.T) {
	s, _, _ := applicationFixture(t)
	ctx := context.Background()
	// Even an already-held child lease must pass the parent gate before
	// reading its job. These deliberately absent IDs prove the check precedes
	// node/child locks and cannot perform a remote operation.
	j := DeploymentJob{ID: "not-an-authorized-child", Node: "node-a", Plan: DeploymentPlan{BeforeBackup: "not-an-authorized-backup"}}
	in := DeploymentRequest{Node: "node-a", Kind: "install", Expected: 1, Credential: "synthetic-credential", Release: "v3.0.0", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	for name, op := range map[string]func() error{
		"create":   func() error { _, e := s.CreateDeployment(ctx, "admin", "blocked-create", in); return e },
		"renew":    func() error { return s.RenewDeployment(ctx, j) },
		"complete": func() error { return s.CompleteDeploymentPhase(ctx, j) },
		"fail":     func() error { return s.FailDeployment(ctx, j, "interrupted") },
		"arm":      func() error { return s.ArmDeploymentRecovery(ctx, j) },
		"plan":     func() error { return s.checkDeploymentPlan(ctx, j) },
		"archive":  func() error { return s.checkDeploymentConfigurationArchive(ctx, nil, j) },
		"setup":    func() error { return s.PutNode(ctx, nodeFixture("independent-node"), 0, 256) },
		"edit-without-backup-context": func() error {
			_, e := s.SaveNode(ctx, "admin", "blocked-low-level-edit", nodeFixture("independent-node"), 0, 256)
			return e
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := op(); !errors.Is(err, errConfigurationApplicationBusy) {
				t.Fatal("independent mutation passed active application", err)
			}
		})
	}
	if _, err := s.ClaimDeployment(ctx, "independent-executor"); err != sql.ErrNoRows {
		t.Fatal("ordinary worker did not pause cleanly", err)
	}
	if tableCount(t, s, "v3_deployment_jobs") != 0 {
		t.Fatal("blocked mutation created a deployment")
	}
}

func TestConfigurationOperationGateRepeatableReadRechecksApplication(t *testing.T) {
	s, f, stage := environmentFixture(t, http.HandlerFunc(environmentMetrics))
	ctx := context.Background()
	attempts := 0
	_, err := retryDeploymentConfigurationMutation(ctx, func() (json.RawMessage, error) {
		attempts++
		tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		if attempts == 1 {
			// Establish the old snapshot before an application commits.
			var generation int64
			if err = tx.QueryRow(`SELECT generation FROM v3_configuration_operation_gate WHERE singleton`).Scan(&generation); err != nil {
				t.Fatal(err)
			}
			raw, err := s.queueConfigurationApplication(ctx, f.v, f.c, "admin", "racing-application", stage, 1)
			_ = applicationReceipt(t, raw, err)
			if err = lockDeploymentWriteRelationsTx(ctx, tx); err == nil {
				t.Fatal("stale snapshot authorized independent deployment")
			}
			var conflict *pgconn.PgError
			if !errors.As(err, &conflict) || conflict.Code != "40001" {
				t.Fatal("snapshot did not fail with retryable serialization conflict", err)
			}
			return nil, err
		}
		return nil, lockDeploymentWriteRelationsTx(ctx, tx)
	})
	if !errors.Is(err, errConfigurationApplicationBusy) || attempts != 2 {
		t.Fatal("retry did not observe new parent", attempts, err)
	}
}

func TestConfigurationOperationGateOrdinaryDeploymentsRemainConcurrent(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	second, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback()
	if err = lockDeploymentWriteRelationsTx(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err = lockDeploymentWriteRelationsTx(ctx, second); err != nil {
		t.Fatal("ordinary operations serialized behind a global exclusive lock", err)
	}
	parent, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Rollback()
	var pid int
	if err = parent.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	locked := make(chan error, 1)
	go func() { locked <- lockConfigurationRestoreRelationsTx(ctx, parent) }()
	defer func() { first.Rollback(); second.Rollback(); <-locked }()
	// Confirm an actual SQL lock wait, rather than relying on a sleep to infer
	// concurrency. Both shared holders must drain before parent activation.
	for {
		var waiting bool
		if err = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if !waitRetry(ctx, 5*time.Millisecond) {
			t.Fatal("parent did not wait for ordinary writers")
		}
	}
	if err = first.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-locked:
		locked <- err
		t.Fatal("parent passed second shared holder", err)
	default:
	}
	if err = second.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-locked:
		locked <- err
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("parent did not acquire after writers drained")
	}
}

func TestConfigurationOperationGateSchema24BackupRestore(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE IF EXISTS v3_deployment_recoveries;DROP TABLE IF EXISTS v3_deployment_installations;DROP TABLE IF EXISTS v3_node_provisioning;DROP TABLE v3_configuration_application_registrations;DROP TABLE v3_configuration_application_nodes;DROP TABLE v3_configuration_application_targets;DROP TABLE v3_configuration_operation_gate;DELETE FROM v3_schema WHERE version>=25`)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("migrated existing schema without backup")
	}
	bad := filepath.Join(privateTestDir(t), "not-a-directory")
	localWrite(t, bad, []byte("synthetic"))
	if err := s.Upgrade(ctx, bad); err == nil {
		t.Fatal("backup failure permitted migration")
	}
	if version, err := currentSchema(ctx, s.DB); err != nil || version != 24 {
		t.Fatal("failed backup changed schema", version, err)
	}
	if err := s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_operation_gate SET generation=17 WHERE singleton`)
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	var generation int64
	if err = target.DB.QueryRow(`SELECT generation FROM v3_configuration_operation_gate WHERE singleton`).Scan(&generation); err != nil || generation != 17 {
		t.Fatal("restore lost operation fence", generation, err)
	}
}

func TestConfigurationOperationGateMissingRowFailsClosed(t *testing.T) {
	s := testStore(t)
	mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_operation_gate`)
	for _, exclusive := range []bool{false, true} {
		tx, err := s.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		err = lockConfigurationOperationTx(context.Background(), tx, exclusive)
		tx.Rollback()
		if err == nil {
			t.Fatal("missing operation fence accepted")
		}
	}
}
