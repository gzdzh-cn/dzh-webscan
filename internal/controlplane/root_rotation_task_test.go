package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

func rootTaskFixture(t *testing.T) (renewalRegistryFixture, []rootRotationNodeInput) {
	return rootTaskFixtureWith(t, nil)
}

func rootTaskFixtureWith(t *testing.T, configure func(*provisioningFixture)) (renewalRegistryFixture, []rootRotationNodeInput) {
	t.Helper()
	f := renewalRegistryFixtureWith(t, configure)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET applied_version=version;UPDATE v3_node_runtime SET delivered_version=1`)
	dir := filepath.Join(filepath.Dir(f.c.Collector.CAFile), "root-collector")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.crt")
	localWrite(t, ca, f.collector.CA)
	f.c.Collector.IdentityFile = filepath.Join(dir, "active.pem")
	f.c.Collector.CertFile, f.c.Collector.KeyFile = "", ""
	if _, err := nodepki.PublishIdentity(context.Background(), ca, f.c.Collector.IdentityFile, nodepki.Collector, "collector-a", "", f.collector, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.NewPersistentFileTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, f.c.Collector.RevocationStateDirectory, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Release(context.Background(), f.lease); err != nil {
		t.Fatal(err)
	}
	return f, []rootRotationNodeInput{{f.in.Request.Node, f.provisioningFixture.in.Credential, f.in.Request.Certificate}}
}

func TestRootTaskBindsAllMembersAndGuardsConfiguration(t *testing.T) {
	f, in := rootTaskFixture(t)
	ctx := context.Background()
	if _, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "viewer", "viewer-root", f.t.release, in); err == nil {
		t.Fatal("viewer authorized root rotation")
	}
	if _, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "empty-root", f.t.release, nil); err == nil {
		t.Fatal("installed node omitted")
	}
	j, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "root-task", f.t.release, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Members) != 2 || j.Roots != nil || j.Status != "prepared" || j.Members[0].Role != nodepki.Collector {
		t.Fatal("incorrect frozen membership")
	}
	if _, err := os.Stat(nodepki.SuccessorAuthorityDirectory(f.c.NodePKI.AuthorityDirectory)); !os.IsNotExist(err) {
		t.Fatal("prepare generated a signing key")
	}
	again, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "root-task", f.t.release, in)
	if err != nil || again.ID != j.ID {
		t.Fatal("prepare replay changed task", err)
	}
	if _, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "different-task", f.t.release, in); err == nil {
		t.Fatal("parallel rotation accepted")
	}
	tx, err := f.s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = lockConfigurationOperationTx(ctx, tx, false)
	tx.Rollback()
	if !errors.Is(err, errRootRotationTask) {
		t.Fatal("configuration gate ignored active task", err)
	}
	l, err := f.s.Acquire(ctx, "pki-root-rotation", "root-test")
	if err != nil {
		t.Fatal(err)
	}
	defer f.s.Release(ctx, l)
	if _, err := f.s.checkRootTask(ctx, f.c, f.t.vault, l, j.ID); err != nil {
		t.Fatal(err)
	}
	changed := f.c
	changed.Central.Topology = "ha"
	if _, err := f.s.checkRootTask(ctx, changed, f.t.vault, l, j.ID); err == nil {
		t.Fatal("different host configuration accepted")
	}
	j, err = f.s.authorizeRootTask(ctx, f.c, f.t.vault, l, j.ID)
	if err != nil || j.Roots == nil || j.Status != "dual" {
		t.Fatal("authorization failed", err)
	}
	if _, err := nodepki.ReadRootState(f.c.Collector.CAFile, f.c.Collector.RevocationStateDirectory, time.Now()); err != nil {
		t.Fatal(err)
	}
	state, err := nodepki.ReadRootState(f.c.Collector.CAFile, f.c.Collector.RevocationStateDirectory, time.Now())
	if err != nil || state.Format != 0 {
		t.Fatal("issuing an authorization prematurely published collector trust")
	}
	if _, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "root-task", f.t.release, in); err != nil {
		t.Fatal("authorized task cannot replay prepare", err)
	}
	if err := publishCollectorRootTask(ctx, f.c, j, 0); err != nil {
		t.Fatal(err)
	}
	j, err = f.s.rootTaskCheckpoint(ctx, f.c, f.t.vault, l, j, func(current *rootRotationTask, _ *sql.Tx) error { current.State[0].Trust = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := rootMemberCertificateSHA(j.Members[0])
	r, err := nodepki.PrepareRootIdentity(ctx, f.c.Collector.CAFile, f.c.Collector.IdentityFile, f.c.Collector.RevocationStateDirectory, nodepki.Collector, "collector-a", nodepki.RootAuthorizationSHA256(j.Roots.Dual), expected, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	for _, damage := range []func(*nodepki.RootIdentityRequest){
		func(r *nodepki.RootIdentityRequest) { r.Proof = append([]byte(nil), r.Proof...); r.Proof[0] ^= 1 },
		func(r *nodepki.RootIdentityRequest) { r.CSR = []byte("invalid-public-csr") },
	} {
		invalid := r
		damage(&invalid)
		bad, _ := json.Marshal(invalid)
		if _, err := f.s.admitRootTaskRequest(ctx, f.c, f.t.vault, l, j, 0, bad); err == nil {
			t.Fatal("unverified proof poisoned durable request")
		}
		saved, _, err := f.s.readRootTask(ctx, f.t.vault, j.ID)
		if err != nil || len(saved.State[0].Request) != 0 || saved.Revision != j.Revision {
			t.Fatal("invalid request modified checkpoint", err)
		}
	}
	j, err = f.s.admitRootTaskRequest(ctx, f.c, f.t.vault, l, j, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	j, err = f.s.signRootTaskMember(ctx, f.c, f.t.vault, l, j.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	first := append([]byte(nil), j.State[0].Certificate...)
	j, err = f.s.signRootTaskMember(ctx, f.c, f.t.vault, l, j.ID, 0)
	if err != nil || !bytes.Equal(first, j.State[0].Certificate) || tableCount(t, f.s, "v3_root_identity_issuances") != 1 {
		t.Fatal("response loss duplicated issuance", err)
	}
	if _, err := f.s.DB.Exec(`UPDATE v3_root_identity_issuances SET certificate='replaced'`); err == nil {
		t.Fatal("public issuance ledger is mutable")
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_root_rotations SET proof=repeat('0',64)`)
	if _, _, err := f.s.readRootTask(ctx, f.t.vault, j.ID); err == nil {
		t.Fatal("tampered task authorized")
	}
}

func TestRootTaskWaitsForExistingNodeMaintenanceLease(t *testing.T) {
	f, in := rootTaskFixture(t)
	ctx := context.Background()
	l, err := f.s.Acquire(ctx, nodeRenewalResource(in[0].Node), "maintenance-in-flight")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "wait-maintenance", f.t.release, in); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("root task overlapped existing identity maintenance", err)
	}
	if tableCount(t, f.s, "v3_root_rotations") != 0 {
		t.Fatal("busy preparation created a blocking task")
	}
	if err := f.s.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "wait-maintenance", f.t.release, in); err != nil {
		t.Fatal("released maintenance still blocked preparation", err)
	}
}

func TestRootTaskRestoreHoldAndCheckpointFence(t *testing.T) {
	f, in := rootTaskFixture(t)
	ctx := context.Background()
	j, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "root-task-restore", f.t.release, in)
	if err != nil {
		t.Fatal(err)
	}
	l, err := f.s.Acquire(ctx, "pki-root-rotation", "root-test")
	if err != nil {
		t.Fatal(err)
	}
	defer f.s.Release(ctx, l)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_root_rotations SET restore_hold=true`)
	if _, err := f.s.checkRootTask(ctx, f.c, f.t.vault, l, j.ID); err == nil {
		t.Fatal("restored authorization resumed without administrator")
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_root_rotations SET restore_hold=false;UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
	if _, err := f.s.checkRootTask(ctx, f.c, f.t.vault, l, j.ID); err == nil {
		t.Fatal("account revision change ignored")
	}
}
