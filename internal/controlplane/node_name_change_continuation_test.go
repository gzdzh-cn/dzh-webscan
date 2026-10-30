package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

func freshNameChangeTask(t *testing.T, f nameChangeRegistryFixture, key string) nodeNameChangeJob {
	t.Helper()
	if _, err := f.s.cancelNodeNameChange(context.Background(), "admin", "cancel-"+key, f.job.ID); err != nil {
		t.Fatal(err)
	}
	j, err := f.s.prepareNodeNameChange(context.Background(), f.c, f.t.vault, "admin", key, f.input)
	if err != nil {
		t.Fatal("fresh authorization", err)
	}
	return j
}

func TestNodeNameChangeReauthorizationReplaysOriginalIssuance(t *testing.T) {
	for _, scenario := range []string{"pending", "active", "new-runtime", "new-account-revision", "missing-old-key"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeRegistryFixture(t)
			ctx := context.Background()
			f.admit(t)
			first, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				t.Fatal(err)
			}
			original := f.request
			if scenario != "pending" {
				if _, err := nodepki.ActivateNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, f.trust, original, f.job.Intent, first.Certificate, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.s.cancelNodeNameChange(ctx, "admin", "cancel-first", f.job.ID); err != nil {
				t.Fatal(err)
			}
			if scenario == "new-runtime" {
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1`, f.input.Node)
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_runtime SET epoch=epoch+1 WHERE node=$1`, f.input.Node)
			}
			if scenario == "new-account-revision" {
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			}
			next, err := f.s.prepareNodeNameChange(ctx, f.c, f.t.vault, "admin", "fresh-name-task", f.input)
			if err != nil {
				t.Fatal(err)
			}
			if next.ID == f.job.ID || next.Intent.Challenge == f.job.Intent.Challenge {
				t.Fatal("reauthorization reused old task")
			}
			if _, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID); err == nil {
				t.Fatal("old task regained permission")
			}
			before, err := os.ReadFile(f.identity)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before)
			if scenario == "missing-old-key" {
				if err := os.Remove(f.identity + ".history/" + f.input.ParentSHA256 + ".pem"); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")); err != nil {
					t.Fatal(err)
				}
			}
			r, err := nodepki.PrepareNodeNameChangeContinuation(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.crl, next.Intent, original, first.Certificate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(r)
			if r.IssuanceSHA256() != original.SHA256() || r.SHA256() == r.IssuanceSHA256() {
				t.Fatal("fresh proof conflated with original issuance")
			}
			if _, err := f.s.admitNodeNameChange(ctx, f.t.vault, f.lease, next.ID, raw); err != nil {
				t.Fatal(err)
			}
			replay, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, next.ID)
			if err != nil || replay.Receipt != first.Receipt || !bytes.Equal(replay.Certificate, first.Certificate) || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
				t.Fatal("fresh task changed original issuance", err)
			}
			if _, err := nodepki.ActivateNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, f.trust, r, next.Intent, replay.Certificate, time.Now()); err != nil {
				t.Fatal(err)
			}
			if scenario != "pending" {
				after, _ := os.ReadFile(f.identity)
				defer clear(after)
				if !bytes.Equal(before, after) {
					t.Fatal("active continuation rewrote private identity")
				}
			}
			leaf, _ := provisioningCertificate(replay.Certificate)
			if err := f.s.confirmNodeNameChange(ctx, f.c, f.t.vault, f.lease, next.ID, leaf); err != nil {
				t.Fatal("fresh task confirmation", err)
			}
			var status string
			if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_changes WHERE id=$1`, next.ID).Scan(&status); err != nil || status != "completed" {
				t.Fatal("new task not completed", err)
			}
		})
	}
}

func TestNodeNameChangeReauthorizationRejectsChangedIssuance(t *testing.T) {
	for _, scenario := range []string{"target", "hours", "ordinary-ledger", "missing-original", "tampered-original", "revoked-successor"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeRegistryFixture(t)
			ctx := context.Background()
			f.admit(t)
			first, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.cancelNodeNameChange(ctx, "admin", "cancel-before-new", f.job.ID); err != nil {
				t.Fatal(err)
			}
			input := f.input
			switch scenario {
			case "target":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET server_name='other.test'`)
			case "hours":
				input.LifetimeHours++
			case "ordinary-ledger":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET request_kind='renewal'`)
			case "missing-original":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET request=NULL,request_sha256='' WHERE id=$1`, f.job.ID)
			case "tampered-original":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET request=decode('deadbeef','hex') WHERE id=$1`, f.job.ID)
			case "revoked-successor":
				crl, err := f.ca.Revoke(f.crl, [][]byte{first.Certificate}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, crl)
			}
			if _, err := f.s.prepareNodeNameChange(ctx, f.c, f.t.vault, "admin", "must-not-reauthorize", input); err == nil {
				t.Fatal("changed original issuance admitted")
			}
			if tableCount(t, f.s, "v3_node_name_changes") != 1 || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
				t.Fatal("rejection created task or new issuance")
			}
		})
	}
}

func TestNodeNameChangeReauthorizationAfterActualIntentExpiry(t *testing.T) {
	f := newNameChangeRegistryFixture(t)
	ctx := context.Background()
	// A deliberately short, still-valid fixture authorization is installed BEFORE
	// admitting any request or signing. We wait for real SQL/wall-clock expiry.
	now := time.Now().UTC().Truncate(time.Second)
	f.job.Intent.IssuedAt, f.job.Intent.ExpiresAt = now, now.Add(4*time.Second)
	f.job.ExpiresAt = f.job.Intent.ExpiresAt
	rawIntent, _ := json.Marshal(f.job.Intent)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET intent=$2,expires_at=$3 WHERE id=$1`, f.job.ID, rawIntent, f.job.ExpiresAt)
	var err error
	f.request, err = nodepki.PrepareNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.job.Intent, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.admit(t)
	first, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.ActivateNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.request, f.job.Intent, first.Certificate, time.Now()); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Until(f.job.ExpiresAt.Add(100 * time.Millisecond)))
	defer timer.Stop()
	<-timer.C
	if _, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID); err == nil {
		t.Fatal("actually expired task remained authorized")
	}
	next, err := f.s.prepareNodeNameChange(ctx, f.c, f.t.vault, "admin", "after-real-expiry", f.input)
	if err != nil {
		t.Fatal(err)
	}
	r, err := nodepki.PrepareNodeNameChangeContinuation(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.crl, next.Intent, f.request, first.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if _, err := f.s.admitNodeNameChange(ctx, f.t.vault, f.lease, next.ID, raw); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")); err != nil {
		t.Fatal(err)
	}
	replay, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, next.ID)
	if err != nil || replay.Receipt != first.Receipt || !bytes.Equal(replay.Certificate, first.Certificate) {
		t.Fatal("expired task continuation changed issuance", err)
	}
}

func TestNodeNameChangeCompletedOverlapAllowsManagedTargetPreparation(t *testing.T) {
	f := newNameChangeRegistryFixture(t)
	ctx := context.Background()
	f.admit(t)
	signed, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.ActivateNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.request, f.job.Intent, signed.Certificate, time.Now()); err != nil {
		t.Fatal(err)
	}
	in := f.provisioningFixture.in
	in.Kind, in.Expected, in.IdentityDirectory = "upgrade", f.input.Expected, ""
	if err := f.s.DB.QueryRow(`SELECT id FROM v3_node_certificates WHERE node=$1`, f.input.Node).Scan(&in.IdentityID); err != nil {
		t.Fatal(err)
	}
	draft, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, in)
	if err != nil {
		t.Fatal("immutable preparation failed", err)
	}
	if _, err := f.s.previewLocalDeployment(ctx, f.c, f.t, "admin", draft); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("active name operation allowed deployment preview", err)
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 0 {
		t.Fatal("preparation created an executable deployment")
	}
	leaf, _ := provisioningCertificate(signed.Certificate)
	// Store-layer completion only. Actual peer observation has separate mTLS tests.
	if err := f.s.confirmNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID, leaf); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificates SET ciphertext='unavailable-original-seed'::bytea`)
	request, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, in)
	if err != nil {
		t.Fatal("completed overlap cannot prepare saved target", err)
	}
	material := readPreparedManagedMaterial(t, f.provisioningFixture, request)
	if material.ServerName != f.job.TargetName || material.Version != f.input.Expected {
		t.Fatal("saved target name/version not used")
	}
	preview, err := f.s.previewLocalDeployment(ctx, f.c, f.t, "admin", request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.confirmLocalDeployment(ctx, f.c, f.t, "admin", "queue-name-target", preview.Token); err != nil {
		t.Fatal(err)
	}
	var activeName string
	if err := f.s.DB.QueryRow(`SELECT server_name FROM v3_active_nodes WHERE id=$1`, f.input.Node).Scan(&activeName); err != nil || activeName != f.job.SourceName {
		t.Fatal("queueing target silently changed active runtime", err)
	}
	if tableCount(t, f.s, "v3_node_certificate_renewals") != 1 || tableCount(t, f.s, "v3_node_certificates") != 1 {
		t.Fatal("target preparation issued or retrieved a new private seed")
	}
}

func TestNodeNameChangeContinuationBackupRestoresOriginalAncestry(t *testing.T) {
	f := newNameChangeRegistryFixture(t)
	ctx := context.Background()
	f.admit(t)
	first, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.ActivateNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.request, f.job.Intent, first.Certificate, time.Now()); err != nil {
		t.Fatal(err)
	}
	next := freshNameChangeTask(t, f, "fresh-backup")
	r, err := nodepki.PrepareNodeNameChangeContinuation(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.crl, next.Intent, f.request, first.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if _, err := f.s.admitNodeNameChange(ctx, f.t.vault, f.lease, next.ID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, next.ID); err != nil {
		t.Fatal(err)
	}
	backup, err := f.s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	restored, err := target.nodeNameChange(ctx, f.t.vault, next.ID)
	if err != nil || restored.RequestSHA256 != r.SHA256() || !bytes.Equal(restored.Request, raw) || restored.Status != "signed" {
		t.Fatal("restored continuation changed", err)
	}
	mustHistoryExec(t, target.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
	l, err := target.Acquire(ctx, f.lease.Resource, "restored-continuation")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")); err != nil {
		t.Fatal(err)
	}
	replay, err := target.signNodeNameChange(ctx, f.c, f.t.vault, l, next.ID)
	if err != nil || replay.Receipt != first.Receipt || !bytes.Equal(replay.Certificate, first.Certificate) || tableCount(t, target, "v3_node_certificate_renewals") != 1 || tableCount(t, target, "v3_node_name_changes") != 2 {
		t.Fatal("restored continuation lost ancestry or changed issuance", err)
	}
	stale, err := target.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, next.ID)
	requireEmptyRenewalFailure(t, stale, err)
}
