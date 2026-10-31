package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRetirementCheckpointReconcilesNewerLedgerIntoOlderArchive(t *testing.T) {
	s, in := nodeHistoryRetirementFixture(t)
	f := newConfigurationLocalFixture(t)
	ctx := context.Background()
	archive, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	// This explicit retirement is newer than the archived PostgreSQL state.
	confirmNodeHistoryRetirement(t, s, in, "retire-after-archive")
	anchor := strings.Repeat("a", 64)
	raw, err := s.exportRetirementCheckpoint(ctx, f.v, "admin", "isolated-center", anchor, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE KEY", "ciphertext", "password_hash"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("retirement export leaked unrelated private data")
		}
	}
	restored := emptyTestStore(t)
	if err := restored.RestorePostgres(ctx, archive); err != nil {
		t.Fatal(err)
	}
	before := runtimeNodeForTest(t, restored, in.Node)
	result, err := restored.reconcileRetirementCheckpoint(ctx, f.v, "admin", "reconcile-newer-retirements", "isolated-center", anchor, digest(raw), raw)
	var receipt retirementReconcileResult
	if err != nil || json.Unmarshal(result, &receipt) != nil || receipt.Imported != 1 || receipt.CutoverAuthorized || receipt.Checkpoint != digest(raw) {
		t.Fatal("newer retirement was not reconciled", err)
	}
	if after := runtimeNodeForTest(t, restored, in.Node); before.RuntimeEpoch != after.RuntimeEpoch || before.Version != after.Version || before.ServerName != after.ServerName {
		t.Fatal("ledger reconciliation changed runtime")
	}
	audits := tableCount(t, restored, "v3_audit")
	if _, err := restored.reconcileRetirementCheckpoint(ctx, f.v, "admin", "reconcile-newer-retirements", "isolated-center", anchor, digest(raw), raw); err != nil || tableCount(t, restored, "v3_audit") != audits || tableCount(t, restored, "v3_node_history_retirements") != 1 {
		t.Fatal("response loss changed retirement/audit history", err)
	}
	tx, err := restored.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireNodeSnapshotAvailableTx(ctx, tx, in.Node, in.Snapshots[0]); err == nil {
		t.Fatal("reconciled retired history can be activated")
	}
	tx.Rollback()
	// A later physical/logical backup retains the imported immutable evidence.
	newArchive, err := restored.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	second := emptyTestStore(t)
	if err := second.RestorePostgres(ctx, newArchive); err != nil || tableCount(t, second, "v3_node_history_retirements") != 1 {
		t.Fatal("second restore lost imported retirement floor", err)
	}
}

func TestRetirementCheckpointAuthenticationAndTransactionalConflict(t *testing.T) {
	s, in := nodeHistoryRetirementFixture(t)
	f := newConfigurationLocalFixture(t)
	other := newConfigurationLocalFixture(t)
	ctx := context.Background()
	archive, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	confirmNodeHistoryRetirement(t, s, in, "retire-checkpoint-security")
	anchor := strings.Repeat("b", 64)
	raw, err := s.exportRetirementCheckpoint(ctx, f.v, "admin", "isolated-center", anchor, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"wrong-vault", "wrong-anchor", "wrong-center", "wrong-sha", "tampered", "duplicate-field", "unknown-history", "active-snapshot", "viewer"} {
		t.Run(scenario, func(t *testing.T) {
			restored := emptyTestStore(t)
			if err := restored.RestorePostgres(ctx, archive); err != nil {
				t.Fatal(err)
			}
			v, center, expectedAnchor := f.v, "isolated-center", anchor
			data := append([]byte{}, raw...)
			hash := digest(data)
			switch scenario {
			case "wrong-vault":
				v = other.v
			case "wrong-anchor":
				expectedAnchor = strings.Repeat("c", 64)
			case "wrong-center":
				center = "other-center"
			case "wrong-sha":
				hash = strings.Repeat("d", 64)
			case "tampered", "unknown-history", "active-snapshot":
				var p retirementCheckpoint
				if err := json.Unmarshal(raw, &p); err != nil {
					t.Fatal(err)
				}
				if scenario == "tampered" {
					p.Records[0].User = "forged"
				} else {
					// Model an authentic later source checkpoint whose snapshots
					// are missing from, or still active in, this older archive.
					if scenario == "unknown-history" {
						p.Records[0].Snapshot = "unarchived-snapshot"
					} else {
						var snapshot []byte
						if err := restored.DB.QueryRow(`SELECT r.snapshot,to_jsonb(c) FROM v3_node_runtime r JOIN v3_node_configurations c ON c.id=r.snapshot WHERE r.node=$1`, in.Node).Scan(&p.Records[0].Snapshot, &snapshot); err != nil {
							t.Fatal(err)
						}
						p.Records[0].SHA256 = digest(snapshot)
					}
					proof := hmac.New(sha256.New, f.v.receiptKeys[p.Key])
					proof.Write(retirementCheckpointMessage(p))
					p.Signature = hex.EncodeToString(proof.Sum(nil))
				}
				data, _ = json.Marshal(p)
				hash = digest(data)
			case "duplicate-field":
				data = append(append([]byte{}, data[:len(data)-1]...), []byte(`,"format":1}`)...)
				hash = digest(data)
			case "viewer":
				mustHistoryExec(t, restored.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
			}
			audits := tableCount(t, restored, "v3_audit")
			if _, err := restored.reconcileRetirementCheckpoint(ctx, v, "admin", "reject-checkpoint", center, expectedAnchor, hash, data); err == nil || tableCount(t, restored, "v3_node_history_retirements") != 0 || tableCount(t, restored, "v3_audit") != audits {
				t.Fatal("invalid or incompatible checkpoint changed restored state", err)
			}
		})
	}
}
