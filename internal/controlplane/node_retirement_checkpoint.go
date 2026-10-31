package controlplane

// An archive is not the latest retirement ledger. A separately retained,
// authenticated checkpoint can add missing tombstones after restoring an older
// archive, but never enables workers or authorizes a disaster-recovery cutover.
import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"webscan/internal/nodepki"
)

var errRetirementCheckpoint = errors.New("历史退役检查点校验或对账失败；未覆盖历史及运行状态，请核对最新独立检查点、原 Vault 和恢复节点配置")

const maxRetirementCheckpointBytes = 32 << 20

type retirementCheckpointRecord struct {
	Node          string    `json:"node"`
	Snapshot      string    `json:"snapshot"`
	SHA256        string    `json:"snapshot_sha256"`
	User          string    `json:"username"`
	ActorRevision int64     `json:"actor_revision"`
	NodeVersion   int64     `json:"node_version"`
	RuntimeEpoch  int64     `json:"runtime_epoch"`
	PreviewSHA256 string    `json:"preview_sha256"`
	CreatedAt     time.Time `json:"created_at"`
}

type retirementCheckpoint struct {
	Format    int                          `json:"format"`
	Instance  string                       `json:"instance"`
	Anchor    string                       `json:"anchor_sha256"`
	IssuedAt  time.Time                    `json:"issued_at"`
	Records   []retirementCheckpointRecord `json:"records"`
	Key       string                       `json:"key_id"`
	Signature string                       `json:"signature"`
}

func retirementCheckpointMessage(p retirementCheckpoint) []byte {
	p.Signature = ""
	raw, _ := json.Marshal(p)
	return append([]byte("webscan-v3/node-retirement-checkpoint/v1\x00"), raw...)
}

func validRetirementRecord(r retirementCheckpointRecord, issued time.Time) bool {
	return identifier.MatchString(r.Node) && identifier.MatchString(r.Snapshot) && identifier.MatchString(r.User) && releaseDigest(r.SHA256) && releaseDigest(r.PreviewSHA256) && r.ActorRevision > 0 && r.NodeVersion > 0 && r.RuntimeEpoch > 0 && !r.CreatedAt.IsZero() && !r.CreatedAt.After(issued)
}

func parseRetirementCheckpoint(raw []byte, v *Vault, instance, anchor string, now time.Time) (retirementCheckpoint, error) {
	var p retirementCheckpoint
	if len(raw) == 0 || len(raw) > maxRetirementCheckpointBytes || singleDecode(raw, &p) != nil {
		return p, errRetirementCheckpoint
	}
	canonical, _ := json.Marshal(p)
	if !bytes.Equal(canonical, raw) || v == nil || len(v.receiptKeys[p.Key]) == 0 || p.Format != 1 || p.Instance != instance || !identifier.MatchString(instance) || p.Anchor != anchor || !releaseDigest(anchor) || p.IssuedAt.IsZero() || p.IssuedAt.After(now.Add(time.Minute)) || len(p.Records) > 64000 || p.Records == nil {
		return retirementCheckpoint{}, errRetirementCheckpoint
	}
	signature, err := hex.DecodeString(p.Signature)
	proof := hmac.New(sha256.New, v.receiptKeys[p.Key])
	proof.Write(retirementCheckpointMessage(p))
	if err != nil || hex.EncodeToString(signature) != p.Signature || !hmac.Equal(signature, proof.Sum(nil)) {
		return retirementCheckpoint{}, errRetirementCheckpoint
	}
	for i, r := range p.Records {
		if !validRetirementRecord(r, p.IssuedAt) || i > 0 && p.Records[i-1].Snapshot >= r.Snapshot {
			return retirementCheckpoint{}, errRetirementCheckpoint
		}
	}
	return p, nil
}

func (s *Store) exportRetirementCheckpoint(ctx context.Context, v *Vault, user, instance, anchor string, now time.Time) ([]byte, error) {
	if v == nil || len(v.receiptKeys[v.active]) == 0 || !identifier.MatchString(instance) || !releaseDigest(anchor) {
		return nil, errRetirementCheckpoint
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Retirements use the exclusive gate. This captures one complete committed
	// checkpoint even if an administrator is concurrently retiring more rows.
	if err := lockConfigurationOperationTx(ctx, tx, false); err != nil {
		return nil, err
	}
	if _, err := deploymentPreviewAccount(ctx, tx, user); err != nil {
		return nil, err
	}
	p := retirementCheckpoint{Format: 1, Instance: instance, Anchor: anchor, Key: v.active, Records: []retirementCheckpointRecord{}}
	rows, err := tx.QueryContext(ctx, `SELECT node,snapshot,snapshot_sha256,username,actor_revision,node_version,runtime_epoch,preview_sha256,created_at FROM v3_node_history_retirements ORDER BY snapshot LIMIT 64001`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r retirementCheckpointRecord
		if err := rows.Scan(&r.Node, &r.Snapshot, &r.SHA256, &r.User, &r.ActorRevision, &r.NodeVersion, &r.RuntimeEpoch, &r.PreviewSHA256, &r.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		r.CreatedAt = r.CreatedAt.UTC()
		p.Records = append(p.Records, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(p.Records) > 64000 {
		return nil, errRetirementCheckpoint
	}
	// Wall time is not a monotonic floor. Ensure it cannot make a concurrent
	// committed record appear newer than the checkpoint that contains it.
	p.IssuedAt = now.UTC()
	for _, r := range p.Records {
		if r.CreatedAt.After(p.IssuedAt) {
			p.IssuedAt = r.CreatedAt
		}
		if !validRetirementRecord(r, p.IssuedAt) {
			return nil, errRetirementCheckpoint
		}
	}
	proof := hmac.New(sha256.New, v.receiptKeys[v.active])
	proof.Write(retirementCheckpointMessage(p))
	p.Signature = hex.EncodeToString(proof.Sum(nil))
	raw, _ := json.Marshal(p)
	if len(raw) > maxRetirementCheckpointBytes {
		return nil, errRetirementCheckpoint
	}
	return raw, tx.Commit()
}

type retirementReconcileResult struct {
	Checkpoint string `json:"checkpoint_sha256"`
	Imported   int    `json:"imported"`
	Existing   int    `json:"existing"`
	// A successful ledger merge is never permission to activate remote tasks,
	// notifications, collection generations, source paths or archived DSNs.
	CutoverAuthorized bool `json:"cutover_authorized"`
}

func (s *Store) reconcileRetirementCheckpoint(ctx context.Context, v *Vault, user, key, instance, anchor, expected string, raw []byte) (json.RawMessage, error) {
	if !releaseDigest(expected) || digest(raw) != expected {
		return nil, errRetirementCheckpoint
	}
	p, err := parseRetirementCheckpoint(raw, v, instance, anchor, time.Now())
	if err != nil {
		return nil, err
	}
	return s.guardedMutationOptions(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, user, key, "reconcile-node-retirements", instance, map[string]string{"checkpoint": expected, "anchor": anchor}, func(tx *sql.Tx) error {
		if err := lockConfigurationOperationTx(ctx, tx, true); err != nil {
			return err
		}
		_, err := deploymentPreviewAccount(ctx, tx, user)
		return err
	}, func(tx *sql.Tx) (any, error) {
		result := retirementReconcileResult{Checkpoint: expected}
		// Lock nodes in a stable order, including all missing-history cases.
		nodes := make([]string, 0, len(p.Records))
		for _, r := range p.Records {
			nodes = append(nodes, r.Node)
		}
		slices.Sort(nodes)
		for _, node := range slices.Compact(nodes) {
			var id string
			if err := tx.QueryRowContext(ctx, `SELECT id FROM v3_nodes WHERE id=$1 FOR UPDATE`, node).Scan(&id); err != nil {
				return nil, errRetirementCheckpoint
			}
		}
		for _, r := range p.Records {
			var snapshot []byte
			if err := tx.QueryRowContext(ctx, `SELECT to_jsonb(c) FROM v3_node_configurations c WHERE node=$1 AND id=$2`, r.Node, r.Snapshot).Scan(&snapshot); err != nil || digest(snapshot) != r.SHA256 {
				return nil, errRetirementCheckpoint
			}
			var existing retirementCheckpointRecord
			err := tx.QueryRowContext(ctx, `SELECT node,snapshot,snapshot_sha256,username,actor_revision,node_version,runtime_epoch,preview_sha256,created_at FROM v3_node_history_retirements WHERE snapshot=$1`, r.Snapshot).Scan(&existing.Node, &existing.Snapshot, &existing.SHA256, &existing.User, &existing.ActorRevision, &existing.NodeVersion, &existing.RuntimeEpoch, &existing.PreviewSHA256, &existing.CreatedAt)
			if err == nil {
				existing.CreatedAt = existing.CreatedAt.UTC()
				if existing != r {
					return nil, errRetirementCheckpoint
				}
				result.Existing++
				continue
			}
			if err != sql.ErrNoRows {
				return nil, err
			}
			// The database trigger refuses an active snapshot. Such a recovery
			// needs explicit live-node reconciliation, never a forced rewrite.
			if _, err := tx.ExecContext(ctx, `INSERT INTO v3_node_history_retirements(node,snapshot,snapshot_sha256,username,actor_revision,node_version,runtime_epoch,preview_sha256,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, r.Node, r.Snapshot, r.SHA256, r.User, r.ActorRevision, r.NodeVersion, r.RuntimeEpoch, r.PreviewSHA256, r.CreatedAt); err != nil {
				return nil, errRetirementCheckpoint
			}
			result.Imported++
		}
		if result.Imported > 0 {
			if err := advanceConfigurationOperationTx(ctx, tx); err != nil {
				return nil, err
			}
		}
		return result, nil
	})
}

func (s *Store) localRetirementCheckpointCommand(ctx context.Context, c Config, o Options, out io.Writer) error {
	if err := provisioningAdmin(ctx, s.DB, o.Username); err != nil {
		return err
	}
	v, err := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return err
	}
	ca, err := readTrustData(c.Collector.CAFile, false, 64<<10)
	if err != nil {
		return errRetirementCheckpoint
	}
	anchor, err := nodepki.RootFingerprint(ca)
	if err != nil {
		return errRetirementCheckpoint
	}
	if o.Action == "export-node-retirements" {
		raw, err := s.exportRetirementCheckpoint(ctx, v, o.Username, c.Central.Instance, anchor, time.Now())
		if err != nil {
			return err
		}
		if err := publishTrustFiles(ctx, o.Output, map[string][]byte{"retirements.json": raw}); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"checkpoint_sha256": digest(raw), "cutover_authorized": false})
	}
	var in struct {
		File    string `json:"checkpoint_file"`
		SHA256  string `json:"checkpoint_sha256"`
		Confirm bool   `json:"confirm"`
	}
	if o.Action != "reconcile-node-retirements" || provisioningInput(o.Source, &in) != nil || !in.Confirm || !identifier.MatchString(o.RequestKey) {
		return errRetirementCheckpoint
	}
	raw, err := readTrustData(in.File, true, maxRetirementCheckpointBytes)
	if err != nil {
		return errRetirementCheckpoint
	}
	result, err := s.reconcileRetirementCheckpoint(ctx, v, o.Username, o.RequestKey, c.Central.Instance, anchor, in.SHA256, raw)
	if err != nil {
		return err
	}
	_, err = out.Write(append(result, '\n'))
	return err
}
