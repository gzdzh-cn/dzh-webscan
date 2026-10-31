package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"webscan/internal/common"
)

var errNodeHistoryRetired = errors.New("该节点历史配置已退役，不能用于恢复或重新激活；请基于当前配置创建新的部署")
var errNodeHistoryRetirement = errors.New("历史退役检查不满足要求：请核对已生效配置、待完成任务及预览摘要，原历史记录未删除")

type nodeHistoryRetirementInput struct {
	Node          string   `json:"node"`
	Expected      int64    `json:"expected_version"`
	Snapshots     []string `json:"snapshots"`
	PreviewSHA256 string   `json:"preview_sha256,omitempty"`
	Confirm       bool     `json:"confirm,omitempty"`
}

type nodeHistoryRetirementSnapshot struct {
	ID         string `json:"id"`
	ServerName string `json:"server_name"`
	SHA256     string `json:"sha256"`
}

type nodeHistoryRetirementPreview struct {
	Node          string                          `json:"node"`
	NodeVersion   int64                           `json:"node_version"`
	RuntimeEpoch  int64                           `json:"runtime_epoch"`
	Snapshots     []nodeHistoryRetirementSnapshot `json:"snapshots"`
	PreviewSHA256 string                          `json:"preview_sha256"`
	// Expose the consequence explicitly. Retiring does not revoke a live leaf
	// or erase an audit; pruning is a separate authenticated host operation.
	HistoryKept    bool `json:"history_preserved"`
	RecoveryDenied bool `json:"historical_recovery_disabled"`
}

func validNodeHistoryRetirementInput(in nodeHistoryRetirementInput) bool {
	if !identifier.MatchString(in.Node) || in.Expected < 1 || len(in.Snapshots) < 1 || len(in.Snapshots) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range in.Snapshots {
		if !identifier.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// The shared operation gate must precede account and node locks. Only callers
// that publish a retirement use its exclusive mode and advance its generation.
func nodeHistoryRetirementPlanTx(ctx context.Context, tx *sql.Tx, user string, in nodeHistoryRetirementInput) (nodeHistoryRetirementPreview, int64, error) {
	var empty nodeHistoryRetirementPreview
	if !validNodeHistoryRetirementInput(in) {
		return empty, 0, errNodeHistoryRetirement
	}
	if held, err := migrationHeld(ctx, tx); err != nil {
		return empty, 0, err
	} else if held {
		return empty, 0, ErrMigrationPending
	}
	if err := configurationApplicationAvailableTx(ctx, tx); err != nil {
		return empty, 0, err
	}
	actor, err := deploymentPreviewAccount(ctx, tx, user)
	if err != nil {
		return empty, 0, err
	}
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR UPDATE`, in.Node))
	if err != nil || !n.Enabled || n.Version != in.Expected || n.AppliedVersion != n.Version {
		return empty, 0, errNodeHistoryRetirement
	}
	b, err := runtimeBaselineTx(ctx, tx, n.ID)
	if err != nil || b.Snapshot == "" || b.Version != n.Version || b.Delivered != n.Version || b.Epoch < 1 {
		return empty, 0, errNodeHistoryRetirement
	}
	var matches bool
	err = tx.QueryRowContext(ctx, `SELECT ROW(n.version,n.name,n.endpoint,n.server_name,n.enabled,n.mode,n.shard,n.config)=ROW(c.version,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.shard,c.config) FROM v3_nodes n JOIN v3_node_configurations c ON c.node=n.id AND c.id=$2 WHERE n.id=$1`, n.ID, b.Snapshot).Scan(&matches)
	if err != nil || !matches {
		return empty, 0, errNodeHistoryRetirement
	}
	// Expired intents still have a potential reauthorization path. Require an
	// explicit cancellation/settlement rather than silently dropping them.
	var busy bool
	err = tx.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status NOT IN ('succeeded','rolled_back')) OR
 EXISTS(SELECT 1 FROM v3_deployment_preparations WHERE node=$1 AND status IN ('queued','running')) OR
 EXISTS(SELECT 1 FROM v3_node_renewal_jobs WHERE node=$1 AND activated_at IS NULL) OR
 EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE node=$1 AND status NOT IN ('completed','canceled')) OR
 EXISTS(SELECT 1 FROM v3_node_name_changes WHERE node=$1 AND status NOT IN ('completed','canceled')) OR
 EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE node=$1 AND status NOT IN ('completed','canceled'))`, n.ID).Scan(&busy)
	if err != nil {
		return empty, 0, err
	}
	if busy {
		return empty, 0, ErrDeploymentBusy
	}
	ids := slices.Clone(in.Snapshots)
	slices.Sort(ids)
	out := nodeHistoryRetirementPreview{Node: n.ID, NodeVersion: n.Version, RuntimeEpoch: b.Epoch, HistoryKept: true, RecoveryDenied: true}
	for _, id := range ids {
		if id == b.Snapshot {
			return empty, 0, errNodeHistoryRetirement
		}
		if err := requireNodeSnapshotAvailableTx(ctx, tx, n.ID, id); err != nil {
			return empty, 0, err
		}
		var raw []byte
		var name string
		var saved bool
		err = tx.QueryRowContext(ctx, `SELECT to_jsonb(c),c.server_name,ROW(n.version,n.name,n.endpoint,n.server_name,n.enabled,n.mode,n.shard,n.config)=ROW(c.version,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.shard,c.config) FROM v3_node_configurations c JOIN v3_nodes n ON n.id=c.node WHERE c.node=$1 AND c.id=$2 FOR SHARE OF c`, n.ID, id).Scan(&raw, &name, &saved)
		if err != nil || saved {
			return empty, 0, errNodeHistoryRetirement
		}
		out.Snapshots = append(out.Snapshots, nodeHistoryRetirementSnapshot{ID: id, ServerName: name, SHA256: digest(raw)})
	}
	// Bind the entire live saved configuration, runtime, exact historical
	// bytes and administrator revision. No private configuration is exposed.
	out.PreviewSHA256 = digest(common.JSON([]any{"webscan-v3/node-history-retirement/v1", user, actor, n, b, out.Snapshots}))
	return out, actor, nil
}

func (s *Store) previewNodeHistoryRetirement(ctx context.Context, user string, in nodeHistoryRetirementInput) (nodeHistoryRetirementPreview, error) {
	var empty nodeHistoryRetirementPreview
	// Each post-lock query must see a preparation or journal committed while
	// we waited for the gate/node. Some such inserts need not change the node.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := lockConfigurationOperationTx(ctx, tx, false); err != nil {
		return empty, err
	}
	p, _, err := nodeHistoryRetirementPlanTx(ctx, tx, user, in)
	if err != nil {
		return empty, err
	}
	return p, tx.Commit()
}

func (s *Store) retireNodeHistory(ctx context.Context, user, key string, in nodeHistoryRetirementInput) (json.RawMessage, error) {
	if !validNodeHistoryRetirementInput(in) || !in.Confirm || !releaseDigest(in.PreviewSHA256) {
		return nil, errNodeHistoryRetirement
	}
	return retryDeploymentConfigurationMutation(ctx, func() (json.RawMessage, error) {
		return s.guardedMutationOptions(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, user, key, "retire-node-history", in.Node, in, func(tx *sql.Tx) error {
			if err := lockConfigurationOperationTx(ctx, tx, true); err != nil {
				return err
			}
			// Authorization is rechecked even when replaying the same receipt.
			_, err := deploymentPreviewAccount(ctx, tx, user)
			return err
		}, func(tx *sql.Tx) (any, error) {
			p, actor, err := nodeHistoryRetirementPlanTx(ctx, tx, user, in)
			if err != nil {
				return nil, err
			}
			if p.PreviewSHA256 != in.PreviewSHA256 {
				return nil, ErrConflict
			}
			for _, snapshot := range p.Snapshots {
				_, err := tx.ExecContext(ctx, `INSERT INTO v3_node_history_retirements(node,snapshot,snapshot_sha256,username,actor_revision,node_version,runtime_epoch,preview_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, p.Node, snapshot.ID, snapshot.SHA256, user, actor, p.NodeVersion, p.RuntimeEpoch, p.PreviewSHA256)
				if err != nil {
					return nil, err
				}
			}
			if err := advanceConfigurationOperationTx(ctx, tx); err != nil {
				return nil, err
			}
			return p, nil
		})
	})
}

// Called before remote work and again at runtime publication. Existing rows
// and all their digests remain unchanged, so older task signatures still verify
// as historical evidence but can no longer authorize a recovery side effect.
func requireNodeSnapshotAvailableTx(ctx context.Context, tx *sql.Tx, node, snapshot string) error {
	if snapshot == "" {
		return nil
	}
	var retired bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_node_history_retirements WHERE node=$1 AND snapshot=$2)`, node, snapshot).Scan(&retired)
	if err != nil {
		return err
	}
	if retired {
		return errNodeHistoryRetired
	}
	return nil
}

func (s *Store) localNodeHistoryRetirementCommand(ctx context.Context, o Options, out io.Writer) error {
	var in nodeHistoryRetirementInput
	if provisioningInput(o.Source, &in) != nil {
		return errNodeHistoryRetirement
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if o.Action == "preview-node-history-retirement" {
		p, err := s.previewNodeHistoryRetirement(ctx, o.Username, in)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(p)
	}
	if o.Action != "retire-node-history" {
		return errNodeHistoryRetirement
	}
	raw, err := s.retireNodeHistory(ctx, o.Username, o.RequestKey, in)
	if err != nil {
		return err
	}
	_, err = out.Write(append(raw, '\n'))
	return err
}
