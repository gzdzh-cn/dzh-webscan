package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"webscan/internal/common"
	"webscan/internal/nodeops"
)

var errDeploymentRecovery = errors.New("历史恢复授权或当前运行状态不匹配；未继续操作，请重新核对来源及当前任务")

// Internal administrator input only. No HTTP route accepts this contract.
type deploymentRecoveryInput struct {
	Node         string `json:"node"`
	Expected     int64  `json:"expected_version"`
	Credential   string `json:"credential"`
	Source       string `json:"source_job"`
	SourceDigest string `json:"source_plan_digest"`
	Head         string `json:"head_job"`
	HeadDigest   string `json:"head_plan_digest"`
}

type deploymentRecoveryPlan struct {
	Source                string                    `json:"source_job"`
	SourceDigest          string                    `json:"source_plan_digest"`
	Head                  string                    `json:"head_job"`
	HeadDigest            string                    `json:"head_plan_digest"`
	From                  deploymentRuntimeBaseline `json:"from_runtime"`
	Restore               deploymentRuntimeBaseline `json:"restore_runtime"`
	RestoreAppliedVersion int64                     `json:"restore_applied_version"`
}

func recoveryProof(v *Vault, key string, j DeploymentJob) (string, error) {
	if v == nil || len(v.receiptKeys[key]) == 0 || j.Plan.Recovery == nil {
		return "", errDeploymentRecovery
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/deployment-recovery/v1\x00"))
	h.Write(common.JSON([]any{j.ID, j.Node, j.PlanDigest, j.Plan.Recovery.Source, j.Plan.Recovery.Head}))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sameRuntime(a, b deploymentRuntimeBaseline) bool {
	a.Epoch, b.Epoch = 0, 0
	return a == b
}

func readRecoveryJobTx(ctx context.Context, tx *sql.Tx, id string) (DeploymentJob, error) {
	return scanDeployment(tx.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM v3_deployment_jobs WHERE id=$1 FOR SHARE", id))
}

// Authenticate every immutable ancestor. Only the top-level live task checks
// today's generation; historical ancestors retain their original generations.
func readDeploymentRecoveryTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob, seen map[string]bool) (deploymentInstallation, error) {
	var empty deploymentInstallation
	r := j.Plan.Recovery
	if r == nil || j.Kind != "recover" || j.Plan.Request.Kind != "recover" || j.Direction != "rollback" || j.Step != 0 || len(seen) >= 128 || seen[j.ID] || j.Plan.PreviousRuntime == nil || *j.Plan.PreviousRuntime != r.From {
		return empty, errDeploymentRecovery
	}
	seen[j.ID] = true
	var source, head, key, proof string
	if err := tx.QueryRowContext(ctx, `SELECT source,head,key_id,proof FROM v3_deployment_recoveries WHERE job=$1 FOR SHARE`, j.ID).Scan(&source, &head, &key, &proof); err != nil {
		return empty, err
	}
	want, err := recoveryProof(v, key, j)
	if err != nil || !hmac.Equal([]byte(want), []byte(proof)) || source != r.Source || head != r.Head {
		return empty, errDeploymentRecovery
	}
	s, err := readRecoveryJobTx(ctx, tx, r.Source)
	if err != nil {
		return empty, err
	}
	if s.Node != j.Node || s.PlanDigest != r.SourceDigest || s.Plan.Recovery != nil || s.Kind != "install" && s.Kind != "upgrade" || s.Direction != "forward" || s.Status != "succeeded" || s.Step != 6 || s.RollbackStep != 0 || s.Plan.PreviousRuntime == nil || *s.Plan.PreviousRuntime != r.Restore || s.Plan.Node.AppliedVersion != r.RestoreAppliedVersion || s.ID == j.ID {
		return empty, errDeploymentRecovery
	}
	installation, err := readDeploymentInstallationTx(ctx, tx, v, s)
	if err != nil {
		return empty, err
	}
	h, err := readRecoveryJobTx(ctx, tx, r.Head)
	if err != nil {
		return empty, err
	}
	if h.Node != j.Node || h.PlanDigest != r.HeadDigest || h.Status != "rolled_back" || h.Direction != "rollback" || h.RollbackStep != 2 || h.ID == s.ID || h.ID == j.ID || !h.CreatedAt.After(s.CreatedAt) || !j.CreatedAt.After(h.CreatedAt) {
		return empty, errDeploymentRecovery
	}
	previous := h.Plan.PreviousRuntime
	if h.Plan.Recovery != nil || h.Kind == "recover" {
		if _, err = readDeploymentRecoveryTx(ctx, tx, v, h, seen); err != nil {
			return empty, err
		}
		previous = &h.Plan.Recovery.Restore
	} else if h.Step < 4 {
		// A pre-activation settlement may never have created the immutable
		// head activation evidence required by the node recovery adopter.
		return empty, errDeploymentRecovery
	}
	if previous == nil || !sameRuntime(*previous, r.From) || r.From.Snapshot != s.Plan.TargetRuntime || r.From.Digest != s.Plan.TargetRuntimeDigest || r.From.Version != s.NodeVersion || r.From.Delivered != s.NodeVersion {
		return empty, errDeploymentRecovery
	}
	return installation, nil
}

// Current active generations must match exactly. Publishing a historical
// snapshot advances from today's fence, never rewinds to its old epoch.
func checkRecoveryRuntimeTx(ctx context.Context, tx *sql.Tx, j DeploymentJob) error {
	r := j.Plan.Recovery
	if r == nil || j.Kind != "recover" || j.Direction != "rollback" || j.Plan.PreviousRuntime == nil || *j.Plan.PreviousRuntime != r.From {
		return errDeploymentRecovery
	}
	for _, b := range []deploymentRuntimeBaseline{r.From, r.Restore} {
		if b.Snapshot == "" {
			if b.Version != 0 || b.Delivered != 0 || b.Digest != "" {
				return errDeploymentRecovery
			}
			continue
		}
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT to_jsonb(c) FROM v3_node_configurations c WHERE node=$1 AND id=$2 AND version=$3 FOR SHARE`, j.Node, b.Snapshot, b.Version).Scan(&raw); err != nil {
			return err
		}
		if digest(raw) != b.Digest {
			return errDeploymentRecovery
		}
	}
	current, err := runtimeBaselineTx(ctx, tx, j.Node)
	if err != nil {
		return err
	}
	want := r.From
	if j.RollbackStep > 0 {
		want = r.Restore
		want.Epoch = r.From.Epoch + 1
	}
	if *current != want {
		return ErrConflict
	}
	return nil
}

func (s *Store) recoveryRequest(ctx context.Context, v *Vault, j DeploymentJob, operation string) (nodeops.Request, error) {
	var request nodeops.Request
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return request, err
	}
	defer tx.Rollback()
	if err = lockDeploymentJournalTx(ctx, tx, j); err != nil {
		return request, err
	}
	current, err := lockedDeployment(ctx, tx, j)
	if err != nil {
		return request, err
	}
	installation, err := readDeploymentRecoveryTx(ctx, tx, v, current, map[string]bool{})
	if err != nil {
		return request, err
	}
	if err = checkRecoveryRuntimeTx(ctx, tx, current); err != nil {
		return request, err
	}
	r := current.Plan.Recovery
	request = nodeops.Request{Protocol: nodeops.Protocol, Operation: operation, Job: current.ID, Node: current.Node, PlanDigest: current.PlanDigest, Epoch: current.Epoch, Phase: current.Phase(), Spec: installation.Spec, Recovery: &nodeops.RecoveryReference{SourceJob: r.Source, SourcePlanDigest: r.SourceDigest, HeadJob: r.Head, HeadPlanDigest: r.HeadDigest, CaptureSHA256: installation.Evidence.CaptureSHA256, ActiveSHA256: installation.Evidence.ActiveSHA256}}
	if request.Validate() != nil {
		return nodeops.Request{}, errDeploymentRecovery
	}
	return request, tx.Commit()
}

func (s *Store) queueLocalDeploymentRecovery(ctx context.Context, c Config, t *deploymentTrust, user, key string, in deploymentRecoveryInput) (json.RawMessage, error) {
	if !c.Executor.Enabled || t == nil || t.release == nil || t.vault == nil || !identifier.MatchString(in.Node) || in.Expected < 1 || !identifier.MatchString(in.Credential) || !identifier.MatchString(in.Source) || !identifier.MatchString(in.Head) || in.Source == in.Head || !releaseDigest(in.SourceDigest) || !releaseDigest(in.HeadDigest) {
		return nil, errDeploymentRecovery
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := provisioningAdmin(ctx, s.DB, user); err != nil {
		return nil, err
	}
	out, err := retryDeploymentConfigurationMutation(ctx, func() (json.RawMessage, error) {
		return s.guardedMutationOptions(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, user, key, "create-deployment-recovery", in.Node, in, func(tx *sql.Tx) error {
			if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
				return err
			}
			return provisioningAdmin(ctx, tx, user)
		}, func(tx *sql.Tx) (any, error) {
			n, err := scanNode(tx.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE id=$1 FOR UPDATE", in.Node))
			if err != nil {
				return nil, err
			}
			if !n.Enabled || n.Version != in.Expected {
				return nil, ErrConflict
			}
			var busy bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required)) OR EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_changes WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp())`, in.Node).Scan(&busy); err != nil {
				return nil, err
			}
			if busy {
				return nil, ErrDeploymentBusy
			}
			var latest string
			if err = tx.QueryRowContext(ctx, `SELECT id FROM v3_deployment_jobs WHERE node=$1 ORDER BY created_at DESC,id DESC LIMIT 1 FOR SHARE`, in.Node).Scan(&latest); err != nil {
				return nil, err
			}
			if latest != in.Head {
				return nil, errDeploymentRecovery
			}
			source, err := readRecoveryJobTx(ctx, tx, in.Source)
			if err != nil || source.Plan.PreviousRuntime == nil {
				return nil, errDeploymentRecovery
			}
			from, err := runtimeBaselineTx(ctx, tx, in.Node)
			if err != nil {
				return nil, err
			}
			target := t.release.manifest.Native.SHA256
			if n.Mode == "docker" {
				target = t.release.manifest.Image[len(t.release.manifest.Image)-64:]
			}
			request := DeploymentRequest{Node: n.ID, Expected: n.Version, Kind: "recover", Credential: in.Credential, Release: t.release.manifest.Release, SHA256: target, ManifestSHA256: t.release.SHA256()}
			if _, err = previewCredential(ctx, tx, t, request); err != nil {
				return nil, err
			}
			plan := DeploymentPlan{Request: request, Node: n, ConfigDigest: digest(n.Config), PreviousRuntime: from, Recovery: &deploymentRecoveryPlan{Source: in.Source, SourceDigest: in.SourceDigest, Head: in.Head, HeadDigest: in.HeadDigest, From: *from, Restore: *source.Plan.PreviousRuntime, RestoreAppliedVersion: source.Plan.Node.AppliedVersion}}
			if plan.BeforeBackup, err = (&deploymentConfigurationBackup{t.vault, c}).archive(ctx, tx, user); err != nil {
				return nil, err
			}
			var canonical []byte
			if err = tx.QueryRowContext(ctx, `SELECT $1::jsonb`, common.JSON(plan)).Scan(&canonical); err != nil {
				return nil, err
			}
			j := DeploymentJob{ID: token(), Node: n.ID, Username: user, Kind: "recover", Status: "queued", Direction: "rollback", NodeVersion: n.Version, Plan: plan, PlanDigest: digest(canonical)}
			if err = tx.QueryRowContext(ctx, `INSERT INTO v3_deployment_jobs(id,node,username,kind,direction,recovery_required,node_version,credential,plan,plan_digest) VALUES($1,$2,$3,'recover','rollback',true,$4,$5,$6,$7) RETURNING created_at`, j.ID, j.Node, user, n.Version, in.Credential, canonical, j.PlanDigest).Scan(&j.CreatedAt); err != nil {
				return nil, err
			}
			proof, err := recoveryProof(t.vault, t.vault.active, j)
			if err != nil {
				return nil, err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO v3_deployment_recoveries(job,source,head,key_id,proof) VALUES($1,$2,$3,$4,$5)`, j.ID, in.Source, in.Head, t.vault.active, proof); err != nil {
				return nil, err
			}
			if _, err = readDeploymentRecoveryTx(ctx, tx, t.vault, j, map[string]bool{}); err != nil {
				return nil, err
			}
			if err = checkRecoveryRuntimeTx(ctx, tx, j); err != nil {
				return nil, err
			}
			if err = pinDeploymentConfigurationTx(ctx, tx, user, j); err != nil {
				return nil, err
			}
			if err = armDeploymentConfigurationTx(ctx, tx, j); err != nil {
				return nil, err
			}
			if err = deploymentLog(ctx, tx, &j, "restore", "queued"); err != nil {
				return nil, err
			}
			return map[string]any{"id": j.ID, "node": j.Node, "status": j.Status, "direction": j.Direction}, nil
		})
	})
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		switch pg.ConstraintName {
		case "v3_deployment_node_reserved":
			return nil, ErrDeploymentBusy
		case "v3_deployment_recoveries_source_key":
			return nil, errDeploymentRecovery
		}
	}
	return out, err
}
