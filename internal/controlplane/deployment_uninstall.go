package controlplane

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"

	"webscan/internal/common"
	"webscan/internal/nodeops"
)

var errNodeUninstall = errors.New("实际安装身份或恢复资料无法确认，已停止卸载；请核对原安装任务")

// Source identifies an authenticated installation rather than editable intent.
// Node.Config is omitted by Node's encoding; the immutable snapshot and digest
// remain the authority for private configuration.
type deploymentInstalledSource struct {
	Job         string                       `json:"job"`
	PlanDigest  string                       `json:"plan_digest"`
	Node        Node                         `json:"node"`
	Snapshot    string                       `json:"snapshot"`
	Spec        nodeops.Spec                 `json:"spec"`
	Evidence    nodeops.InstallationEvidence `json:"evidence"`
	Restoration *deploymentSourceRestoration `json:"restoration,omitempty"`
	Reinstall   *nodeops.ReinstallReference  `json:"reinstall,omitempty"`
}

type deploymentSourceRestoration struct {
	Job        string                      `json:"job"`
	PlanDigest string                      `json:"plan_digest"`
	Evidence   nodeops.RestorationEvidence `json:"evidence"`
}

type deploymentUninstallPlan struct {
	Source deploymentInstalledSource `json:"source"`
}

type deploymentLifecycleState struct {
	Node              string                     `json:"node"`
	Job               string                     `json:"job"`
	State             string                     `json:"state"`
	RuntimeGeneration int64                      `json:"runtime_generation"`
	Source            *deploymentInstalledSource `json:"source,omitempty"`
}

func lifecycleProof(v *Vault, key, domain string, value any) (string, error) {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return "", errNodeUninstall
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/" + domain + "/v1\x00"))
	h.Write(common.JSON(value))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readNodeLifecycleTx(ctx context.Context, tx *sql.Tx, v *Vault, node string) (*deploymentLifecycleState, error) {
	var raw []byte
	var key, proof, job, state string
	err := tx.QueryRowContext(ctx, `SELECT job,state,body,key_id,proof FROM v3_node_lifecycle WHERE node=$1 FOR SHARE`, node).Scan(&job, &state, &raw, &key, &proof)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value deploymentLifecycleState
	if json.Unmarshal(raw, &value) != nil || value.Node != node || value.Job != job || value.State != state || state != "installed" && state != "uninstalled" {
		return nil, errNodeUninstall
	}
	want, err := lifecycleProof(v, key, "node-lifecycle", value)
	if err != nil || !hmac.Equal([]byte(want), []byte(proof)) {
		return nil, errNodeUninstall
	}
	return &value, nil
}

func writeNodeLifecycleTx(ctx context.Context, tx *sql.Tx, v *Vault, value deploymentLifecycleState) error {
	if v == nil || value.State != "installed" && value.State != "uninstalled" {
		return errNodeUninstall
	}
	if err := tx.QueryRowContext(ctx, `SELECT runtime_generation FROM v3_nodes WHERE id=$1`, value.Node).Scan(&value.RuntimeGeneration); err != nil {
		return err
	}
	proof, err := lifecycleProof(v, v.active, "node-lifecycle", value)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_node_lifecycle(node,job,state,body,key_id,proof) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(node) DO UPDATE SET job=excluded.job,state=excluded.state,body=excluded.body,key_id=excluded.key_id,proof=excluded.proof,updated_at=clock_timestamp()`, value.Node, value.Job, value.State, common.JSON(value), v.active, proof)
	return err
}

func sourceFromInstallation(j DeploymentJob, row deploymentInstallation) deploymentInstalledSource {
	return deploymentInstalledSource{Job: j.ID, PlanDigest: j.PlanDigest, Node: j.Plan.Node, Snapshot: j.Plan.TargetRuntime, Spec: row.Spec, Evidence: row.Evidence, Reinstall: j.Plan.Reinstall}
}

func authenticateInstalledSourceTx(ctx context.Context, tx *sql.Tx, v *Vault, source deploymentInstalledSource) error {
	j, err := readRecoveryJobTx(ctx, tx, source.Job)
	if err != nil {
		return err
	}
	if j.Node != source.Node.ID || j.PlanDigest != source.PlanDigest || j.Plan.TargetRuntime != source.Snapshot || j.Status != "succeeded" || j.Direction != "forward" || j.Kind != "install" && j.Kind != "upgrade" {
		return errNodeUninstall
	}
	row, err := readDeploymentInstallationTx(ctx, tx, v, j)
	if err != nil {
		return err
	}
	want := sourceFromInstallation(j, row)
	want.Restoration = source.Restoration
	if !bytes.Equal(common.JSON(want), common.JSON(source)) {
		return errNodeUninstall
	}
	if r := source.Restoration; r != nil {
		parent, err := readRecoveryJobTx(ctx, tx, r.Job)
		if err != nil {
			return err
		}
		if parent.Kind != "uninstall" || parent.PlanDigest != r.PlanDigest || parent.Plan.Uninstall == nil || parent.Plan.Uninstall.Source.Job != source.Job || parent.Status != "rolled_back" || parent.RollbackStep != 2 {
			return errNodeUninstall
		}
		var evidence nodeops.RestorationEvidence
		if err := readLifecycleReceiptTx(ctx, tx, v, parent, "restoration", &evidence); err != nil || !evidence.Valid() || evidence != r.Evidence {
			return errNodeUninstall
		}
	}
	return nil
}

// Old installations are adopted only from a matching registered snapshot and
// existing authenticated proof. Missing proof remains unknown, never installed.
func installedSourceTx(ctx context.Context, tx *sql.Tx, v *Vault, n Node) (deploymentInstalledSource, error) {
	var empty deploymentInstalledSource
	lifecycle, err := readNodeLifecycleTx(ctx, tx, v, n.ID)
	if err != nil {
		return empty, err
	}
	if lifecycle != nil {
		var generation int64
		if err := tx.QueryRowContext(ctx, `SELECT runtime_generation FROM v3_nodes WHERE id=$1`, n.ID).Scan(&generation); err != nil {
			return empty, err
		}
		if lifecycle.State != "installed" || lifecycle.Source == nil || lifecycle.RuntimeGeneration != generation {
			return empty, errNodeUninstall
		}
		if err := authenticateInstalledSourceTx(ctx, tx, v, *lifecycle.Source); err != nil {
			return empty, err
		}
		return *lifecycle.Source, nil
	}
	return installedSourceFromRuntimeTx(ctx, tx, v, n)
}

func installedSourceFromRuntimeTx(ctx context.Context, tx *sql.Tx, v *Vault, n Node) (deploymentInstalledSource, error) {
	var empty deploymentInstalledSource
	b, err := runtimeBaselineTx(ctx, tx, n.ID)
	if err != nil || b.Snapshot == "" || b.Delivered < 1 || n.AppliedVersion < 1 {
		return empty, errNodeUninstall
	}
	j, err := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE node=$1 AND status='succeeded' AND kind IN ('install','upgrade') AND plan->>'target_runtime'=$2 ORDER BY created_at DESC,id DESC LIMIT 1 FOR SHARE`, n.ID, b.Snapshot))
	if err != nil {
		return empty, errNodeUninstall
	}
	row, err := readDeploymentInstallationTx(ctx, tx, v, j)
	if err != nil {
		return empty, err
	}
	return sourceFromInstallation(j, row), nil
}

func uninstallPlanProof(v *Vault, key string, j DeploymentJob) (string, error) {
	if j.Kind != "uninstall" || j.Plan.Uninstall == nil {
		return "", errNodeUninstall
	}
	return lifecycleProof(v, key, "uninstall-authorization", []any{j.ID, j.Node, j.PlanDigest, j.Plan.Uninstall})
}

func readUninstallPlanTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob) error {
	var source, key, proof string
	if err := tx.QueryRowContext(ctx, `SELECT source,key_id,proof FROM v3_deployment_uninstalls WHERE job=$1 FOR SHARE`, j.ID).Scan(&source, &key, &proof); err != nil {
		return err
	}
	want, err := uninstallPlanProof(v, key, j)
	if err != nil || !hmac.Equal([]byte(want), []byte(proof)) || source != j.Plan.Uninstall.Source.Job {
		return errNodeUninstall
	}
	return authenticateInstalledSourceTx(ctx, tx, v, j.Plan.Uninstall.Source)
}

func lifecycleReceiptProof(v *Vault, key string, j DeploymentJob, kind string, raw any, epoch int64) (string, error) {
	// PostgreSQL jsonb reorders fields. Normalize before signing so typed
	// receipts and independently decoded replay evidence have one encoding.
	var canonical any
	if json.Unmarshal(common.JSON(raw), &canonical) != nil {
		return "", errNodeUninstall
	}
	return lifecycleProof(v, key, "deployment-lifecycle-receipt", []any{j.ID, j.Node, j.PlanDigest, kind, canonical, epoch})
}

func readLifecycleReceiptTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob, kind string, into any) error {
	var raw []byte
	var key, proof string
	var epoch int64
	if err := tx.QueryRowContext(ctx, `SELECT evidence,recorded_epoch,key_id,proof FROM v3_deployment_lifecycle_receipts WHERE job=$1 AND kind=$2 FOR SHARE`, j.ID, kind).Scan(&raw, &epoch, &key, &proof); err != nil {
		return err
	}
	if json.Unmarshal(raw, into) != nil || epoch < 1 {
		return errNodeUninstall
	}
	want, err := lifecycleReceiptProof(v, key, j, kind, into, epoch)
	if err != nil || !hmac.Equal([]byte(want), []byte(proof)) {
		return errNodeUninstall
	}
	return nil
}

func recordLifecycleReceiptTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob, kind string, evidence any) error {
	if v == nil {
		return errNodeUninstall
	}
	proof, err := lifecycleReceiptProof(v, v.active, j, kind, evidence, j.Epoch)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_deployment_lifecycle_receipts(job,kind,evidence,recorded_epoch,key_id,proof) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(job,kind) DO NOTHING`, j.ID, kind, common.JSON(evidence), j.Epoch, v.active, proof)
	if err != nil {
		return err
	}
	var stored any
	if err := readLifecycleReceiptTx(ctx, tx, v, j, kind, &stored); err != nil {
		return err
	}
	var expected any
	if json.Unmarshal(common.JSON(evidence), &expected) != nil || !bytes.Equal(common.JSON(stored), common.JSON(expected)) {
		return errNodeUninstall
	}
	return nil
}

func uninstallReference(source deploymentInstalledSource) *nodeops.UninstallReference {
	ref := &nodeops.UninstallReference{SourceJob: source.Job, SourcePlanDigest: source.PlanDigest, CaptureSHA256: source.Evidence.CaptureSHA256, ActiveSHA256: source.Evidence.ActiveSHA256}
	if r := source.Restoration; r != nil {
		ref.ActiveSHA256 = r.Evidence.ActiveSHA256
		ref.RestorationJob, ref.RestorationPlanDigest = r.Job, r.PlanDigest
		ref.RestorationSHA256 = digest(common.JSON(r.Evidence))
	}
	return ref
}

func (s *Store) uninstallRequest(ctx context.Context, v *Vault, j DeploymentJob, operation string) (nodeops.Request, error) {
	var empty nodeops.Request
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := lockDeploymentJournalTx(ctx, tx, j); err != nil {
		return empty, err
	}
	current, err := lockedDeployment(ctx, tx, j)
	if err != nil {
		return empty, err
	}
	if err := readUninstallPlanTx(ctx, tx, v, current); err != nil {
		return empty, err
	}
	if err := checkUninstallRuntimeTx(ctx, tx, current); err != nil {
		return empty, err
	}
	source := current.Plan.Uninstall.Source
	spec := source.Spec
	spec.Action = "uninstall"
	request := nodeops.Request{Protocol: nodeops.Protocol, Operation: operation, Job: j.ID, Node: j.Node, PlanDigest: j.PlanDigest, Epoch: j.Epoch, Phase: j.Phase(), Spec: spec, Uninstall: uninstallReference(source)}
	if err := request.Validate(); err != nil {
		return empty, errNodeUninstall
	}
	return request, tx.Commit()
}

func (s *Store) uninstallCredentialTx(ctx context.Context, tx *sql.Tx, v *Vault, source deploymentInstalledSource) (string, SSHCredential, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT credential FROM v3_web_uninstall_credentials WHERE node=$1 AND source=$2`, source.Node.ID, source.Job).Scan(&id)
	if err == sql.ErrNoRows {
		j, e := readRecoveryJobTx(ctx, tx, source.Job)
		if e != nil {
			return "", SSHCredential{}, e
		}
		id, err = j.Plan.Request.Credential, nil
	}
	if err != nil {
		return "", SSHCredential{}, err
	}
	var key string
	var rev int64
	var nonce, sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT key_id,revision,nonce,ciphertext FROM v3_credentials WHERE id=$1 AND node=$2 FOR SHARE`, id, source.Node.ID).Scan(&key, &rev, &nonce, &sealed); err != nil {
		return "", SSHCredential{}, err
	}
	c, err := v.open(id, source.Node.ID, key, rev, nonce, sealed)
	host, _, hostErr := net.SplitHostPort(source.Node.Endpoint)
	if err != nil || hostErr != nil || c.Host != host {
		return "", SSHCredential{}, ErrCredentialUnavailable
	}
	return id, c, nil
}
