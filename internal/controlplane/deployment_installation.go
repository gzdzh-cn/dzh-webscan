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
	"io"
	"net"
	"slices"
	"strconv"
	"strings"

	"webscan/internal/common"
	"webscan/internal/nodeops"
)

var errDeploymentInstallation = errors.New("节点安装恢复证据缺失、损坏或与任务不符")

type deploymentInstallation struct {
	Job, Node, PlanDigest string
	Spec                  nodeops.Spec
	Evidence              nodeops.InstallationEvidence
	Epoch                 int64
	Key, Proof            string
}

func installationMatchesPlan(j DeploymentJob, spec nodeops.Spec, configuration []byte) bool {
	p := j.Plan
	settings, err := nodeRuntimeSettings(configuration)
	_, port, portErr := net.SplitHostPort(p.Node.Endpoint)
	n, numberErr := strconv.Atoi(port)
	artifact := p.Request.RuntimeArtifact
	if err != nil || portErr != nil || numberErr != nil || artifact == nil || spec.Validate() != nil || spec.Mode != p.Node.Mode || spec.MetricsPort != n || !slices.Equal(spec.MonitorDirectories, settings.Monitor.Roots) || spec.ClamAV != settings.Scan.ClamAV.Enabled || spec.Release != p.Request.Release || spec.ConfigVersion != j.NodeVersion || spec.ConfigSourceSHA256 != p.ConfigDigest || spec.ServerName != p.Node.ServerName || spec.RuntimeSHA256 != artifact.SHA256 || spec.RuntimeBytes != artifact.Bytes {
		return false
	}
	if spec.Mode == "native" {
		return spec.BundleSHA256 == p.Request.SHA256 && spec.AgentImage == "" && spec.ImageArchiveSHA256 == "" && spec.ImageArchiveBytes == 0 && spec.ImageConfigSHA256 == ""
	}
	return nodeops.ValidAgentImage(spec.AgentImage) && strings.HasSuffix(spec.AgentImage, "@sha256:"+p.Request.SHA256)
}

// Node.Config is intentionally excluded from the serialized task plan. Use
// its immutable, digest-bound snapshot, never defaults from a decoded plan or
// the editable current node row.
func installationMatchesPlanTx(ctx context.Context, tx *sql.Tx, j DeploymentJob, spec nodeops.Spec) error {
	if err := requireNodeSnapshotAvailableTx(ctx, tx, j.Node, j.Plan.TargetRuntime); err != nil {
		return err
	}
	var configuration, snapshot []byte
	err := tx.QueryRowContext(ctx, `SELECT config,to_jsonb(c) FROM v3_node_configurations c WHERE node=$1 AND id=$2 FOR SHARE`, j.Node, j.Plan.TargetRuntime).Scan(&configuration, &snapshot)
	if err != nil {
		return err
	}
	if digest(snapshot) != j.Plan.TargetRuntimeDigest || digest(configuration) != j.Plan.ConfigDigest || !installationMatchesPlan(j, spec, configuration) {
		return errDeploymentInstallation
	}
	return nil
}

func installationProof(v *Vault, row deploymentInstallation) (string, error) {
	if v == nil || len(v.receiptKeys[row.Key]) == 0 {
		return "", errDeploymentInstallation
	}
	h := hmac.New(sha256.New, v.receiptKeys[row.Key])
	h.Write([]byte("webscan-v3/deployment-installation/v1\x00"))
	h.Write(common.JSON([]any{row.Job, row.Node, row.PlanDigest, row.Spec, row.Evidence, row.Epoch}))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readDeploymentInstallationTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob) (deploymentInstallation, error) {
	var row deploymentInstallation
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT job,node,plan_digest,spec,capture_sha256,active_sha256,recorded_epoch,key_id,proof FROM v3_deployment_installations WHERE job=$1 FOR SHARE`, j.ID).Scan(&row.Job, &row.Node, &row.PlanDigest, &raw, &row.Evidence.CaptureSHA256, &row.Evidence.ActiveSHA256, &row.Epoch, &row.Key, &row.Proof)
	if err != nil {
		return row, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&row.Spec) != nil || d.Decode(new(any)) != io.EOF || row.Job != j.ID || row.Node != j.Node || row.PlanDigest != j.PlanDigest || row.Epoch < 1 || !row.Evidence.Valid() {
		return deploymentInstallation{}, errDeploymentInstallation
	}
	want, err := installationProof(v, row)
	if err != nil || !hmac.Equal([]byte(row.Proof), []byte(want)) {
		return deploymentInstallation{}, errDeploymentInstallation
	}
	if err = installationMatchesPlanTx(ctx, tx, j, row.Spec); err != nil {
		return deploymentInstallation{}, err
	}
	return row, nil
}

// Called in the same fenced transaction as finalize/applied_version. There is
// no successful task whose newly collected recovery proof failed to commit.
func recordDeploymentInstallationTx(ctx context.Context, tx *sql.Tx, v *Vault, j DeploymentJob, remote RemoteDeploymentCheckpoint) error {
	if j.Direction != "forward" || j.Phase() != "finalize" || !remote.matches(j) || remote.State != "complete" || remote.Spec == nil || remote.Installation == nil || !remote.Installation.Valid() || v == nil {
		return errDeploymentInstallation
	}
	if err := installationMatchesPlanTx(ctx, tx, j, *remote.Spec); err != nil {
		return err
	}
	row := deploymentInstallation{Job: j.ID, Node: j.Node, PlanDigest: j.PlanDigest, Spec: *remote.Spec, Evidence: *remote.Installation, Epoch: j.Epoch, Key: v.active}
	proof, err := installationProof(v, row)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO v3_deployment_installations(job,node,plan_digest,spec,capture_sha256,active_sha256,recorded_epoch,key_id,proof) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(job) DO NOTHING`, row.Job, row.Node, row.PlanDigest, common.JSON(row.Spec), row.Evidence.CaptureSHA256, row.Evidence.ActiveSHA256, row.Epoch, row.Key, proof)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	stored, err := readDeploymentInstallationTx(ctx, tx, v, j)
	if err != nil || stored.Epoch != row.Epoch || !bytes.Equal(common.JSON(stored.Spec), common.JSON(row.Spec)) || stored.Evidence != row.Evidence {
		return errDeploymentInstallation
	}
	if count == 0 {
		return nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'deployment-installation-recorded',$2,$3)`, j.Username, j.ID, common.JSON(map[string]any{"node": j.Node, "plan_digest": j.PlanDigest, "remote_epoch": j.Epoch}))
	return err
}
