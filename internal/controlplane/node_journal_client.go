package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodeops"
)

// SSHNodeRuntime speaks to a pre-provisioned, checksum-pinned v3 node helper.
// Provisioning of the trusted helper and artifact manifest remains separate;
// this client never downloads an executable or falls back to the v2 installer.
// The default adapter supports preparation only; the explicitly configured
// executor selects full lifecycle phases and task-bound configuration files.
// An unsupported phase must stop, never be recorded as installation success.
type SSHNodeRuntime struct {
	Store   *Store
	Vault   *Vault
	Release *TrustedRelease
	// These server-side paths are not accepted from deployment API requests.
	LocalHelper        string
	LocalBundle        string
	LocalImageArchive  string
	LocalConfiguration string
	// Lifecycle opts into native/Docker service phases. Configurations are
	// content-addressed per task, never one mutable file shared by workers.
	Lifecycle              bool
	ConfigurationDirectory string
	// Installed by the configured executor, never supplied by a job. Rechecks
	// live collector trust and the shared issuer floor before each remote phase.
	ValidateConfiguration func(context.Context, nodeconfig.Material) error
	// Production validation can inspect the fenced immutable task as well as
	// current trust. This is required when a managed installation's seed has
	// expired; the ordinary preparation decoder must remain strict.
	ValidateTaskConfiguration func(context.Context, DeploymentJob, []byte) error
}

func (w *SSHNodeRuntime) SupportsDeploymentPhase(phase string) bool {
	if phase == "preflight" || phase == "stage" {
		return true
	}
	if !w.Lifecycle {
		return false
	}
	switch phase {
	case "backup", "activate", "verify", "finalize", "restore", "verify-rollback":
		return true
	}
	return false
}

func (w *SSHNodeRuntime) Inspect(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	if (j.Direction == "forward" && j.Phase() == "preflight" || j.Kind == "recover" && j.Phase() == "restore") && w.LocalHelper != "" {
		if err := w.ProvisionHelper(ctx, j, w.LocalHelper); err != nil {
			return RemoteDeploymentCheckpoint{}, err
		}
	}
	return w.phase(ctx, j, "inspect")
}
func (w *SSHNodeRuntime) Apply(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	if j.Kind != "uninstall" && j.Direction == "forward" && j.Phase() == "stage" && w.LocalBundle != "" {
		if err := w.ProvisionBundle(ctx, j, w.LocalBundle); err != nil {
			return RemoteDeploymentCheckpoint{}, err
		}
	}
	if j.Kind != "uninstall" && j.Direction == "forward" && j.Phase() == "stage" && j.Plan.Node.Mode == "docker" && w.LocalImageArchive != "" {
		if err := w.ProvisionImageArchive(ctx, j, w.LocalImageArchive); err != nil {
			return RemoteDeploymentCheckpoint{}, err
		}
	}
	if j.Kind != "uninstall" && j.Direction == "forward" && j.Phase() == "stage" {
		configuration, err := w.configurationFile(ctx, j)
		if err != nil {
			return RemoteDeploymentCheckpoint{}, err
		}
		if configuration != "" {
			if err := w.ProvisionConfiguration(ctx, j, configuration); err != nil {
				return RemoteDeploymentCheckpoint{}, err
			}
		}
	}
	return w.phase(ctx, j, "apply")
}
func (w *SSHNodeRuntime) request(ctx context.Context, j DeploymentJob, operation string) (nodeops.Request, error) {
	var request nodeops.Request
	if w.Store == nil || w.Vault == nil || w.Release == nil {
		return request, DeploymentFailure{"executor-unavailable"}
	}
	if !w.Release.matches(j) {
		return request, DeploymentFailure{"artifact-invalid"}
	}
	if j.Kind == "uninstall" {
		if !w.Lifecycle {
			return request, DeploymentFailure{"executor-unavailable"}
		}
		if err := w.Store.checkDeploymentPlan(ctx, j); err != nil {
			return request, err
		}
		return w.Store.uninstallRequest(ctx, w.Vault, j, operation)
	}
	if j.Kind == "recover" || j.Plan.Recovery != nil {
		if !w.Lifecycle {
			return request, DeploymentFailure{"executor-unavailable"}
		}
		if err := w.Store.checkDeploymentPlan(ctx, j); err != nil {
			return request, err
		}
		return w.Store.recoveryRequest(ctx, w.Vault, j, operation)
	}
	if w.Lifecycle {
		path, err := w.configurationFile(ctx, j)
		if err != nil {
			return request, err
		}
		if w.ValidateConfiguration != nil || w.ValidateTaskConfiguration != nil {
			raw, err := readTrustData(path, true, nodeconfig.MaxBytes)
			if err != nil {
				return request, DeploymentFailure{"artifact-invalid"}
			}
			defer clear(raw)
			a := j.Plan.Request.RuntimeArtifact
			if a == nil || digest(raw) != a.SHA256 || uint64(len(raw)) != a.Bytes {
				return request, DeploymentFailure{"artifact-invalid"}
			}
			if w.ValidateTaskConfiguration != nil {
				if err := w.ValidateTaskConfiguration(ctx, j, raw); err != nil {
					return request, DeploymentFailure{"artifact-invalid"}
				}
			} else {
				material, err := nodeconfig.Decode(raw, time.Now())
				defer clear(material.Key)
				if err != nil || w.ValidateConfiguration(ctx, material) != nil {
					return request, DeploymentFailure{"artifact-invalid"}
				}
			}
		}
	}
	if err := w.Store.checkDeploymentPlan(ctx, j); err != nil {
		return request, err
	}
	n, err := scanNode(w.Store.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE id=$1 AND version=$2", j.Node, j.NodeVersion))
	if err != nil {
		return request, ErrConflict
	}
	if digest(n.Config) != j.Plan.ConfigDigest {
		return request, ErrConflict
	}
	// Use the same defaults and typed validation as the immutable package.
	// Sparse saved configs must not generate an empty monitor scope here.
	settings, err := nodeRuntimeSettings(n.Config)
	if err != nil {
		return request, DeploymentFailure{"preflight-failed"}
	}
	_, port, e := net.SplitHostPort(n.Endpoint)
	p, pe := strconv.Atoi(port)
	if e != nil || pe != nil {
		return request, DeploymentFailure{"preflight-failed"}
	}
	request = nodeops.Request{Protocol: nodeops.Protocol, Operation: operation, Job: j.ID, Node: j.Node, PlanDigest: j.PlanDigest, Epoch: j.Epoch, Phase: j.Phase(), Spec: nodeops.Spec{Mode: n.Mode, MetricsPort: p, MonitorDirectories: settings.Monitor.Roots, ArtifactBytes: w.Release.manifest.Native.Bytes, ClamAV: settings.Scan.ClamAV.Enabled, Release: w.Release.manifest.Release, BundleSHA256: w.Release.manifest.Native.SHA256}}
	if n.Mode == "docker" {
		request.Spec.AgentImage = w.Release.manifest.Image
		if a := w.Release.manifest.ImageArchive; a != nil {
			request.Spec.ImageArchiveSHA256, request.Spec.ImageArchiveBytes, request.Spec.ImageConfigSHA256 = a.SHA256, a.Bytes, w.Release.manifest.ImageConfigSHA256
		}
	}
	if a := j.Plan.Request.RuntimeArtifact; a != nil {
		request.Spec.RuntimeSHA256, request.Spec.RuntimeBytes = a.SHA256, a.Bytes
		request.Spec.ConfigVersion, request.Spec.ConfigSourceSHA256, request.Spec.ServerName = n.Version, j.Plan.ConfigDigest, n.ServerName
	}
	request.Reinstall = j.Plan.Reinstall
	if request.Validate() != nil {
		return request, DeploymentFailure{"preflight-failed"}
	}
	return request, nil
}
func (w *SSHNodeRuntime) phase(ctx context.Context, j DeploymentJob, operation string) (RemoteDeploymentCheckpoint, error) {
	request, err := w.request(ctx, j, operation)
	if err != nil {
		return RemoteDeploymentCheckpoint{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, nodePhaseTimeout(w.Lifecycle, j.Phase()))
	defer cancel()
	remote, err := w.Store.ConnectDeploymentSSH(ctx, w.Vault, j)
	if err != nil {
		return RemoteDeploymentCheckpoint{}, err
	}
	defer remote.Close()
	raw, _ := json.Marshal(request)
	// Every shell token here is server-generated or hexadecimal; none comes
	// from editable paths, monitor rules or a browser-supplied command.
	command := helperRunCommand(w.Release.manifest.Helper)
	if w.Lifecycle {
		command = strings.TrimSuffix(command, "\n") + " --lifecycle\n"
	}
	capture, err := runNodeCommand(ctx, remote.Client, command, bytes.NewReader(raw))
	if ctx.Err() != nil {
		return RemoteDeploymentCheckpoint{}, ctx.Err()
	}
	// An expected helper failure still returns a structured diagnosis. A shell
	// failure, corrupt JSON or oversized response is never treated as a receipt.
	if capture.overflow {
		return RemoteDeploymentCheckpoint{}, DeploymentFailure{"remote-state-unknown"}
	}
	var response nodeops.Result
	d := json.NewDecoder(bytes.NewReader(capture.raw))
	d.DisallowUnknownFields()
	if d.Decode(&response) != nil || d.Decode(new(any)) != io.EOF {
		return RemoteDeploymentCheckpoint{}, DeploymentFailure{"remote-unavailable"}
	}
	proof, err := decodeNodeReceipt(request, response, err)
	if err == nil && w.Lifecycle && request.Phase == "finalize" && proof.State == "complete" && (request.Uninstall == nil && proof.Installation == nil || request.Uninstall != nil && proof.Removal == nil) {
		return RemoteDeploymentCheckpoint{}, DeploymentFailure{"remote-state-unknown"}
	}
	return proof, err
}

func nodePhaseTimeout(lifecycle bool, phase string) time.Duration {
	if phase == "stage" {
		return 6 * time.Minute
	}
	if lifecycle {
		switch phase {
		case "backup", "activate", "restore", "verify", "finalize", "verify-rollback":
			// Verification/finalization authenticate the complete signed image
			// and live process, including replay after a lost response. Their
			// bounded budget must cover the same slow storage as staging.
			return 6 * time.Minute
		}
	}
	return 75 * time.Second
}

func (w *SSHNodeRuntime) configurationFile(ctx context.Context, j DeploymentJob) (string, error) {
	if w.ConfigurationDirectory == "" {
		if w.Lifecycle {
			return "", DeploymentFailure{"artifact-invalid"}
		}
		return w.LocalConfiguration, nil
	}
	if w.LocalConfiguration != "" || j.Plan.Request.RuntimeArtifact == nil || !releaseDigest(j.Plan.Request.RuntimeArtifact.SHA256) {
		return "", DeploymentFailure{"artifact-invalid"}
	}
	root, err := trustDirectory(w.ConfigurationDirectory, true)
	if err != nil {
		return "", DeploymentFailure{"artifact-invalid"}
	}
	defer root.Close()
	dir := filepath.Join(w.ConfigurationDirectory, j.Plan.Request.RuntimeArtifact.SHA256)
	d, err := trustDirectory(dir, true)
	if err != nil {
		return "", DeploymentFailure{"artifact-invalid"}
	}
	d.Close()
	path := filepath.Join(dir, "node.json")
	f, err := verifiedReleaseFile(ctx, path, *j.Plan.Request.RuntimeArtifact, nodeconfig.MaxBytes)
	if err != nil {
		return "", DeploymentFailure{"artifact-invalid"}
	}
	f.Close()
	return path, nil
}
func decodeNodeReceipt(request nodeops.Request, response nodeops.Result, commandError error) (RemoteDeploymentCheckpoint, error) {
	empty := RemoteDeploymentCheckpoint{}
	if response.Protocol != nodeops.Protocol || response.Job != request.Job || response.Node != request.Node || response.PlanDigest != request.PlanDigest || response.Epoch != request.Epoch || response.Phase != request.Phase {
		return empty, DeploymentFailure{"remote-state-unknown"}
	}
	if response.Code != "ok" {
		switch response.Code {
		case "fenced":
			return empty, ErrLeaseLost
		case "busy", "remote-conflict":
			return empty, DeploymentFailure{"remote-conflict"}
		case "executor-unavailable":
			return empty, DeploymentFailure{"executor-unavailable"}
		case "preflight-failed", "artifact-invalid", "backup-failed", "activation-failed", "verification-failed":
			return empty, DeploymentFailure{response.Code}
		case "phase-order", "remote-state-unknown":
			return empty, DeploymentFailure{"remote-state-unknown"}
		default:
			return empty, DeploymentFailure{"remote-unavailable"}
		}
	}
	if commandError != nil || response.State != "absent" && response.State != "complete" {
		return empty, DeploymentFailure{"remote-state-unknown"}
	}
	proof := RemoteDeploymentCheckpoint{Job: response.Job, PlanDigest: response.PlanDigest, Phase: response.Phase, Epoch: response.Epoch, State: response.State}
	if response.Removal != nil {
		if request.Uninstall == nil || request.Phase != "finalize" || response.State != "complete" || !response.Removal.Valid() || response.Restoration != nil || response.Installation != nil {
			return empty, DeploymentFailure{"remote-state-unknown"}
		}
		value := *response.Removal
		proof.Removal = &value
	}
	if response.Restoration != nil {
		if request.Uninstall == nil || request.Phase != "verify-rollback" || response.State != "complete" || !response.Restoration.Valid() || response.Removal != nil || response.Installation != nil {
			return empty, DeploymentFailure{"remote-state-unknown"}
		}
		value := *response.Restoration
		proof.Restoration = &value
	}
	if request.Uninstall != nil && request.Phase == "verify-rollback" && response.State == "complete" && proof.Restoration == nil {
		return empty, DeploymentFailure{"remote-state-unknown"}
	}
	if response.Installation != nil {
		if request.Phase != "finalize" || request.Recovery != nil || request.Uninstall != nil || response.State != "complete" || !response.Installation.Valid() {
			return empty, DeploymentFailure{"remote-state-unknown"}
		}
		spec, installation := request.Spec, *response.Installation
		proof.Spec, proof.Installation = &spec, &installation
	}
	return proof, nil
}

type nodeResponseCapture struct {
	raw      []byte
	overflow bool
}

func (b *nodeResponseCapture) Write(raw []byte) (int, error) {
	n := len(raw)
	free := (64 << 10) - len(b.raw)
	if n > free {
		b.overflow = true
	}
	if free > 0 {
		b.raw = append(b.raw, raw[:min(free, n)]...)
	}
	return n, nil
}

var _ DeploymentRuntime = (*SSHNodeRuntime)(nil)
