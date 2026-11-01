package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"

	"webscan/internal/common"
)

type publicInstalledTarget struct {
	Job        string `json:"job"`
	PlanDigest string `json:"plan_digest"`
	Release    string `json:"release"`
	SHA256     string `json:"sha256"`
	Mode       string `json:"mode"`
	Endpoint   string `json:"endpoint"`
	Host       string `json:"host"`
	SSHPort    int    `json:"ssh_port"`
}

func publicUninstallTarget(source deploymentInstalledSource, c SSHCredential) publicInstalledTarget {
	sha := source.Spec.BundleSHA256
	if source.Spec.Mode == "docker" {
		sha = source.Spec.AgentImage[len(source.Spec.AgentImage)-64:]
	}
	return publicInstalledTarget{Job: source.Job, PlanDigest: source.PlanDigest, Release: source.Spec.Release, SHA256: sha, Mode: source.Spec.Mode, Endpoint: source.Node.Endpoint, Host: c.Host, SSHPort: c.Port}
}

func (s *Store) webUninstallSource(ctx context.Context, v *Vault, n Node) (deploymentInstalledSource, string, SSHCredential, string, error) {
	var empty deploymentInstalledSource
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, "", SSHCredential{}, "", err
	}
	defer tx.Rollback()
	if err := lockConfigurationOperationTx(ctx, tx, false); err != nil {
		return empty, "", SSHCredential{}, "", err
	}
	current, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR SHARE`, n.ID))
	if err != nil || current.Version != n.Version {
		return empty, "", SSHCredential{}, "", ErrConflict
	}
	if _, _, _, err := deploymentPreviewState(ctx, tx, current, DeploymentRequest{}); err != nil {
		return empty, "", SSHCredential{}, "", err
	}
	if err := uninstallMaintenanceAvailableTx(ctx, tx, n.ID); err != nil {
		return empty, "", SSHCredential{}, "", err
	}
	source, err := installedSourceTx(ctx, tx, v, current)
	if err != nil {
		return empty, "", SSHCredential{}, "", err
	}
	credential, c, err := s.uninstallCredentialTx(ctx, tx, v, source)
	if err != nil {
		return empty, "", SSHCredential{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return empty, "", SSHCredential{}, "", err
	}
	return source, credential, c, digest(common.JSON([]any{current.Version, source})), nil
}

func (s *Store) addWebUninstallCredential(ctx context.Context, v *Vault, p deploymentPreparation, source deploymentInstalledSource, state string, c SSHCredential) (json.RawMessage, error) {
	if c.validate() != nil {
		return nil, ErrCredentialUnavailable
	}
	id := token()
	key, nonce, sealed, err := v.seal(id, p.Node, 1, c)
	if err != nil {
		return nil, err
	}
	requestProof, err := lifecycleProof(v, key, "web-uninstall-credential", []any{p.ID, source.Job, state, c})
	if err != nil {
		return nil, err
	}
	return s.guardedMutation(ctx, p.Username, "web-uninstall-credential-"+p.ID, "uninstall-ssh-credential", p.Node, []any{p.Version, source.Job, state, requestProof}, func(tx *sql.Tx) error {
		if err := lockConfigurationOperationTx(ctx, tx, false); err != nil {
			return err
		}
		if _, err := deploymentPreviewAccount(ctx, tx, p.Username); err != nil {
			return err
		}
		n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR UPDATE`, p.Node))
		if err != nil || n.Version != p.Version {
			return ErrConflict
		}
		var owned bool
		if err := tx.QueryRowContext(ctx, `SELECT lease_owner=$2 AND lease_epoch=$3 AND account_revision=(SELECT revision FROM v3_accounts WHERE username=$4) AND status='running' AND lease_until>clock_timestamp() AND expires_at>clock_timestamp() FROM v3_deployment_preparations WHERE id=$1 FOR SHARE`, p.ID, p.Owner.String, p.Epoch, p.Username).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return errWebDeployment
		}
		if err := uninstallMaintenanceAvailableTx(ctx, tx, n.ID); err != nil {
			return err
		}
		if _, _, _, err := deploymentPreviewState(ctx, tx, n, DeploymentRequest{}); err != nil {
			return err
		}
		live, err := installedSourceTx(ctx, tx, v, n)
		if err != nil || digest(common.JSON([]any{n.Version, live})) != state {
			return errNodeUninstall
		}
		_, prior, err := s.uninstallCredentialTx(ctx, tx, v, live)
		if err != nil || prior.Host != c.Host || prior.Port != c.Port || prior.Fingerprint != c.Fingerprint {
			return errFingerprintChanged
		}
		return nil
	}, func(tx *sql.Tx) (any, error) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_credentials(id,node,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5)`, id, p.Node, key, nonce, sealed); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_web_uninstall_credentials(node,source,credential) VALUES($1,$2,$3) ON CONFLICT(node,source) DO UPDATE SET credential=excluded.credential`, p.Node, source.Job, id); err != nil {
			return nil, err
		}
		return map[string]any{"id": id, "node": p.Node, "configured": true}, nil
	})
}

func (s *Store) prepareUninstallDeployment(ctx context.Context, c Config, t *deploymentTrust, n Node, source deploymentInstalledSource, credential string) (DeploymentRequest, error) {
	sha := t.release.manifest.Native.SHA256
	if n.Mode == "docker" {
		sha = t.release.manifest.Image[len(t.release.manifest.Image)-64:]
	}
	in := DeploymentRequest{Node: n.ID, Kind: "uninstall", Expected: n.Version, Credential: credential, Release: t.release.manifest.Release, SHA256: sha, ManifestSHA256: t.release.SHA256()}
	if !c.Executor.Enabled || in.validate() != nil || source.Node.ID != n.ID {
		return DeploymentRequest{}, errNodeUninstall
	}
	return in, nil
}

func (a *API) uninstallCredentialStatus(ctx context.Context, v *Vault, n Node) (map[string]any, error) {
	source, _, c, _, err := a.Store.webUninstallSource(ctx, v, n)
	if err != nil {
		return nil, err
	}
	target := publicUninstallTarget(source, c)
	return map[string]any{"configured": true, "version": n.Version, "ssh_port": c.Port, "fingerprint": c.Fingerprint, "installation": target, "can_uninstall": true, "reason": "", "outcome": "still_installed"}, nil
}

func (s *Store) checkUninstallSSH(ctx context.Context, v *Vault, j DeploymentJob, c SSHCredential) error {
	if j.Plan.Uninstall == nil {
		return errNodeUninstall
	}
	host, _, err := net.SplitHostPort(j.Plan.Uninstall.Source.Node.Endpoint)
	if err != nil || c.Host != host {
		return ErrCredentialUnavailable
	}
	// The immutable task selected this exact credential. A later credential
	// replacement affects future requests, never an in-flight recovery.
	return nil
}
