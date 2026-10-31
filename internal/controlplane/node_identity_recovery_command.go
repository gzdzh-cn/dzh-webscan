package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"time"
)

type nodeIdentityRecoveryPreparationFile struct {
	Node           string `json:"node"`
	Expected       int64  `json:"expected_version"`
	Credential     string `json:"credential"`
	CertificatePEM string `json:"certificate_pem"`
	LifetimeHours  int    `json:"lifetime_hours"`
	Confirm        bool   `json:"confirm"`
}

type nodeIdentityRecoveryTargetFile struct {
	ID      string `json:"id"`
	Confirm bool   `json:"confirm"`
}

// Read-only projection intentionally omits credentials, paths, public request
// material and account revisions. A historical status is not live readiness.
type nodeIdentityRecoveryView struct {
	ID          string    `json:"id"`
	Node        string    `json:"node"`
	Status      string    `json:"status"`
	NodeVersion int64     `json:"node_version,string"`
	ExpiresAt   time.Time `json:"expires_at"`
	Expired     bool      `json:"expired"`
}

func (s *Store) nodeIdentityRecoveryStatus(ctx context.Context, user, id string) (nodeIdentityRecoveryView, error) {
	var out nodeIdentityRecoveryView
	if !identifier.MatchString(id) || !identifier.MatchString(user) {
		return out, errNodeIdentityRecovery
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if _, err := deploymentPreviewAccount(ctx, tx, user); err != nil {
		return out, err
	}
	err = tx.QueryRowContext(ctx, `SELECT id,node,status,node_version,expires_at FROM v3_node_identity_recoveries WHERE id=$1 AND username=$2`, id, user).Scan(&out.ID, &out.Node, &out.Status, &out.NodeVersion, &out.ExpiresAt)
	if err != nil {
		return nodeIdentityRecoveryView{}, errNodeIdentityRecovery
	}
	out.ExpiresAt = out.ExpiresAt.UTC()
	out.Expired = out.Status != "completed" && out.Status != "canceled" && !time.Now().Before(out.ExpiresAt)
	if err := tx.Commit(); err != nil {
		return nodeIdentityRecoveryView{}, err
	}
	return out, nil
}

// Host-only root CLI. Prepare saves explicit authorization but never connects
// or signs; run is a separate confirmed operation against that saved task.
// A repeated run uses the same task as its durable idempotency identifier.
func (s *Store) localNodeIdentityRecoveryCommand(ctx context.Context, c Config, o Options, out io.Writer) error {
	if err := provisioningAdmin(ctx, s.DB, o.Username); err != nil {
		return err
	}
	if o.Action == "prepare-node-identity-recovery" {
		if !identifier.MatchString(o.RequestKey) {
			return errNodeIdentityRecovery
		}
		var in nodeIdentityRecoveryPreparationFile
		if provisioningInput(o.Source, &in) != nil || !in.Confirm || len(in.CertificatePEM) > 16<<10 {
			return errNodeIdentityRecovery
		}
		parent, err := provisioningCertificate([]byte(in.CertificatePEM))
		if err != nil {
			return errNodeIdentityRecovery
		}
		ca, _, err := provisioningCertificateIssuer(c, parent, time.Now())
		if err != nil {
			return errNodeIdentityRecovery
		}
		root, err := provisioningCertificate(ca)
		if err != nil {
			return errNodeIdentityRecovery
		}
		v, err := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
		if err != nil {
			return errNodeIdentityRecovery
		}
		if in.LifetimeHours == 0 {
			in.LifetimeHours = 720
		}
		j, err := s.prepareNodeIdentityRecovery(ctx, c, v, o.Username, o.RequestKey, nodeIdentityRecoveryInput{Node: in.Node, Credential: in.Credential, AuthoritySHA256: digest(root.Raw), ParentSHA256: digest(parent.Raw), Expected: in.Expected, LifetimeHours: in.LifetimeHours, Certificate: []byte(in.CertificatePEM)})
		if err != nil {
			return err
		}
		view, err := s.nodeIdentityRecoveryStatus(ctx, o.Username, j.ID)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(view)
	}
	var target nodeIdentityRecoveryTargetFile
	if provisioningInput(o.Source, &target) != nil || !identifier.MatchString(target.ID) {
		return errNodeIdentityRecovery
	}
	view, err := s.nodeIdentityRecoveryStatus(ctx, o.Username, target.ID)
	if err != nil {
		return err
	}
	switch o.Action {
	case "node-identity-recovery-status":
		return json.NewEncoder(out).Encode(view)
	case "cancel-node-identity-recovery":
		if !target.Confirm || !identifier.MatchString(o.RequestKey) {
			return errNodeIdentityRecovery
		}
		if _, err := s.cancelNodeIdentityRecovery(ctx, o.Username, o.RequestKey, target.ID); err != nil {
			return err
		}
		view, err = s.nodeIdentityRecoveryStatus(ctx, o.Username, target.ID)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(view)
	case "run-node-identity-recovery":
		if !target.Confirm {
			return errNodeIdentityRecovery
		}
		if view.Status == "completed" {
			return json.NewEncoder(out).Encode(view)
		}
		trust, err := loadDeploymentTrust(ctx, c.DeploymentTrust)
		if err != nil {
			return err
		}
		remote := &sshNodeIdentityRecovery{store: s, vault: trust.vault, config: c, release: trust.release, localHelper: trust.config.HelperFile}
		worker := nodeIdentityRecoveryRunner{store: s, vault: trust.vault, runtime: remote}
		encoder := json.NewEncoder(out)
		return worker.run(ctx, o.Username, target.ID, func(p identityRecoveryProgress) error { return encoder.Encode(p) })
	default:
		return errNodeIdentityRecovery
	}
}
