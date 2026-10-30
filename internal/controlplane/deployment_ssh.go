package controlplane

import (
	"context"
	"webscan/internal/common"
	"webscan/internal/deploy"
)

// ConnectDeploymentSSH is restricted to an active, fenced job and the immutable
// encrypted credential selected in its plan. Existing SSH code supplies root
// authentication, modern host-key negotiation and context cancellation. The
// mandatory pin avoids first-use trust or changes to v2 known-host records.
func (s *Store) ConnectDeploymentSSH(ctx context.Context, v *Vault, j DeploymentJob) (*deploy.Remote, error) {
	if err := s.checkDeploymentPlan(ctx, j); err != nil {
		return nil, err
	}
	c, err := s.ReadCredential(ctx, v, j.Plan.Request.Credential, j.Node)
	if err != nil {
		return nil, err
	}
	return connectCredentialSSH(ctx, c)
}

func connectCredentialSSH(ctx context.Context, c SSHCredential) (*deploy.Remote, error) {
	if c.validate() != nil {
		return nil, ErrCredentialUnavailable
	}
	auth := "password"
	if c.PrivateKey != "" {
		auth = "key"
	}
	n := common.Map{"host": c.Host, "ssh": common.Map{"port": c.Port, "auth_method": auth, "password": c.Password, "host_key_sha256": c.Fingerprint, "connect_timeout_seconds": 10}}
	remote, err := deploy.CheckConnection(ctx, n, "", c.PrivateKey)
	if err != nil {
		return nil, DeploymentFailure{"remote-unavailable"}
	}
	// A successful authentication alone is not a deployment checkpoint. Remote
	// operation locks and phase receipts are still required by DeploymentRuntime.
	return remote, nil
}
