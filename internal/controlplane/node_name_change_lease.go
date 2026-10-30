package controlplane

import (
	"context"
	"webscan/internal/deploy"
)

func (s *Store) checkNodeNameChangeLease(ctx context.Context, v *Vault, l Lease, id string) (nodeNameChangeJob, error) {
	var empty nodeNameChangeJob
	j, err := s.nodeNameChange(ctx, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) || j.Status == "completed" {
		return empty, errNodeNameChange
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return empty, err
	}
	if err := nameChangeActorTx(ctx, tx, j); err != nil {
		return empty, err
	}
	j, err = checkNodeNameChangeTx(ctx, tx, v, j)
	if err != nil {
		return empty, err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return j, nil
}

// Read-only root SSH authentication with an immutable, verified host pin. The
// host runner must still use fixed commands and recheck this task/fence before
// every remote phase. This never trusts a first-use key or changes known_hosts.
func (s *Store) connectNodeNameChangeSSH(ctx context.Context, v *Vault, l Lease, id string) (*deploy.Remote, error) {
	j, err := s.checkNodeNameChangeLease(ctx, v, l, id)
	if err != nil {
		return nil, err
	}
	c, err := s.ReadCredential(ctx, v, j.Credential, j.Node)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, j.ExpiresAt)
	defer cancel()
	remote, err := connectCredentialSSH(ctx, c)
	if err != nil {
		return nil, err
	}
	if _, err := s.checkNodeNameChangeLease(ctx, v, l, id); err != nil {
		remote.Close()
		return nil, err
	}
	return remote, nil
}
