package controlplane

import (
	"context"
	"webscan/internal/deploy"
)

func (s *Store) checkNodeNamePruningLease(ctx context.Context, c Config, v *Vault, l Lease, id string) (nodeNamePruningJob, error) {
	var empty nodeNamePruningJob
	j, err := s.nodeNamePruning(ctx, c, v, id)
	if err != nil || l.Resource != nodeRenewalResource(j.Node) || j.Status == "completed" {
		return empty, errNodeNamePruning
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return empty, err
	}
	if err := pruningActorTx(ctx, tx, j); err != nil {
		return empty, err
	}
	j, err = checkNodeNamePruningTx(ctx, tx, c, v, j)
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
func (s *Store) connectNodeNamePruningSSH(ctx context.Context, c Config, v *Vault, l Lease, id string) (*deploy.Remote, error) {
	j, err := s.checkNodeNamePruningLease(ctx, c, v, l, id)
	if err != nil {
		return nil, err
	}
	credential, err := s.ReadCredential(ctx, v, j.Credential, j.Node)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, j.ExpiresAt)
	defer cancel()
	remote, err := connectCredentialSSH(ctx, credential)
	if err != nil {
		return nil, err
	}
	if _, err := s.checkNodeNamePruningLease(ctx, c, v, l, id); err != nil {
		remote.Close()
		return nil, err
	}
	return remote, nil
}
