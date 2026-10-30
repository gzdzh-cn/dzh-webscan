package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"webscan/internal/nodepki"
)

type nodeRenewalSigningResult struct {
	State   string `json:"state,omitempty"`
	Error   string `json:"error,omitempty"`
	Signed  int    `json:"signed"`
	Skipped int    `json:"skipped"`
	Failed  int    `json:"failed"`
}

// Host-only bounded work. No RPC handler invokes this method and collectors do
// not need CA-key/Vault access. Dedicated per-node leases serialize issuer
// failover; the public ledger remains the final issuance idempotency boundary.
func (s *Store) processNodeRenewalQueue(ctx context.Context, c Config, owner string, limit int) (nodeRenewalSigningResult, error) {
	var result nodeRenewalSigningResult
	if !c.NodePKI.Enabled || c.NodePKI.validate() != nil || !identifier.MatchString(owner) {
		return result, errNodeIdentity
	}
	jobs, err := s.pendingNodeRenewals(ctx, limit)
	if err != nil {
		return result, err
	}
	for _, j := range jobs {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		l, err := s.Acquire(ctx, nodeRenewalResource(j.Node), owner)
		if errors.Is(err, ErrLeaseLost) {
			result.Skipped++
			continue
		}
		if err != nil {
			return result, err
		}
		// A failed candidate receives a persisted backoff so a bad node cannot
		// repeatedly occupy the front of the bounded batch after restarts.
		r, parseErr := nodepki.ParseNodeRenewalRequest(j.Request)
		if parseErr == nil && (r.Node != j.Node || r.CertificateSHA256 != j.ParentSHA256 || r.SHA256() != j.RequestSHA256) {
			parseErr = errNodeIdentity
		}
		if parseErr == nil {
			_, err = s.signNodeRenewal(ctx, c, l, nodeRenewalSigningInput{Snapshot: j.Snapshot, RuntimeEpoch: j.RuntimeEpoch, LifetimeHours: j.LifetimeHours, Request: r})
		} else {
			err = parseErr
		}
		var persistenceErr error
		if err == nil {
			result.Signed++
		} else {
			result.Failed++
			// Do not persist underlying SQL, filesystem or certificate errors.
			if updateErr := s.deferNodeRenewal(ctx, l, j); updateErr != nil && !errors.Is(updateErr, ErrConflict) && !errors.Is(updateErr, ErrLeaseLost) {
				persistenceErr = updateErr
			}
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		releaseErr := s.Release(cleanup, l)
		cancel()
		if releaseErr != nil {
			return result, releaseErr
		}
		if persistenceErr != nil {
			return result, persistenceErr
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
	}
	return result, nil
}

func (s *Store) deferNodeRenewal(ctx context.Context, l Lease, j nodeRenewalJob) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if l.Resource != nodeRenewalResource(j.Node) {
		return ErrLeaseLost
	}
	// Keep the same node -> dedicated lease order as signing. Deployment may
	// have advanced runtime meanwhile; never write into a rebound request.
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM v3_nodes WHERE id=$1 FOR UPDATE`, j.Node).Scan(&id); err != nil {
		return err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return err
	}
	row := tx.QueryRowContext(ctx, `UPDATE v3_node_renewal_jobs SET attempts=LEAST(attempts,1000000)+1,
 last_error='续期签发暂未完成，请检查节点身份、运行配置、吊销列表及宿主签发服务',
 next_attempt_at=clock_timestamp()+LEAST(3600,60*power(2,LEAST(attempts,6))) * interval '1 second',updated_at=clock_timestamp()
 WHERE node=$1 AND parent_sha256=$2 AND request_sha256=$3 AND snapshot=$4 AND runtime_epoch=$5 AND activated_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM v3_node_certificate_renewals x WHERE x.node=$1 AND x.parent_sha256=$2)
 RETURNING node`, j.Node, j.ParentSHA256, j.RequestSHA256, j.Snapshot, j.RuntimeEpoch)
	if err := row.Scan(&id); err == sql.ErrNoRows {
		return ErrConflict
	} else if err != nil {
		return err
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return err
	}
	return tx.Commit()
}
