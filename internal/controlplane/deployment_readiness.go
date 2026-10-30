package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"google.golang.org/grpc"
	agentv1 "webscan/sdk/agent/v1"
)

var ErrDeploymentNotReady = errors.New("等待实际采集器确认目标版本、配置、目录覆盖、扫描能力、指标和事件链路")

// Network evidence is produced by the actual fenced collector, never by an SSH
// command or the API/executor's network. It is ephemeral even though persisted:
// restored backups, expired leases and old successes cannot complete a new job.
const deploymentReadinessSchema = `
CREATE TABLE v3_node_readiness(
 node text NOT NULL REFERENCES v3_nodes(id),kind text NOT NULL CHECK(kind IN ('metrics','events')),
 node_version bigint NOT NULL,config_digest text NOT NULL,endpoint text NOT NULL,server_name text NOT NULL,
 resource text NOT NULL,owner text NOT NULL,epoch bigint NOT NULL,
 release text NOT NULL,reported_version bigint NOT NULL,reported_digest text NOT NULL,
 sampled_at bigint NOT NULL,checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(node,kind)
);
INSERT INTO v3_schema(version) VALUES(4);
`

type capabilityReader interface {
	Capabilities(context.Context, *agentv1.CapabilitiesRequest, ...grpc.CallOption) (*agentv1.CapabilitiesResponse, error)
}

func (c *Collector) observeRuntime(ctx context.Context, n Node, l Lease, client capabilityReader) error {
	if c.trust == nil {
		return ErrDeploymentNotReady
	}
	cap, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
	if err != nil || !validCapabilities(n, cap) {
		return ErrDeploymentNotReady
	}
	sampled, _, err := c.Store.MetricCursor(ctx, n.ID)
	if err != nil {
		return err
	}
	err = c.Store.recordNodeReadiness(ctx, n, l, "metrics", cap, sampled)
	if errors.Is(err, ErrDeploymentNotReady) {
		// An older compatible Agent remains collectable. Its missing version
		// acknowledgement can never certify a new v3 deployment, though.
		tx, e := c.Store.DB.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if e = c.Store.FenceNode(ctx, tx, n, l); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM v3_node_readiness WHERE node=$1 AND kind='metrics'", n.ID); e != nil {
			return e
		}
		return tx.Commit()
	}
	return err
}

func (s *Store) recordNodeReadiness(ctx context.Context, n Node, l Lease, kind string, cap *agentv1.CapabilitiesResponse, sampled int64) error {
	if kind != "metrics" && kind != "events" || kind == "metrics" && (!validCapabilities(n, cap) || len(cap.Version) > 128 || !releaseVersion.MatchString(cap.Version) || cap.ConfigurationVersion < 1 || !releaseDigest(cap.ConfigurationSha256) || sampled < 1) {
		return ErrDeploymentNotReady
	}
	version, reported, release := int64(0), "", ""
	if kind == "metrics" {
		version, reported, release = cap.ConfigurationVersion, cap.ConfigurationSha256, cap.Version
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.FenceNode(ctx, tx, n, l); err != nil {
		return err
	}
	if kind == "metrics" {
		if err := s.deploymentHealth(ctx, tx, n, sampled, time.Time{}); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_node_readiness(node,kind,node_version,config_digest,endpoint,server_name,resource,owner,epoch,release,reported_version,reported_digest,sampled_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT(node,kind) DO UPDATE SET node_version=excluded.node_version,config_digest=excluded.config_digest,endpoint=excluded.endpoint,server_name=excluded.server_name,
resource=excluded.resource,owner=excluded.owner,epoch=excluded.epoch,release=excluded.release,reported_version=excluded.reported_version,reported_digest=excluded.reported_digest,sampled_at=excluded.sampled_at,checked_at=clock_timestamp()`,
		n.ID, kind, n.Version, digest(n.Config), n.Endpoint, n.ServerName, l.Resource, l.Owner, l.Epoch, release, version, reported, sampled)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Called in the same transaction that advances verify/finalize/applied_version.
// Lock the evidence and current collector lease so a concurrent failure or
// takeover is ordered against this decision. Node/config checks share the lock.
func (s *Store) deploymentReady(ctx context.Context, tx *sql.Tx, j DeploymentJob) error {
	// Match FenceNode's lease -> node -> evidence ordering. Taking the node
	// first can deadlock a collector already holding its lease, particularly
	// when a lease renewal/takeover is also waiting for an exclusive lock.
	var epoch int64
	err := tx.QueryRowContext(ctx, "SELECT epoch FROM v3_leases WHERE resource=$1 AND expires_at>clock_timestamp() FOR SHARE", shardResource(j.Plan.Node.Shard)).Scan(&epoch)
	if err == sql.ErrNoRows {
		return ErrDeploymentNotReady
	}
	if err != nil {
		return err
	}
	n, err := scanNode(tx.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE id=$1 FOR UPDATE", j.Node))
	if err != nil {
		return err
	}
	if !n.Enabled || n.Version != j.NodeVersion || digest(n.Config) != j.Plan.ConfigDigest || n.Endpoint != j.Plan.Node.Endpoint || n.ServerName != j.Plan.Node.ServerName || n.Mode != j.Plan.Node.Mode {
		return ErrConflict
	}
	var activated time.Time
	if err := tx.QueryRowContext(ctx, "SELECT created_at FROM v3_deployment_logs WHERE job=$1 AND phase='activate' AND code='phase-complete' ORDER BY cursor DESC LIMIT 1", j.ID).Scan(&activated); err == sql.ErrNoRows {
		return ErrDeploymentNotReady
	} else if err != nil {
		return err
	}
	if err := s.deploymentHealth(ctx, tx, n, 0, activated); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.kind FROM v3_node_readiness r JOIN v3_leases l ON l.resource=r.resource AND l.owner=r.owner AND l.epoch=r.epoch
WHERE r.node=$1 AND r.node_version=$2 AND r.config_digest=$3 AND r.endpoint=$4 AND r.server_name=$5 AND r.resource=$6
AND l.expires_at>clock_timestamp() AND r.checked_at>clock_timestamp()-interval '60 seconds'
AND r.checked_at>= (SELECT created_at FROM v3_deployment_logs WHERE job=$7 AND phase='activate' AND code='phase-complete' ORDER BY cursor DESC LIMIT 1)
AND (r.kind='events' OR (r.sampled_at=(SELECT sampled_at FROM v3_node_status WHERE node=$1) AND r.release=$8 AND r.reported_version=$2 AND r.reported_digest=$3
 AND r.sampled_at>=extract(epoch FROM clock_timestamp()-interval '60 seconds')*1000
 AND r.sampled_at<=extract(epoch FROM clock_timestamp()+interval '5 seconds')*1000
 AND r.sampled_at>=extract(epoch FROM (SELECT created_at FROM v3_deployment_logs WHERE job=$7 AND phase='activate' AND code='phase-complete' ORDER BY cursor DESC LIMIT 1)-interval '5 seconds')*1000))
ORDER BY r.kind FOR SHARE OF r,l`, n.ID, j.NodeVersion, j.Plan.ConfigDigest, n.Endpoint, n.ServerName, shardResource(n.Shard), j.ID, j.Plan.Request.Release)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			return err
		}
		seen[kind] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !seen["metrics"] || !seen["events"] {
		return ErrDeploymentNotReady
	}
	return nil
}

func (w *DeploymentRunner) completePhase(ctx context.Context, j DeploymentJob) error {
	return w.completePhaseWithEvidence(ctx, j, RemoteDeploymentCheckpoint{})
}

func (w *DeploymentRunner) completePhaseWithEvidence(ctx context.Context, j DeploymentJob, proof RemoteDeploymentCheckpoint) error {
	wait, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for {
		op, stop := context.WithTimeout(wait, 5*time.Second)
		err := w.Store.completeDeploymentPhase(op, j, w.Vault, &proof)
		stop()
		if wait.Err() != nil && ctx.Err() == nil {
			return DeploymentFailure{"verification-failed"}
		}
		if !errors.Is(err, ErrDeploymentNotReady) {
			return err
		}
		if !waitRetry(wait, 2*time.Second) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return DeploymentFailure{"verification-failed"}
		}
	}
}
