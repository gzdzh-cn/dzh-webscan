package controlplane

import (
	"context"
	"time"
)

type collectionTarget struct {
	node    string
	version int64
}

// One batched lookup per collector reconciliation, never one query per node.
// Only leased shards and a live task already waiting at verify/finalize qualify.
// The query schedules read-only collection; it cannot install or ACK data.
func (s *Store) deploymentCollectionTargets(ctx context.Context, leases map[int]Lease) ([]collectionTarget, error) {
	shards := make([]int, 0, len(leases))
	for shard := range leases {
		shards = append(shards, shard)
	}
	targets := []collectionTarget{}
	if len(shards) == 0 {
		return targets, nil
	}
	after := ""
	for {
		rows, err := s.DB.QueryContext(ctx, `SELECT j.node,j.node_version FROM v3_deployment_jobs j JOIN v3_active_nodes n ON n.id=j.node JOIN v3_nodes saved ON saved.id=j.node
WHERE j.status='running' AND j.direction='forward' AND j.step IN (4,5) AND j.lease_until>clock_timestamp()
AND saved.enabled AND saved.version=j.node_version AND n.enabled AND n.version=j.node_version AND n.shard=ANY($1::integer[]) AND j.node>$2 ORDER BY j.node LIMIT 200`, shards, after)
		if err != nil {
			return nil, err
		}
		page := []collectionTarget{}
		for rows.Next() {
			var target collectionTarget
			if err = rows.Scan(&target.node, &target.version); err != nil {
				break
			}
			page = append(page, target)
		}
		rowErr := rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if rowErr != nil {
			return nil, rowErr
		}
		targets = append(targets, page...)
		if len(page) < 200 {
			return targets, nil
		}
		after = page[len(page)-1].node
	}
}

func wakeCollectionTargets(running map[string]nodeRun, wanted map[string]Node, leases map[int]Lease, targets []collectionTarget) {
	for _, target := range targets {
		n, wanted := wanted[target.node]
		r, active := running[target.node]
		l, leased := leases[n.Shard]
		if !wanted || !n.Enabled || !active || !leased || l.Resource != shardResource(n.Shard) || target.version != n.Version || r.version != n.Version || r.epoch != l.Epoch || r.runtimeEpoch != n.RuntimeEpoch {
			continue
		}
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
}

// A wake bypasses both startup jitter and the normal interval. Collection is
// serial and uses the same global slots as ordinary samples. One buffered wake
// coalesces concurrent requests; the next normal interval starts after work,
// rather than consuming an accumulated ticker immediately after a slow request.
func collectionSchedule(ctx context.Context, initial, interval time.Duration, wake <-chan struct{}, collect func()) {
	timer := time.NewTimer(initial)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-wake:
			if !ok {
				wake = nil
				continue
			}
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		if ctx.Err() != nil {
			return
		}
		collect()
		timer.Reset(interval)
	}
}
