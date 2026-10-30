package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"sort"
)

// AcquireMany renews assigned shards in one round trip. SQL orders conflicting
// rows consistently so concurrent collectors do not take locks in reverse order.
func (s *Store) AcquireMany(ctx context.Context, resources []string, owner string) (map[string]Lease, error) {
	result := make(map[string]Lease, len(resources))
	if len(resources) == 0 {
		return result, nil
	}
	resources = append([]string(nil), resources...)
	sort.Strings(resources)
	for i, r := range resources {
		if r == "" || i > 0 && resources[i-1] == r {
			return nil, errors.New("租约资源为空或重复")
		}
	}
	rows, err := s.DB.QueryContext(ctx, `INSERT INTO v3_leases(resource,owner,epoch,expires_at)
	SELECT r,$2,1,clock_timestamp()+interval '30 seconds' FROM unnest($1::text[]) r ORDER BY r
	ON CONFLICT(resource) DO UPDATE SET owner=EXCLUDED.owner,
	epoch=CASE WHEN v3_leases.owner=EXCLUDED.owner AND v3_leases.expires_at>clock_timestamp() THEN v3_leases.epoch ELSE v3_leases.epoch+1 END,
	expires_at=clock_timestamp()+interval '30 seconds'
	WHERE v3_leases.owner=EXCLUDED.owner OR v3_leases.expires_at<=clock_timestamp()
	RETURNING resource,owner,epoch,expires_at`, resources, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var l Lease
		if err = rows.Scan(&l.Resource, &l.Owner, &l.Epoch, &l.Expires); err != nil {
			return nil, err
		}
		result[l.Resource] = l
	}
	return result, rows.Err()
}

func (s *Store) nodesForShards(ctx context.Context, after string, shards []int, limit int) ([]Node, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+activeNodeColumns+" FROM v3_active_nodes WHERE enabled AND id>$1 AND shard=ANY($2::integer[]) ORDER BY id LIMIT $3", after, shards, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := []Node{}
	for rows.Next() {
		n, err := scanActiveNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

// FenceNode rejects a task from the wrong shard and a previously enabled or
// edited node. A lease alone is not sufficient authorization to write any node.
func (s *Store) FenceNode(ctx context.Context, tx *sql.Tx, n Node, l Lease) error {
	if l.Resource != shardResource(n.Shard) {
		return ErrLeaseLost
	}
	if err := s.Fence(ctx, tx, l); err != nil {
		return err
	}
	var version int64
	// Lock the desired identity before the runtime row. Publishers follow this
	// same ordering; a join's planner-dependent row order cannot invert it.
	if err := tx.QueryRowContext(ctx, `SELECT version FROM v3_nodes WHERE id=$1 FOR SHARE`, n.ID).Scan(&version); err == sql.ErrNoRows {
		return ErrLeaseLost
	} else if err != nil {
		return err
	}
	err := tx.QueryRowContext(ctx, "SELECT version FROM v3_active_nodes WHERE id=$1 AND enabled AND shard=$2 AND version=$3 AND runtime_epoch=$4 FOR SHARE", n.ID, n.Shard, n.Version, n.RuntimeEpoch).Scan(&version)
	if err == sql.ErrNoRows {
		return ErrLeaseLost
	}
	return err
}
