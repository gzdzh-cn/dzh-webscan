package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/common"
	"webscan/internal/nodepki"
	"webscan/internal/telemetry"
	agentv1 "webscan/sdk/agent/v1"
)

type Collector struct {
	Store    *Store
	Config   Config
	Metrics  *Metrics
	TLS      *tls.Config
	slots    chan struct{}
	trust    *nodepki.FileTrust
	identity *nodepki.LiveIdentity
}
type nodeRun struct {
	version, epoch, runtimeEpoch int64
	cancel                       context.CancelFunc
	done                         chan struct{}
	wake                         chan struct{}
	identitySHA                  string
}

func (c *Collector) Run(ctx context.Context) error {
	if c.Store == nil || c.Config.Collector.Concurrency < 1 || c.Config.Collector.Concurrency > 2048 || c.Config.Collector.Shards < 1 || c.Config.Collector.Shards > 4096 || c.Config.Collector.IntervalSeconds < 10 || c.Config.Collector.IntervalSeconds > 3600 {
		return errors.New("采集器数据库、并发、分片或采集间隔配置不正确")
	}
	var e error
	if c.Config.Collector.RevocationFile != "" {
		if c.Config.Collector.RevocationStateDirectory != "" {
			c.trust, e = nodepki.NewPersistentFileTrust(c.Config.Collector.CAFile, c.Config.Collector.RevocationFile, c.Config.Collector.RevocationStateDirectory, time.Now())
		} else {
			c.trust, e = nodepki.NewFileTrust(c.Config.Collector.CAFile, c.Config.Collector.RevocationFile, time.Now())
		}
		if e != nil {
			return e
		}
	}
	if c.TLS == nil || c.Config.Collector.IdentityFile != "" {
		c.TLS, c.identity, e = collectorTLSIdentity(c.Config)
		if e != nil {
			return e
		}
	}
	if c.Metrics == nil {
		c.Metrics = &Metrics{WriteURL: c.Config.Metrics.WriteURL, QueryURL: c.Config.Metrics.QueryURL, HTTP: &http.Client{Timeout: 15 * time.Second}}
	}
	c.slots = make(chan struct{}, c.Config.Collector.Concurrency)
	running := map[string]nodeRun{}
	leases := map[int]Lease{}
	defer func() {
		for _, r := range running {
			r.cancel()
		}
		for _, r := range running {
			<-r.done
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, l := range leases {
			_ = c.Store.Release(cleanup, l)
		}
		_, _ = c.Store.DB.ExecContext(cleanup, "DELETE FROM v3_workers WHERE instance=$1", c.Config.Central.Instance)
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		cycle, cancel := context.WithTimeout(ctx, 8*time.Second)
		wanted, newLeases, e := c.reconcile(cycle, leases)
		var targets []collectionTarget
		if e == nil {
			// This optional acceleration must not cancel healthy collection when
			// its lookup times out. Lease renewal errors still cancel every run.
			// Missing wakes are retried at the next reconciliation; the executor
			// independently requires fresh evidence and cannot assume readiness.
			targets, _ = c.Store.deploymentCollectionTargets(cycle, newLeases)
		}
		cancel()
		identitySHA := ""
		if e == nil && c.identity != nil {
			leases = newLeases
			var record nodepki.IdentityRecord
			record, e = c.identity.Record(time.Now())
			identitySHA = record.CertificateSHA256
		}
		if e != nil {
			// Cancel immediately on a failed renewal; an isolated collector must
			// not continue using a lease that another process may take over.
			for id, r := range running {
				r.cancel()
				<-r.done
				delete(running, id)
			}
		} else {
			runtimeReady(ctx, "collector")
			leases = newLeases
			for id, r := range running {
				n, ok := wanted[id]
				l := leases[n.Shard]
				finished := false
				select {
				case <-r.done:
					finished = true
				default:
				}
				if finished || r.identitySHA != identitySHA || !ok || r.version != n.Version || r.epoch != l.Epoch || r.runtimeEpoch != n.RuntimeEpoch {
					r.cancel()
					<-r.done
					delete(running, id)
				}
			}
			for id, n := range wanted {
				if _, ok := running[id]; ok {
					continue
				}
				l := leases[n.Shard]
				nodeCtx, stop := context.WithCancel(ctx)
				done := make(chan struct{})
				wake := make(chan struct{}, 1)
				running[id] = nodeRun{version: n.Version, epoch: l.Epoch, runtimeEpoch: n.RuntimeEpoch, cancel: stop, done: done, wake: wake, identitySHA: identitySHA}
				go func(n Node, l Lease) { defer close(done); c.node(nodeCtx, n, l, wake) }(n, l)
			}
			wakeCollectionTargets(running, wanted, leases, targets)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (c *Collector) reconcile(ctx context.Context, previous map[int]Lease) (map[string]Node, map[int]Lease, error) {
	if _, e := c.Store.DB.ExecContext(ctx, "INSERT INTO v3_workers VALUES($1,clock_timestamp()) ON CONFLICT(instance) DO UPDATE SET last_seen=excluded.last_seen", c.Config.Central.Instance); e != nil {
		return nil, nil, e
	}
	rows, e := c.Store.DB.QueryContext(ctx, "SELECT instance FROM v3_workers WHERE last_seen>clock_timestamp()-interval '30 seconds' ORDER BY instance")
	if e != nil {
		return nil, nil, e
	}
	members := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			break
		}
		members = append(members, id)
	}
	re := rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, e
	}
	if re != nil {
		return nil, nil, re
	}
	wanted := map[string]Node{}
	leases := map[int]Lease{}
	resources := []string{}
	shards := []int{}
	for shard := 0; shard < c.Config.Collector.Shards; shard++ {
		if !assigned(shard, members, c.Config.Central.Instance) {
			if l, ok := previous[shard]; ok {
				if e = c.Store.Release(ctx, l); e != nil {
					return nil, nil, e
				}
			}
			continue
		}
		resources = append(resources, shardResource(shard))
	}
	acquired, e := c.Store.AcquireMany(ctx, resources, c.Config.Central.Instance)
	if e != nil {
		return nil, nil, e
	}
	for shard := 0; shard < c.Config.Collector.Shards; shard++ {
		if l, ok := acquired[shardResource(shard)]; ok {
			leases[shard] = l
			shards = append(shards, shard)
		}
	}
	after := ""
	for len(shards) > 0 {
		nodes, err := c.Store.nodesForShards(ctx, after, shards, 200)
		if err != nil {
			return nil, nil, err
		}
		for _, n := range nodes {
			wanted[n.ID] = n
		}
		if len(nodes) < 200 {
			break
		}
		after = nodes[len(nodes)-1].ID
	}
	return wanted, leases, nil
}
func (c *Collector) node(ctx context.Context, n Node, l Lease, wake <-chan struct{}) {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	tlsConfig := c.TLS.Clone()
	tlsConfig.ServerName = n.ServerName
	options := []grpc.DialOption{grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(2<<20), grpc.MaxCallSendMsgSize(2<<20))}
	if c.trust != nil {
		policy := &nodeCertificatePolicy{trust: c.trust, node: n.ID, onInvalid: stop}
		policy.wrapTLS(tlsConfig)
		options = append(options, grpc.WithUnaryInterceptor(policy.invoke), grpc.WithPerRPCCredentials(policy))
	}
	options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	conn, e := grpc.NewClient(n.Endpoint, options...)
	if e != nil {
		return
	}
	defer conn.Close()
	client := agentv1.NewAgentServiceClient(conn)
	trustSync := nodeTrustSync{}
	// An authenticated endpoint must also identify itself as this node and
	// advertise the supported protocol before any data is persisted.
	delay := 2 * time.Second
	for {
		select {
		case c.slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		op, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := trustSync.sync(op, c.trust, n.ID, client)
		var capabilities *agentv1.CapabilitiesResponse
		if err == nil {
			capabilities, err = client.Capabilities(op, &agentv1.CapabilitiesRequest{})
		}
		trustSync.invalidate(err)
		cancel()
		<-c.slots
		if err == nil && validCapabilities(n, capabilities) {
			c.failure(ctx, n, l, "protocol", "")
			break
		}
		if ctx.Err() != nil {
			return
		}
		c.failure(ctx, n, l, "protocol", "节点身份、采集协议或吊销列表同步失败")
		if !waitRetry(ctx, min(60*time.Second, delay+time.Duration(rand.Int64N(int64(delay/5))))) {
			return
		}
		delay = min(delay*2, 60*time.Second)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); c.events(ctx, n, l, client) }()
	defer func() { stop(); wg.Wait() }()
	interval := time.Duration(c.Config.Collector.IntervalSeconds) * time.Second
	initial := time.Duration(rand.Int64N(int64(interval)))
	collectionSchedule(ctx, initial, interval, wake, func() {
		select {
		case c.slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		op, cancel := context.WithTimeout(ctx, 20*time.Second)
		if err := trustSync.sync(op, c.trust, n.ID, client); err != nil {
			cancel()
			<-c.slots
			trustSync.failed = true
			c.failure(ctx, n, l, "protocol", "节点吊销列表下发或确认失败")
			return
		}
		if trustSync.failed {
			c.failure(ctx, n, l, "protocol", "")
			trustSync.failed = false
		}
		e = c.collect(op, n, l, client)
		trustSync.invalidate(e)
		if e == nil && c.trust != nil {
			e = c.observeRuntime(op, n, l, client)
		}
		if e == nil && c.trust != nil {
			rotated, renewalErr := c.renewNodeIdentity(op, n, l, client)
			if renewalErr != nil {
				c.failure(ctx, n, l, "protocol", errNodeRenewal.Error())
			} else {
				c.failure(ctx, n, l, "protocol", "")
			}
			if rotated {
				stop()
			}
		}
		cancel()
		<-c.slots
		if e != nil && ctx.Err() == nil {
			c.failure(ctx, n, l, "metrics", "指标采集或持久化失败")
		}
	})
}
func (c *Collector) collect(ctx context.Context, n Node, l Lease, client agentv1.AgentServiceClient) error {
	after, baseline, e := c.Store.MetricCursor(ctx, n.ID)
	if e != nil {
		return e
	}
	b, e := client.ReadMetrics(ctx, &agentv1.ReadMetricsRequest{AfterUnixMillis: after})
	if e != nil {
		return e
	}
	if b == nil || b.NodeId != n.ID {
		return errors.New("节点身份不匹配")
	}
	if len(b.Samples) == 0 {
		if after == 0 || !healthFresh(after, time.Now().UnixMilli(), common.Map{"interval_seconds": c.Config.Collector.IntervalSeconds}) {
			return errors.New("节点未返回有效的新指标样本")
		}
		return nil
	}
	if b.Samples[0].UnixMillis <= after {
		return errors.New("节点返回过期指标游标")
	}
	prepared, e := derivedSamples(b.Samples, baseline)
	if e != nil {
		return e
	}
	if e = c.Metrics.Write(ctx, n.ID, prepared); e != nil {
		return e
	}
	return c.Store.commitMetrics(ctx, n, l, b, baseline, c.Config.Collector.IntervalSeconds)
}
func (c *Collector) events(ctx context.Context, n Node, l Lease, client agentv1.AgentServiceClient) {
	delay := 2 * time.Second
	hadFailure := true
	for ctx.Err() == nil {
		started := time.Now()
		op, cancel := context.WithTimeout(ctx, 30*time.Second)
		b, e := client.FetchEvents(op, &agentv1.FetchEventsRequest{Epoch: uint64(l.Epoch), Limit: 100, WaitSeconds: 25})
		cancel()
		if e == nil && (b == nil || b.NodeId != n.ID) {
			e = errors.New("节点事件身份不匹配")
		}
		if e == nil && len(b.Events) > 0 {
			var accepted []string
			var rejected []*agentv1.Rejection
			op, cancel = context.WithTimeout(ctx, 20*time.Second)
			accepted, rejected, e = c.Store.Ingest(op, n, l, b)
			cancel()
			if e == nil {
				op, cancel = context.WithTimeout(ctx, 10*time.Second)
				_, e = client.AckEvents(op, &agentv1.AckEventsRequest{Epoch: uint64(l.Epoch), Receipt: b.Receipt, Accepted: accepted, Rejected: rejected})
				cancel()
			}
		}
		if e == nil && c.trust != nil {
			op, cancel = context.WithTimeout(ctx, 3*time.Second)
			e = c.Store.recordNodeReadiness(op, n, l, "events", nil, 0)
			cancel()
		}
		if e == nil {
			if hadFailure {
				c.failure(ctx, n, l, "events", "")
				hadFailure = false
			}
			delay = 2 * time.Second
			// A broken/old endpoint that answers an empty long poll immediately
			// must not create an unbounded RPC loop.
			if len(b.Events) == 0 && !waitRetry(ctx, max(time.Duration(0), time.Second-time.Since(started))) {
				return
			}
			continue
		}
		if errors.Is(e, ErrLeaseLost) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		c.failure(ctx, n, l, "events", "事件读取或持久化失败")
		hadFailure = true
		t := time.NewTimer(delay + time.Duration(rand.Int64N(int64(delay/5))))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		delay = min(delay*2, 60*time.Second)
	}
}
func (c *Collector) failure(ctx context.Context, n Node, l Lease, kind, reason string) {
	if kind != "metrics" && kind != "events" && kind != "protocol" {
		return
	}
	op, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, e := c.Store.DB.BeginTx(op, nil)
	if e != nil {
		return
	}
	defer tx.Rollback()
	if c.Store.FenceNode(op, tx, n, l) != nil {
		return
	}
	_, e = tx.ExecContext(op, `INSERT INTO v3_node_status(node,error,metrics_error,events_error,protocol_error)
	VALUES($1,$3,CASE WHEN $2='metrics' THEN $3 ELSE '' END,CASE WHEN $2='events' THEN $3 ELSE '' END,CASE WHEN $2='protocol' THEN $3 ELSE '' END)
	ON CONFLICT(node) DO UPDATE SET
	metrics_error=CASE WHEN $2='metrics' THEN $3 ELSE v3_node_status.metrics_error END,
	events_error=CASE WHEN $2='events' THEN $3 ELSE v3_node_status.events_error END,
	protocol_error=CASE WHEN $2='protocol' THEN $3 ELSE v3_node_status.protocol_error END,
	error=concat_ws('；',nullif(CASE WHEN $2='metrics' THEN $3 ELSE v3_node_status.metrics_error END,''),nullif(CASE WHEN $2='events' THEN $3 ELSE v3_node_status.events_error END,''),nullif(CASE WHEN $2='protocol' THEN $3 ELSE v3_node_status.protocol_error END,'')),updated_at=clock_timestamp()`, n.ID, kind, reason)
	if e == nil && reason != "" {
		_, e = tx.ExecContext(op, "DELETE FROM v3_node_readiness WHERE node=$1 AND ($2='protocol' OR kind=$2)", n.ID, kind)
	}
	if e == nil && reason != "" && (kind == "metrics" || kind == "protocol") {
		var config common.Map
		var version int64
		config, version, e = healthSettings(op, tx)
		if e == nil {
			if interval := c.Config.Collector.IntervalSeconds; interval >= 10 && interval <= 3600 {
				config["interval_seconds"] = interval
			}
			var observed int64
			e = tx.QueryRowContext(op, "SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint").Scan(&observed)
			if e == nil {
				e = c.Store.evaluateHealth(op, tx, n, telemetry.Snapshot{OK: false}, observed, config, version)
			}
		}
	}
	if e == nil {
		_ = tx.Commit()
	}
}

func validCapabilities(n Node, c *agentv1.CapabilitiesResponse) bool {
	return c != nil && c.NodeId == n.ID && c.Protocol == agentv1.ProtocolVersion && c.MaxEvents == agentv1.MaxEvents && c.MaxBytes == agentv1.MaxBytes
}

func waitRetry(ctx context.Context, delay time.Duration) bool {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (s *Store) Summary(ctx context.Context) (json.RawMessage, error) {
	return s.summaryWithFreshness(ctx, 90)
}

func (s *Store) summaryWithFreshness(ctx context.Context, freshness int) (json.RawMessage, error) {
	var raw []byte
	e := s.DB.QueryRowContext(ctx, `SELECT jsonb_build_object('servers',count(*),'enabled',count(*) FILTER(WHERE COALESCE(a.enabled,n.enabled)),'fresh',count(*) FILTER(WHERE COALESCE(a.enabled,n.enabled) AND COALESCE(s.error,'')='' AND s.sampled_at>extract(epoch from clock_timestamp()-$1*interval '1 second')*1000 AND s.sampled_at<=extract(epoch from clock_timestamp()+interval '5 seconds')*1000),'abnormal',count(*) FILTER(WHERE COALESCE(a.enabled,n.enabled) AND (COALESCE(s.error,'')<>'' OR s.sampled_at<=extract(epoch from clock_timestamp()-$1*interval '1 second')*1000 OR s.sampled_at>extract(epoch from clock_timestamp()+interval '5 seconds')*1000)),'unknown',count(*) FILTER(WHERE COALESCE(a.enabled,n.enabled) AND s.sampled_at IS NULL AND COALESCE(s.error,'')=''),'current_alerts',(SELECT count(*) FROM v3_health_rules r JOIN v3_active_nodes a ON a.id=r.node WHERE a.enabled AND r.phase='firing'),'pending_alerts',(SELECT count(*) FROM v3_health_rules r JOIN v3_active_nodes a ON a.id=r.node WHERE a.enabled AND r.phase='pending'),'updated_at',clock_timestamp()) FROM v3_nodes n LEFT JOIN v3_active_nodes a ON a.id=n.id LEFT JOIN v3_node_status s ON s.node=a.id`, freshness).Scan(&raw)
	return raw, e
}
