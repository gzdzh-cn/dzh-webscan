package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/nodepki"
	"webscan/internal/persist"
	"webscan/internal/pull"
)

// Real Agent identity is issued by the original complete-backup authority.
// Unlike an independently minted mTLS fixture, this preserves the actual
// collector CA/identity, Vault and immutable host installation throughout.
func migrationRecoveryHostAgent(t *testing.T, p singleBackupPlan, store *Store) *pull.Source {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	anchor, e := readTrustData(filepath.Join(p.config.NodePKI.AuthorityDirectory, "ca.crt"), true, 64<<10)
	if e != nil {
		t.Fatal(e)
	}
	key, e := readTrustData(filepath.Join(p.config.NodePKI.AuthorityDirectory, "ca.key"), true, 64<<10)
	if e != nil {
		t.Fatal(e)
	}
	authority, e := nodepki.ParseAuthority(anchor, key, now)
	if e != nil {
		t.Fatal(e)
	}
	bundle, e := authority.Issue(nodepki.Node, "recovery-host-node", []string{"recovery-host-node"}, now, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	db, e := persist.OpenDB(filepath.Join(privateTestDir(t), "source.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Exec(`CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT,created REAL,accepted REAL)`); e != nil {
		t.Fatal(e)
	}
	n := nodeFixture("recovery-host-node")
	n.Enabled = false
	n.Config = json.RawMessage(`{"isolated":true}`)
	source, e := pull.New(db, n.ID, "isolated-full-host-recovery", new(sync.Mutex), pull.Configuration{Version: 1, SHA256: digest(n.Config)})
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(bundle.Certificate, bundle.Key)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(anchor)
	crl, e := readTrustData(p.config.Collector.RevocationFile, true, nodepki.MaxCRLBytes)
	if e != nil {
		t.Fatal(e)
	}
	trust, e := nodepki.NewTrust(anchor, crl, now)
	if e != nil {
		t.Fatal(e)
	}
	identity, e := nodepki.Identity(nodepki.Collector, p.spec.Instance)
	if e != nil {
		t.Fatal(e)
	}
	server := pull.NewServerWithRootTrust(source, []string{identity}, nil, nil, nil, func(cert *x509.Certificate) error {
		return trust.Verify(cert, nodepki.Collector, p.spec.Instance, time.Now())
	})
	t.Cleanup(server.Stop)
	https := httptest.NewUnstartedServer(server)
	https.EnableHTTP2 = true
	https.Config.ErrorLog = log.New(io.Discard, "", 0)
	https.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	https.StartTLS()
	t.Cleanup(https.Close)
	n.Endpoint, n.ServerName = https.Listener.Addr().String(), "recovery-host-node"
	if e = store.PutNode(ctx, n, 0, 256); e != nil {
		t.Fatal(e)
	}
	if e = store.DB.QueryRow(`SELECT config FROM v3_nodes WHERE id=$1`, n.ID).Scan(&n.Config); e != nil {
		t.Fatal(e)
	}
	fixed, e := pull.New(db, n.ID, "isolated-full-host-recovery", new(sync.Mutex), pull.Configuration{Version: 1, SHA256: digest(n.Config)})
	if e != nil {
		t.Fatal(e)
	}
	*source = *fixed
	if _, e = db.Exec(`UPDATE pull_state SET epoch=7`); e != nil {
		t.Fatal(e)
	}
	if e = source.RecordMetrics(ctx, time.Now(), []byte("node_memory_MemTotal_bytes 123456\nnode_memory_MemAvailable_bytes 123400\n")); e != nil {
		t.Fatal(e)
	}
	return source
}

func TestMigrationRecoveryHostActualActivationWithRetainedMTLSNodeAndDualVM(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_VM") == "" || os.Getenv("WEBSCAN_V3_TEST_RAW_VM") == "" {
		t.Skip("isolated actual dual VM required")
	}
	ctx := context.Background()
	source := testStore(t)
	p, _ := newSingleBackupFixtureOptions(t, "", 3, false, false, true)
	p = singleBackupUpgradeBindTestDatabase(t, source, p)
	if e := source.Provision(ctx, "recovery-admin", "isolated-host-node-123"); e != nil {
		t.Fatal(e)
	}
	agent := migrationRecoveryHostAgent(t, p, source)
	if _, e := source.DB.Exec(`INSERT INTO v3_leases(resource,owner,epoch,expires_at) VALUES($1,'original',4,clock_timestamp())`, shardResource(Shard("recovery-host-node", 256))); e != nil {
		t.Fatal(e)
	}
	p.output = p.spec.Root + "-node-archive"
	receipt, e := source.backupSingle(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	time.Sleep(20 * time.Millisecond)
	if e = agent.RecordMetrics(ctx, time.Now(), []byte("node_memory_MemTotal_bytes 123456\nnode_memory_MemAvailable_bytes 120000\n")); e != nil {
		t.Fatal(e)
	}
	for _, event := range []struct {
		id       string
		accepted bool
	}{{"host-accepted-after-backup", true}, {"host-pending-after-backup", false}} {
		var accepted any
		if event.accepted {
			accepted = float64(time.Now().UnixMilli()) / 1000
		}
		payload := common.JSON(common.Map{"node_id": "recovery-host-node", "event_id": event.id, "operation": "modify", "path": "/isolated/host-recovery"})
		if _, e = agent.DB.Exec(`INSERT INTO events(id,payload,created,accepted) VALUES(?,?,?,?)`, event.id, payload, float64(time.Now().UnixMilli())/1000, accepted); e != nil {
			t.Fatal(e)
		}
	}
	staged := p.spec.Root + "-node-staged"
	if e = restoreSingleBackupOffline(ctx, receipt.Directory, receipt.ManifestSHA256, staged); e != nil {
		t.Fatal(e)
	}
	manifest, e := verifySingleBackup(ctx, receipt.Directory, receipt.ManifestSHA256)
	if e != nil {
		t.Fatal(e)
	}
	target := emptyTestStore(t)
	if e = target.RestorePostgres(ctx, filepath.Join(staged, manifest.Postgres)); e != nil {
		t.Fatal(e)
	}
	var generation, schema string
	if e = target.DB.QueryRow(`SELECT generation FROM v3_migration_recovery_state WHERE id=1`).Scan(&generation); e != nil {
		t.Fatal(e)
	}
	if e = target.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); e != nil {
		t.Fatal(e)
	}
	c := p.config
	raw, e := readTrustData(c.Database.DSNFile, true, 64<<10)
	if e != nil {
		t.Fatal(e)
	}
	dsn, e := url.Parse(string(raw))
	if e != nil {
		t.Fatal(e)
	}
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	c.Database.DSNFile = p.spec.Root + "-node-target.dsn"
	localWrite(t, c.Database.DSNFile, []byte(dsn.String()))
	c.Metrics.QueryURL = os.Getenv("WEBSCAN_V3_TEST_VM")
	c.Metrics.WriteURL = c.Metrics.QueryURL
	c.Metrics.RawURL = os.Getenv("WEBSCAN_V3_TEST_RAW_VM")
	if _, e = target.BeginMigrationRecovery(ctx, generation); e != nil {
		t.Fatal(e)
	}
	report, e := target.RunMigrationRecovery(ctx, c, generation)
	if e != nil || len(report.Nodes) != 1 || report.Nodes[0].State != "complete" {
		t.Fatal("real node recovery did not complete", report, e)
	}
	replayed, e := target.ReplayMigrationRecoveryMetrics(ctx, c, generation)
	if e != nil || replayed.MetricGaps != 0 || len(replayed.Nodes) != 1 || replayed.Nodes[0].Metrics.State != "verified" {
		for _, n := range replayed.Nodes {
			t.Logf("replay state=%s samples=%d gaps=%d interval=%dms", n.Metrics.State, n.Metrics.Samples, n.Metrics.Gaps, n.Metrics.Last-n.Metrics.First)
		}
		t.Fatal("actual metric replay incomplete", e)
	}
	if e = target.SuppressMigrationRecoveryNotifications(ctx, generation, "recovery-admin"); e != nil {
		t.Fatal(e)
	}
	// Source durable epoch advanced beyond the restored snapshot while recovery
	// was held; activation must exceed this as well as the actual Agent epoch7.
	if _, e = source.DB.Exec(`UPDATE v3_leases SET epoch=11`); e != nil {
		t.Fatal(e)
	}
	request := MigrationRecoveryHostRequest{Format: 1, Generation: generation, Backup: receipt.Directory, ManifestSHA256: receipt.ManifestSHA256, Staged: staged, Original: p.request, WorkDirectory: p.spec.Root + "-node-work"}
	plan, e := planMigrationRecoveryHost(ctx, request, c)
	if e != nil {
		t.Fatal(e)
	}
	stateTx, err := target.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = migrationRecoveryHostStateTx(ctx, stateTx, plan)
	stateTx.Rollback()
	if err != nil {
		var phase, other string
		var missing, unresolved int
		target.DB.QueryRow(`SELECT phase FROM v3_migration_recovery_state WHERE id=1`).Scan(&phase)
		target.DB.QueryRow(`SELECT COALESCE(string_agg(domain,','),'') FROM v3_migration_domains WHERE pending AND domain<>'disaster-recovery'`).Scan(&other)
		target.DB.QueryRow(`SELECT count(*) FROM v3_migration_recovery_nodes WHERE state<>'complete' OR NOT retention_complete OR metrics_state<>'verified' OR metrics_gaps>0`).Scan(&missing)
		target.DB.QueryRow(`SELECT count(*) FROM v3_migration_recovery_events WHERE notification_state IN ('unknown','verified_unsent')`).Scan(&unresolved)
		t.Fatalf("host state binding failed phase=%s other=%s missing=%d unresolved=%d", phase, other, missing, unresolved)
	}
	// Only archive-engine and physical process/container observation are mocked
	// here. Actual full-archive Docker evidence is covered by the kernel test.
	runtime := migrationRecoveryHostObservedFixture(t, p)
	before := shadowSQLSnapshot(t, agent.DB, []string{"events", "pull_state", "pull_receipts", "pull_metrics", "pull_recovery_retention"})
	final, e := target.migrationRecoveryHost(ctx, plan, true, runtime)
	if e != nil || !final.CutoverAuthorized || final.State != "complete" {
		t.Fatal("actual node host handoff", final, e)
	}
	var epoch int64
	if e = target.DB.QueryRow(`SELECT epoch FROM v3_leases WHERE resource=$1`, shardResource(Shard("recovery-host-node", 256))).Scan(&epoch); e != nil || epoch != 12 {
		t.Fatal("host activation missed current durable floor", epoch, e)
	}
	after := shadowSQLSnapshot(t, agent.DB, []string{"events", "pull_state", "pull_receipts", "pull_metrics", "pull_recovery_retention"})
	if !migrationRecoveryHostSameJSON(before, after) {
		t.Fatal("host recovery mutated Agent queue or acknowledgement state")
	}
	if count := tableCount(t, target, "v3_events"); count != 2 {
		t.Fatal("handoff lost retained events", count)
	}
}
