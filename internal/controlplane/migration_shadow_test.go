package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"webscan/internal/nodepki"
	"webscan/internal/persist"
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"
)

type shadowFixture struct {
	store         *Store
	config        Config
	node          Node
	source        *pull.Source
	server        *httptest.Server
	stateDir      string
	mu            sync.Mutex
	methods       []string
	rejectMetrics bool
}

func newShadowFixture(t *testing.T) *shadowFixture {
	t.Helper()
	f := &shadowFixture{store: testStore(t)}
	// The production schema owner registers the migration; this assertion makes
	// accidentally exercising a hand-created test-only schema impossible.
	var exists bool
	if err := f.store.DB.QueryRow("SELECT to_regclass('v3_migration_shadow_runs') IS NOT NULL").Scan(&exists); err != nil || !exists {
		t.Fatal("shadow schema migration missing", err)
	}
	now := time.Now()
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := authority.Export()
	if err != nil {
		t.Fatal(err)
	}
	node, err := authority.Issue(nodepki.Node, "shadow-node", []string{"shadow.test", "shadow-node"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := authority.Issue(nodepki.Collector, "shadow-collector", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := authority.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTestDir(t)
	f.config.Collector.CAFile = filepath.Join(directory, "ca.crt")
	f.config.Collector.CertFile = filepath.Join(directory, "collector.crt")
	f.config.Collector.KeyFile = filepath.Join(directory, "collector.key")
	f.config.Collector.RevocationFile = filepath.Join(directory, "ca.crl")
	localWrite(t, f.config.Collector.CAFile, ca.CA)
	localWrite(t, f.config.Collector.CertFile, collector.Certificate)
	localWrite(t, f.config.Collector.KeyFile, collector.Key)
	localWrite(t, f.config.Collector.RevocationFile, crl)
	f.stateDir = filepath.Join(directory, "trust")
	if err := os.Mkdir(f.stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	localWrite(t, filepath.Join(f.stateDir, "ca.crt"), ca.CA)
	localWrite(t, filepath.Join(f.stateDir, "ca.crl"), crl)
	f.config.Collector.RevocationStateDirectory = f.stateDir
	db, err := persist.OpenDB(filepath.Join(directory, "node.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec("CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT,created REAL,accepted REAL)"); err != nil {
		t.Fatal(err)
	}
	f.node = nodeFixture("shadow-node")
	f.node.Enabled = false
	f.node.Config = json.RawMessage(`{"private_fixture":"must-not-be-returned"}`)
	f.source, err = pull.New(db, f.node.ID, "v3-shadow-isolated", new(sync.Mutex), pull.Configuration{Version: 1, SHA256: digest(f.node.Config)})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.source.RecordMetrics(context.Background(), now.Add(-time.Second), []byte("node_memory_MemTotal_bytes 123456\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE pull_state SET epoch=7;
 INSERT INTO pull_receipts VALUES('existing-receipt',7,'["pending"]',9999999999);
 INSERT INTO events VALUES('pending','{"node_id":"shadow-node","event_id":"pending","operation":"modify","path":"/isolated/shadow"}',1,NULL);
 INSERT INTO events VALUES('malformed','not-json',2,NULL);
 INSERT INTO events VALUES('accepted','{}',3,4);
 INSERT INTO delivery_failures VALUES('earlier-failure','isolated',1);
 INSERT INTO delivery_status VALUES(1,'previous-status',1);`); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(node.Certificate, node.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CA)
	trust, err := nodepki.NewTrust(ca.CA, crl, now)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := nodepki.Identity(nodepki.Collector, "shadow-collector")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := func() { t.Error("shadow invoked identity or trust mutation") }
	g := pull.NewServerWithRootTrust(f.source, []string{identity}, func(context.Context, *x509.Certificate, []byte) (*agentv1.UpdateTrustResponse, error) {
		forbidden()
		return nil, errors.New("forbidden")
	}, func(context.Context, *x509.Certificate, []byte) (*agentv1.RefreshRootTrustResponse, error) {
		forbidden()
		return nil, errors.New("forbidden")
	}, nil, func(cert *x509.Certificate) error {
		return trust.Verify(cert, nodepki.Collector, "shadow-collector", time.Now())
	})
	t.Cleanup(g.Stop)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.methods = append(f.methods, r.URL.Path)
		reject := f.rejectMetrics && r.URL.Path == agentv1.AgentService_ReadMetrics_FullMethodName
		f.mu.Unlock()
		if reject {
			http.Error(w, "isolated temporary failure", http.StatusServiceUnavailable)
			return
		}
		g.ServeHTTP(w, r)
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	f.server = server
	f.node.Endpoint, f.node.ServerName = server.Listener.Addr().String(), "shadow.test"
	if err := f.store.PutNode(context.Background(), f.node, 0, 256); err != nil {
		t.Fatal(err)
	}
	// PostgreSQL jsonb owns the saved configuration's canonical representation.
	// Start the real Source with that exact signed-configuration identity.
	if err := f.store.DB.QueryRow("SELECT config FROM v3_nodes WHERE id=$1", f.node.ID).Scan(&f.node.Config); err != nil {
		t.Fatal(err)
	}
	fixed, err := pull.New(db, f.node.ID, "v3-shadow-isolated", new(sync.Mutex), pull.Configuration{Version: 1, SHA256: digest(f.node.Config)})
	if err != nil {
		t.Fatal(err)
	}
	*f.source = *fixed
	return f
}

func (f *shadowFixture) bind(t *testing.T) (MigrationSession, MigrationShadowReport) {
	t.Helper()
	ctx := context.Background()
	session, err := f.store.BeginMigrationSession(ctx, token(), 0, []string{"central", "health"})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := f.store.BindMigrationShadow(ctx, session.ID, session.Version, []string{f.node.ID})
	if err != nil {
		t.Fatal(err)
	}
	return session, bound
}

func shadowSQLSnapshot(t *testing.T, db *sql.DB, tables []string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, table := range tables {
		rows, err := db.Query("SELECT * FROM " + table)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		out[table] = []string{}
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			for i, value := range values {
				if raw, ok := value.([]byte); ok {
					values[i] = string(raw)
				}
			}
			raw, err := json.Marshal(values)
			if err != nil {
				rows.Close()
				t.Fatal(err)
			}
			out[table] = append(out[table], string(raw))
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
		sort.Strings(out[table])
	}
	return out
}

func shadowBusinessSnapshot(t *testing.T, s *Store) map[string][]string {
	t.Helper()
	rows, err := s.DB.Query("SELECT tablename FROM pg_tables WHERE schemaname=current_schema() AND tablename NOT LIKE 'v3_migration_shadow_%' ORDER BY tablename")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	return shadowSQLSnapshot(t, s.DB, tables)
}

func shadowTrustSnapshot(t *testing.T, path string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(path, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			out[rel] = "directory"
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = digest(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMigrationShadowActualMTLSOnlyReadsWithoutChangingAgentOrBusinessState(t *testing.T) {
	f := newShadowFixture(t)
	session, bound := f.bind(t)
	agentTables := []string{"events", "pull_state", "pull_receipts", "pull_metrics", "delivery_failures", "delivery_status"}
	beforeAgent := shadowSQLSnapshot(t, f.source.DB, agentTables)
	beforeBusiness := shadowBusinessSnapshot(t, f.store)
	beforeTrust := shadowTrustSnapshot(t, f.stateDir)
	report, err := f.store.RunMigrationShadow(context.Background(), f.config, session.ID, session.Version, bound.ID)
	if err != nil || report.State != "complete" || report.Observed != 1 || report.Failed != 0 || !report.ReadOnly || report.ReadyForCutover {
		t.Fatal(report, err)
	}
	evidence := report.Evidence[0]
	if !evidence.MatchesSaved || evidence.Samples != 1 || !releaseDigest(evidence.SampleSHA256) || !releaseDigest(evidence.PeerCertificate) {
		t.Fatal(evidence)
	}
	if !reflect.DeepEqual(beforeAgent, shadowSQLSnapshot(t, f.source.DB, agentTables)) {
		t.Fatal("read-only shadow mutated durable agent epoch, receipts, pending/accepted events, metrics or delivery errors")
	}
	if !reflect.DeepEqual(beforeBusiness, shadowBusinessSnapshot(t, f.store)) {
		t.Fatal("shadow mutated business database outside independent shadow evidence")
	}
	if !reflect.DeepEqual(beforeTrust, shadowTrustSnapshot(t, f.stateDir)) {
		t.Fatal("shadow wrote a CRL floor, lock or trust observation")
	}
	f.mu.Lock()
	methods := append([]string{}, f.methods...)
	f.mu.Unlock()
	if !reflect.DeepEqual(methods, []string{agentv1.AgentService_Capabilities_FullMethodName, agentv1.AgentService_ReadMetrics_FullMethodName}) {
		t.Fatal("unexpected RPC", methods)
	}
	raw, _ := json.Marshal(report)
	for _, private := range []string{f.node.Endpoint, "must-not-be-returned", "node_memory_MemTotal_bytes", "existing-receipt", "/isolated/shadow"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private details returned")
		}
	}
	if _, err := f.store.RunMigrationShadow(context.Background(), f.config, session.ID, session.Version, bound.ID); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.methods) != 2 {
		t.Fatal("complete run was read again")
	}
}

func TestMigrationShadowFencesTargetsExpiryAndConfigurationBeforeNetwork(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *shadowFixture, MigrationSession, MigrationShadowReport)
	}{
		{"saved-enabled", func(t *testing.T, f *shadowFixture, _ MigrationSession, _ MigrationShadowReport) {
			mustHistoryExec(t, f.store.DB, "UPDATE v3_nodes SET enabled=true")
		}},
		{"active-enabled", func(t *testing.T, f *shadowFixture, _ MigrationSession, _ MigrationShadowReport) {
			mustHistoryExec(t, f.store.DB, "UPDATE v3_node_configurations SET enabled=true")
		}},
		{"session-version", func(t *testing.T, f *shadowFixture, _ MigrationSession, _ MigrationShadowReport) {
			mustHistoryExec(t, f.store.DB, "UPDATE v3_migration_sessions SET version=version+1")
		}},
		{"missing-domain-fence", func(t *testing.T, f *shadowFixture, _ MigrationSession, _ MigrationShadowReport) {
			mustHistoryExec(t, f.store.DB, "UPDATE v3_migration_domains SET pending=false")
		}},
		{"node-version", func(t *testing.T, f *shadowFixture, _ MigrationSession, _ MigrationShadowReport) {
			mustHistoryExec(t, f.store.DB, "UPDATE v3_nodes SET version=version+1")
		}},
		{"node-config", func(t *testing.T, f *shadowFixture, _ MigrationSession, _ MigrationShadowReport) {
			mustHistoryExec(t, f.store.DB, `UPDATE v3_nodes SET config='{"changed":true}'`)
		}},
		{"expired", func(t *testing.T, f *shadowFixture, _ MigrationSession, b MigrationShadowReport) {
			mustHistoryExec(t, f.store.DB, "UPDATE v3_migration_shadow_runs SET created_at=clock_timestamp()-interval '11 minutes' WHERE id=$1", b.ID)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newShadowFixture(t)
			session, bound := f.bind(t)
			tc.mutate(t, f, session, bound)
			if _, err := f.store.RunMigrationShadow(context.Background(), f.config, session.ID, session.Version, bound.ID); !errors.Is(err, ErrMigrationShadow) {
				t.Fatal("unprotected run accepted", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.methods) != 0 {
				t.Fatal("stale target contacted", f.methods)
			}
		})
	}
}

func TestMigrationShadowBindingRejectsEnabledDuplicateUnknownAndMissingProtection(t *testing.T) {
	f := newShadowFixture(t)
	ctx := context.Background()
	session, err := f.store.BeginMigrationSession(ctx, token(), 0, []string{"central"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][]string{nil, {f.node.ID, f.node.ID}, {"unknown-node"}} {
		if _, err := f.store.BindMigrationShadow(ctx, session.ID, session.Version, ids); !errors.Is(err, ErrMigrationShadow) {
			t.Fatal("invalid binding accepted", err)
		}
	}
	mustHistoryExec(t, f.store.DB, "UPDATE v3_migration_domains SET pending=false")
	if _, err := f.store.BindMigrationShadow(ctx, session.ID, session.Version, []string{f.node.ID}); !errors.Is(err, ErrMigrationShadow) {
		t.Fatal("session without durable fence accepted", err)
	}
}

func TestMigrationShadowPartialResumesAndInvalidTrustNeverStaysRunning(t *testing.T) {
	f := newShadowFixture(t)
	session, bound := f.bind(t)
	f.mu.Lock()
	f.rejectMetrics = true
	f.mu.Unlock()
	report, err := f.store.RunMigrationShadow(context.Background(), f.config, session.ID, session.Version, bound.ID)
	if err != nil || report.State != "partial" || report.Failed != 1 || report.Observed != 0 {
		t.Fatal(report, err)
	}
	f.mu.Lock()
	f.rejectMetrics = false
	f.mu.Unlock()
	report, err = f.store.RunMigrationShadow(context.Background(), f.config, session.ID, session.Version, bound.ID)
	if err != nil || report.State != "complete" || report.Failed != 0 || report.Observed != 1 {
		t.Fatal(report, err)
	}
	second, err := f.store.BindMigrationShadow(context.Background(), session.ID, session.Version, []string{f.node.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.stateDir, "ca.crl")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RunMigrationShadow(context.Background(), f.config, session.ID, session.Version, second.ID); !errors.Is(err, ErrMigrationShadow) {
		t.Fatal(err)
	}
	report, err = f.store.MigrationShadow(context.Background(), session.ID, session.Version, second.ID)
	if err != nil || report.State != "partial" || report.Observed != 0 {
		t.Fatal("trust failure left running", report, err)
	}
	if _, err := os.Stat(filepath.Join(f.stateDir, "ca.crl")); !os.IsNotExist(err) {
		t.Fatal("missing CRL floor was recreated", err)
	}
}

func TestMigrationShadowActualSourceRejectsStaleSamplesAndReportsSavedMismatch(t *testing.T) {
	for _, kind := range []string{"stale", "malformed", "saved-mismatch", "wrong-node-certificate"} {
		t.Run(kind, func(t *testing.T) {
			f := newShadowFixture(t)
			if kind == "wrong-node-certificate" {
				f.node.ID = "different-node"
				if err := f.store.PutNode(context.Background(), f.node, 0, 256); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "stale" {
				if _, err := f.source.DB.Exec("UPDATE pull_metrics SET sampled=?", time.Now().Add(-2*time.Hour).UnixMilli()); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "malformed" {
				if _, err := f.source.DB.Exec("UPDATE pull_metrics SET payload=?", []byte("bad metric syntax (")); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "saved-mismatch" {
				mustHistoryExec(t, f.store.DB, `UPDATE v3_nodes SET config='{"changed":true}'`)
			}
			session, bound := f.bind(t)
			report, err := f.store.RunMigrationShadow(context.Background(), f.config, session.ID, session.Version, bound.ID)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "saved-mismatch" {
				if report.State != "complete" || report.Evidence[0].MatchesSaved || report.Evidence[0].Reason != "saved-configuration-not-running" || report.ReadyForCutover {
					t.Fatal(report)
				}
			} else if report.State != "partial" || report.Failed != 1 {
				t.Fatal("invalid authenticated evidence accepted", report)
			}
		})
	}
}
