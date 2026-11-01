package pull

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"webscan/internal/persist"
	agentv1 "webscan/sdk/agent/v1"
)

func recoveryDatabaseSnapshot(t *testing.T, s *Source) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range []string{"events", "pull_state", "pull_receipts", "pull_metrics", "delivery_failures", "delivery_status", "pull_recovery_retention"} {
		rows, e := s.DB.Query("SELECT * FROM " + table + " ORDER BY rowid")
		if e != nil {
			t.Fatal(e)
		}
		columns, _ := rows.Columns()
		all := []any{}
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if e = rows.Scan(dest...); e != nil {
				t.Fatal(e)
			}
			all = append(all, values)
		}
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		rows.Close()
		raw, _ := json.Marshal(all)
		out[table] = string(raw)
	}
	return out
}
func TestRecoveryReadPreservesAcceptedPendingAndEverySQLiteTable(t *testing.T) {
	s := testSource(t)
	ctx := context.Background()
	for _, id := range []string{"accepted", "pending"} {
		addEvent(t, s, id)
	}
	if _, e := s.DB.Exec(`UPDATE events SET accepted=2 WHERE id='accepted'; UPDATE pull_state SET epoch=77 WHERE id=1; INSERT INTO pull_metrics VALUES(1000,'metric'); INSERT INTO delivery_failures VALUES('pending','synthetic',1)`); e != nil {
		t.Fatal(e)
	}
	before := recoveryDatabaseSnapshot(t, s)
	state, e := s.RecoveryState(ctx, s.NodeID)
	if e != nil || state.Epoch != 77 || state.RetainedEvents != 2 || state.AcceptedEvents != 1 || state.PendingEvents != 1 || state.RetentionComplete || state.RetentionSinceUnixMillis < time.Now().Add(-time.Minute).UnixMilli() || state.LastDeletedUnixMillis != 0 {
		t.Fatal(state, e)
	}
	a, e := s.ReadRecoveryEvents(ctx, s.NodeID, state.Cursor, 1)
	if e != nil || len(a.Events) != 1 || !a.Events[0].Accepted || a.Events[0].Id != "accepted" || a.Complete || a.ReadEvents != 1 {
		t.Fatal(a, e)
	}
	b, e := s.ReadRecoveryEvents(ctx, s.NodeID, a.NextCursor, 1)
	if e != nil || len(b.Events) != 1 || b.Events[0].Accepted || b.Events[0].Id != "pending" || !b.Complete || b.NextCursor != "" || b.ReadEvents != 2 {
		t.Fatal(b, e)
	}
	again, e := s.ReadRecoveryEvents(ctx, s.NodeID, state.Cursor, 1)
	if e != nil || !reflect.DeepEqual(a.Events, again.Events) {
		t.Fatal("lost response changes replay", again, e)
	}
	if after := recoveryDatabaseSnapshot(t, s); !reflect.DeepEqual(before, after) {
		t.Fatal("readonly recovery wrote to SQLite", before, after)
	}
	if _, e = s.RecoveryState(ctx, "other"); !errors.Is(e, ErrRecoveryRead) {
		t.Fatal("wrong identity read")
	}
	if _, e = s.ReadRecoveryEvents(ctx, s.NodeID, state.Cursor+"x", 1); !errors.Is(e, ErrRecoveryRead) {
		t.Fatal("tampered cursor accepted")
	}
}
func TestRecoveryCursorRejectsRowIDReuseEpochChangeRestartAndBackupRestore(t *testing.T) {
	s := testSource(t)
	ctx := context.Background()
	addEvent(t, s, "a")
	state, e := s.RecoveryState(ctx, s.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := s.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec("DELETE FROM events"); e != nil {
		t.Fatal(e)
	}
	tx.Rollback()
	stable, e := s.RecoveryState(ctx, s.NodeID)
	if e != nil || stable.DeletedEvents != 0 || stable.SnapshotSha256 != state.SnapshotSha256 {
		t.Fatal("rolled-back delete advanced watermark", stable, e)
	}
	if _, e = s.DB.Exec(`DELETE FROM events; INSERT INTO events(rowid,id,payload,created) VALUES(1,'replacement','{}',1)`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReadRecoveryEvents(ctx, s.NodeID, state.Cursor, 1); !errors.Is(e, ErrRecoveryRead) {
		t.Fatal("rowid reuse accepted", e)
	}
	updated, e := s.RecoveryState(ctx, s.NodeID)
	if e != nil || updated.DeletedEvents != 1 || updated.LastDeletedUnixMillis < updated.RetentionSinceUnixMillis {
		t.Fatal(updated, e)
	}
	if _, e = s.DB.Exec("UPDATE pull_state SET epoch=9"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReadRecoveryEvents(ctx, s.NodeID, updated.Cursor, 1); !errors.Is(e, ErrRecoveryRead) {
		t.Fatal("epoch shift accepted")
	}
	updated, e = s.RecoveryState(ctx, s.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "backup.sqlite3")
	if e = persist.BackupDB(s.DB, path); e != nil {
		t.Fatal(e)
	}
	db, e := persist.OpenDB(path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	restarted, e := New(db, s.NodeID, "v3-test", new(sync.Mutex))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restarted.ReadRecoveryEvents(ctx, s.NodeID, updated.Cursor, 1); !errors.Is(e, ErrRecoveryRead) {
		t.Fatal("backup instance reused cursor")
	}
	restored, e := restarted.RecoveryState(ctx, s.NodeID)
	if e != nil || restored.RetentionSinceUnixMillis != updated.RetentionSinceUnixMillis || restored.DeletedEvents != updated.DeletedEvents || restored.SnapshotSha256 != updated.SnapshotSha256 {
		t.Fatal("restored watermark changed", restored, e)
	}
	if _, e = s.ReadRecoveryEvents(ctx, s.NodeID, s.recoveryEncode(recoveryCursor{Snapshot: updated.SnapshotSha256, Expires: time.Now().Add(-time.Minute).Unix()}), 1); !errors.Is(e, ErrRecoveryRead) {
		t.Fatal("expired cursor accepted")
	}
}
func recoveryRPCFixture(t *testing.T, s *Source, role string) agentv1.AgentServiceClient {
	t.Helper()
	now := time.Now()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "recovery-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(n int64, name string, usage x509.ExtKeyUsage) tls.Certificate {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{name}}
		raw, e := x509.CreateCertificate(rand.Reader, cert, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		pk, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
		if e != nil {
			t.Fatal(e)
		}
		return pair
	}
	g := NewServer(s, []string{"recovery-collector"})
	t.Cleanup(g.Stop)
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{issue(2, "recovery.test", x509.ExtKeyUsageServerAuth)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	conn, e := grpc.NewClient(server.Listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "recovery.test", Certificates: []tls.Certificate{issue(3, role, x509.ExtKeyUsageClientAuth)}})))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close() })
	return agentv1.NewAgentServiceClient(conn)
}
func TestRecoveryRPCRequiresExistingMTLSCollectorAndFixedNode(t *testing.T) {
	s := testSource(t)
	addEvent(t, s, "accepted")
	if _, e := s.DB.Exec("UPDATE events SET accepted=2"); e != nil {
		t.Fatal(e)
	}
	before := recoveryDatabaseSnapshot(t, s)
	client := recoveryRPCFixture(t, s, "recovery-collector")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	capabilities, e := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
	if e != nil || !capabilities.RecoveryRead {
		t.Fatal(capabilities, e)
	}
	state, e := client.RecoveryState(ctx, &agentv1.RecoveryStateRequest{NodeId: s.NodeID})
	if e != nil {
		t.Fatal(e)
	}
	batch, e := client.ReadRecoveryEvents(ctx, &agentv1.ReadRecoveryEventsRequest{NodeId: s.NodeID, Cursor: state.Cursor, Limit: 100})
	if e != nil || len(batch.Events) != 1 || !batch.Events[0].Accepted || !batch.Complete {
		t.Fatal(batch, e)
	}
	if _, e = client.RecoveryState(ctx, &agentv1.RecoveryStateRequest{NodeId: "other"}); status.Code(e) != codes.InvalidArgument {
		t.Fatal("wrong target accepted", e)
	}
	bad := recoveryRPCFixture(t, s, "other-role")
	if _, e = bad.RecoveryState(ctx, &agentv1.RecoveryStateRequest{NodeId: s.NodeID}); status.Code(e) != codes.PermissionDenied {
		t.Fatal("wrong role accepted", e)
	}
	if !reflect.DeepEqual(before, recoveryDatabaseSnapshot(t, s)) {
		t.Fatal("RPC read changed durable source")
	}
}
