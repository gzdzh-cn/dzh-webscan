package central

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

func freePort(t *testing.T) int {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
func TestGoFrameHTTPHTTPSDurableQueueAndShutdown(t *testing.T) {
	base := t.TempDir()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1234), Subject: pkix.Name{CommonName: "Webscan test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	certPath := filepath.Join(base, "ca.crt")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPath := filepath.Join(base, "key.pem")
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600)
	delivery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/loki/api/v1/push" {
			w.WriteHeader(204)
		} else {
			w.Write([]byte(`{"code":0}`))
		}
	}))
	defer delivery.Close()
	plain, tlsPort := freePort(t), freePort(t)
	config := common.Map{"data_dir": base, "bind": "127.0.0.1", "port": plain, "https": common.Map{"bind": "127.0.0.1", "port": tlsPort, "cert_file": certPath, "key_file": keyPath, "allowed_sources": []string{"127.0.0.1/32"}}, "max_request_mib": 2, "max_batch_events": 100, "nodes": common.Map{"node": common.Map{"host": "127.0.0.1", "name": "test", "token": "fixture-token"}}, "active_nodes": []string{"node"}, "loki_url": delivery.URL, "feishu": common.Map{"enabled": true, "webhook_url": delivery.URL, "notifications": common.Map{"file_changes": true}, "rate_limit": common.Map{"max_per_second": 100, "max_per_minute": 1000}, "retry": common.Map{"initial_delay_seconds": 1, "max_delay_seconds": 5}}, "retention": common.Map{"sqlite_events_days": 90, "delivery_records_days": 90}}
	path := filepath.Join(base, "runtime.json")
	common.AtomicJSON(path, config)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, path) }()
	defer func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(10 * time.Second):
			t.Error("shutdown did not complete")
		}
	}()
	client, e := common.HTTPClient(certPath, 2*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(10 * time.Second)
	ready := "http://127.0.0.1:" + strconv.Itoa(plain) + "/ready"
	for {
		_, v, e := common.Request(context.Background(), client, "GET", ready, nil, nil)
		if e == nil && common.B(common.M(v)["ready"]) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("GoFrame ready timeout", e)
		}
		time.Sleep(50 * time.Millisecond)
	}
	endpoint := "https://127.0.0.1:" + strconv.Itoa(tlsPort)
	headers := map[string]string{"Authorization": "Bearer fixture-token"}
	if code, _, e := common.Request(context.Background(), client, "POST", endpoint+"/webscan/v1/events", fixture(), headers); e != nil || code != 200 {
		t.Fatal("TLS ingest failed", code, e)
	}
	if code, _, e := common.Request(context.Background(), client, "GET", endpoint+"/metrics", nil, nil); e == nil || code != 404 {
		t.Fatal("public metrics exposed", code, e)
	}
	if _, v, e := common.Request(context.Background(), client, "POST", endpoint+"/webscan/v1/receipts", common.Map{"event_ids": []string{"fixture-1"}}, headers); e != nil || len(common.A(common.M(v)["accepted"])) != 1 {
		t.Fatal("receipt failed", e)
	}
	db, e := persist.OpenDB(filepath.Join(base, "events-v1.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	deadline = time.Now().Add(10 * time.Second)
	for {
		var pending, count int
		db.QueryRow("SELECT count(*) FROM tasks WHERE done IS NULL").Scan(&pending)
		db.QueryRow("SELECT count(*) FROM tasks WHERE done IS NOT NULL").Scan(&count)
		if pending == 0 && count >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("delivery did not drain", pending, count)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
