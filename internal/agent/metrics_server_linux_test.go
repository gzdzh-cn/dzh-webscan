//go:build linux

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestMetricsSourceAndRouteRestrictions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "metrics")
	os.WriteFile(p, []byte("webscan_ready 1\n"), 0600)
	a := &Agent{C: common.Map{"metrics_file": p}}
	h := a.metricsHandler(net.ParseIP("192.0.2.1"))
	for _, tc := range []struct {
		remote, path, method string
		status               int
	}{
		{"192.0.2.1:1", "/metrics", "GET", 200}, {"192.0.2.2:1", "/metrics", "GET", 403},
		{"[::ffff:192.0.2.1]:1", "/metrics", "GET", 200}, {"127.0.0.1:1", "/metrics", "GET", 200},
		{"invalid", "/metrics", "GET", 403}, {"192.0.2.1:1", "/config", "GET", 404}, {"192.0.2.1:1", "/metrics", "POST", 404},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.RemoteAddr = tc.remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal(tc, w.Code)
		}
	}
	os.Remove(p)
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.RemoteAddr = "192.0.2.1:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
func TestMetricsRequireTrustedClientCertificate(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(raw)
	capem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	os.WriteFile(filepath.Join(dir, "ca.crt"), capem, 0600)
	issue := func(name string, usage x509.ExtKeyUsage) tls.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(int64(usage) + 10), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
		b, err := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		kb, _ := x509.MarshalPKCS8PrivateKey(k)
		cb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
		os.WriteFile(filepath.Join(dir, name+".crt"), cb, 0600)
		os.WriteFile(filepath.Join(dir, name+".key"), kp, 0600)
		pair, _ := tls.X509KeyPair(cb, kp)
		return pair
	}
	issue("server", x509.ExtKeyUsageServerAuth)
	client := issue("client", x509.ExtKeyUsageClientAuth)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	os.WriteFile(filepath.Join(dir, "metrics"), []byte("webscan_ready 1\n"), 0600)
	a, _ := testAgent(t)
	a.C["metrics_file"] = filepath.Join(dir, "metrics")
	a.C["metrics"] = common.Map{"port": port, "allowed_source_ip": "127.0.0.1", "tls_enabled": true, "cert_file": filepath.Join(dir, "server.crt"), "key_file": filepath.Join(dir, "server.key"), "ca_file": filepath.Join(dir, "ca.crt")}
	a.C["pull"] = common.Map{"collector_identities": []any{"client"}}
	a.Pull, e = pull.New(a.DB, "isolated-node", "v3-test", &a.writeMu)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); a.worker.Wait() }()
	if e = a.startMetrics(ctx); e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(capem)
	for _, withCert := range []bool{false, true} {
		tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		if withCert {
			tc.Certificates = []tls.Certificate{client}
		}
		tr := &http.Transport{TLSClientConfig: tc}
		c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		r, err := c.Get("https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/metrics")
		tr.CloseIdleConnections()
		if withCert {
			if err != nil {
				t.Fatal(err)
			}
			r.Body.Close()
			if r.StatusCode != 200 {
				t.Fatal(r.StatusCode)
			}
		} else if err == nil {
			r.Body.Close()
			t.Fatal("accepted missing client certificate")
		}
	}
	// Real HTTP/2 gRPC and legacy /metrics must share the same listener.
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, e := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, Certificates: []tls.Certificate{client}, MinVersion: tls.VersionTLS12})))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	op, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	api := agentv1.NewAgentServiceClient(conn)
	capabilities, e := api.Capabilities(op, &agentv1.CapabilitiesRequest{})
	if e != nil || capabilities.NodeId != "isolated-node" || capabilities.Protocol != agentv1.ProtocolVersion {
		t.Fatal(capabilities, e)
	}
	batch, e := api.FetchEvents(op, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100})
	if e != nil || batch.NodeId != "isolated-node" {
		t.Fatal(batch, e)
	}
}
