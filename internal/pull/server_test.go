package pull

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
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	agentv1 "webscan/sdk/agent/v1"
)

func TestGRPCOverHTTP2RequiresAuthorizedCollector(t *testing.T) {
	now := time.Now()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(serial int64, name string, usage x509.ExtKeyUsage) tls.Certificate {
		t.Helper()
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{name}}
		raw, e := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		pk, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
		if e != nil {
			t.Fatal(e)
		}
		return pair
	}
	s := testSource(t)
	addEvent(t, s, "a")
	g := NewServer(s, []string{"collector-a"})
	defer g.Stop()
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{issue(2, "agent.test", x509.ExtKeyUsageServerAuth)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	defer server.Close()
	for i, name := range []string{"collector-a", "untrusted-role"} {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "agent.test", Certificates: []tls.Certificate{issue(int64(i+3), name, x509.ExtKeyUsageClientAuth)}}
		conn, e := grpc.NewClient(server.Listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
		if e != nil {
			t.Fatal(e)
		}
		client := agentv1.NewAgentServiceClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		b, e := client.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100})
		cancel()
		conn.Close()
		if name == "collector-a" {
			if e != nil || len(b.Events) != 1 {
				t.Fatal(b, e)
			}
		} else if status.Code(e) != codes.PermissionDenied {
			t.Fatal("wrong role was accepted", e)
		}
	}
}
