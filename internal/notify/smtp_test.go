package notify

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"
	"webscan/internal/common"
)

func fixture(t *testing.T, mode, reject string) (common.Map, *tls.Config, <-chan string) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pair, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	port := l.Addr().(*net.TCPAddr).Port
	body := make(chan string, 5)
	go func() {
		for {
			conn, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if mode == "tls" {
					conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
				}
				reader := bufio.NewReader(conn)
				write := func(s string) { conn.Write([]byte(s + "\r\n")) }
				write("220 fixture")
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						if mode == "starttls" {
							write("250-fixture\r\n250-STARTTLS\r\n250 AUTH PLAIN")
						} else {
							write("250-fixture\r\n250 AUTH PLAIN")
						}
					case strings.HasPrefix(line, "STARTTLS"):
						write("220 ready")
						conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{pair}})
						reader = bufio.NewReader(conn)
					case strings.HasPrefix(line, "AUTH"):
						if reject == "auth" {
							write("535 rejected")
						} else {
							write("235 accepted")
						}
					case strings.HasPrefix(line, "MAIL"):
						write("250 accepted")
					case strings.HasPrefix(line, "RCPT"):
						if reject == "recipient" {
							write("550 rejected")
						} else {
							write("250 accepted")
						}
					case strings.HasPrefix(line, "DATA"):
						write("354 continue")
						raw, e := textproto.NewReader(reader).ReadDotBytes()
						if e != nil {
							return
						}
						body <- string(raw)
						write("250 queued")
					default:
						write("221 bye")
						return
					}
				}
			}()
		}
	}()
	return common.Map{"enabled": true, "smtp_host": "localhost", "smtp_port": port, "tls_mode": mode, "username": "sender@example.com", "password": "fixture-authorization", "from_address": "sender@example.com", "from_name": "网站监控", "recipients": []string{"receiver@example.com"}, "timeout_seconds": 2, "max_per_minute": 30, "retry": common.Map{"initial_delay_seconds": 1, "max_delay_seconds": 10}}, &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS12}, body
}
func TestSecureSMTP(t *testing.T) {
	for _, mode := range []string{"tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			c, config, bodies := fixture(t, mode, "")
			if e := sendTLS(context.Background(), c, "receiver@example.com", "stable-id", "中文测试", "中文告警\n恢复时间", config); e != nil {
				t.Fatal(e)
			}
			select {
			case body := <-bodies:
				if !strings.Contains(body, "中文告警") || !strings.Contains(body, "Message-ID: <stable-id@webscan.local>") {
					t.Fatal(body)
				}
			case <-time.After(time.Second):
				t.Fatal("no mail")
			}
		})
	}
}
func TestSMTPFailuresAreRedacted(t *testing.T) {
	for _, kind := range []string{"auth", "recipient", "certificate"} {
		t.Run(kind, func(t *testing.T) {
			c, config, _ := fixture(t, "tls", kind)
			if kind == "certificate" {
				config.RootCAs = x509.NewCertPool()
			}
			e := sendTLS(context.Background(), c, "receiver@example.com", "stable-id", "test", "test", config)
			if e == nil || strings.Contains(e.Error(), "fixture-authorization") {
				t.Fatal(e)
			}
		})
	}
}
func TestValidationAndRecipients(t *testing.T) {
	c, _, _ := fixture(t, "tls", "")
	c["recipients"] = []string{"receiver@example.com", "receiver@example.com"}
	if e := Validate(c); e != nil || len(Recipients(c)) != 1 {
		t.Fatal(e)
	}
	c["tls_mode"] = "plain"
	if Validate(c) == nil {
		t.Fatal("plaintext allowed")
	}
	c["tls_mode"] = "tls"
	c["from_name"] = "header\r\ninjection"
	if Validate(c) == nil {
		t.Fatal("header injection allowed")
	}
}

func TestSMTPTimeoutAndCancellation(t *testing.T) {
	c, config, _ := fixture(t, "starttls", "")
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	c["smtp_host"] = "127.0.0.1"
	c["smtp_port"] = listener.Addr().(*net.TCPAddr).Port
	c["timeout_seconds"] = 1
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		conn, e := listener.Accept()
		if e == nil {
			defer conn.Close()
			<-stop
		}
	}()
	started := time.Now()
	if e = sendTLS(context.Background(), c, "receiver@example.com", "timeout", "test", "test", config); e == nil {
		t.Fatal("silent SMTP was accepted")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("timeout not bounded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = sendTLS(ctx, c, "receiver@example.com", "cancel", "test", "test", config); e == nil {
		t.Fatal("cancellation ignored")
	}
}
