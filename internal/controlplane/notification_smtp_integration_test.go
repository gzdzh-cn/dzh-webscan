package controlplane

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"webscan/internal/common"
)

// A separate process scopes the standard-library trust roots to this synthetic
// test. No system certificate, production SMTP setting or TLS check is changed.
func TestNotificationTestChannelSenderSMTPVerifiedTLSAndUncertainResults(t *testing.T) {
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"tls", "starttls"} {
		for _, outcome := range []string{"accepted", "wrong-certificate", "response-lost"} {
			t.Run(mode+"/"+outcome, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, executable, "-test.run=^TestNotificationSMTPTransportProcess$", "-test.v")
				command.Env = append(os.Environ(), "WEBSCAN_NOTIFICATION_SMTP_PROCESS="+mode+":"+outcome, "GODEBUG="+os.Getenv("GODEBUG")+",x509usefallbackroots=1")
				output, e := command.CombinedOutput()
				if e != nil {
					t.Fatalf("isolated SMTP child failed: %v\n%s", e, output)
				}
				if !strings.Contains(string(output), "SMTP_PROCESS_VERIFIED") {
					t.Fatal("isolated SMTP verification did not execute")
				}
			})
		}
	}
}

func notificationSMTPTestFixture(t *testing.T, mode, outcome string) (int, <-chan string, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	address := net.ParseIP("127.0.0.1")
	if outcome == "wrong-certificate" {
		address = net.ParseIP("127.0.0.2")
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated SMTP"}, IPAddresses: []net.IP{address}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool.AddCert(parsed)
	x509.SetFallbackRoots(pool)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	bodies := make(chan string, 5)
	connections, authenticated := &atomic.Int32{}, &atomic.Int32{}
	var acceptWG, connectionsWG sync.WaitGroup
	acceptWG.Add(1)
	go func() {
		defer acceptWG.Done()
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			connections.Add(1)
			connectionsWG.Add(1)
			go func(conn net.Conn) {
				defer connectionsWG.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				config := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
				if mode == "tls" {
					conn = tls.Server(conn, config)
				}
				reader := bufio.NewReader(conn)
				write := func(s string) bool { _, e := conn.Write([]byte(s + "\r\n")); return e == nil }
				if !write("220 isolated SMTP") {
					return
				}
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						if mode == "starttls" {
							if !write("250-isolated\r\n250-STARTTLS\r\n250 AUTH PLAIN") {
								return
							}
						} else if !write("250-isolated\r\n250 AUTH PLAIN") {
							return
						}
					case strings.HasPrefix(line, "STARTTLS"):
						if !write("220 ready") {
							return
						}
						conn = tls.Server(conn, config)
						reader = bufio.NewReader(conn)
					case strings.HasPrefix(line, "AUTH"):
						authenticated.Add(1)
						if !write("235 accepted") {
							return
						}
					case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
						if !write("250 accepted") {
							return
						}
					case strings.HasPrefix(line, "DATA"):
						if !write("354 continue") {
							return
						}
						body, e := textproto.NewReader(reader).ReadDotBytes()
						if e != nil {
							return
						}
						bodies <- string(body)
						if outcome == "response-lost" {
							return
						}
						if !write("250 queued") {
							return
						}
					default:
						_ = write("221 closing")
						return
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); acceptWG.Wait(); connectionsWG.Wait() })
	return listener.Addr().(*net.TCPAddr).Port, bodies, connections, authenticated
}

func TestNotificationSMTPTransportProcess(t *testing.T) {
	selected := os.Getenv("WEBSCAN_NOTIFICATION_SMTP_PROCESS")
	if selected == "" {
		return
	}
	mode, outcome, ok := strings.Cut(selected, ":")
	if !ok || (mode != "tls" && mode != "starttls") {
		t.Fatal("invalid isolated SMTP case")
	}
	port, bodies, connections, authenticated := notificationSMTPTestFixture(t, mode, outcome)
	f := newNotificationTestFixture(t)
	var settings common.Map
	var raw []byte
	if e := f.s.DB.QueryRow(`SELECT payload FROM v3_settings WHERE id=1`).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(raw, &settings); e != nil {
		t.Fatal(e)
	}
	email := common.M(settings["email"])
	email["smtp_host"] = "127.0.0.1"
	email["smtp_port"] = port
	email["tls_mode"] = mode
	email["recipients"] = []string{"synthetic@example.test"}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_settings SET payload=$1`, common.JSON(settings))
	job := f.submit(t, f.preview(t, "email"))
	f.worker.Sender = ChannelSender{}
	for i := 0; i < 3; i++ {
		if e := f.worker.RunRound(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	got := f.job(t, job.ID)
	expected := "succeeded"
	if outcome != "accepted" {
		expected = "unknown"
	}
	if got.Status != expected || connections.Load() != 1 || len(got.Items) != 1 || strings.Contains(got.Message, "PRIVATE") {
		t.Fatal("SMTP outcome or single-attempt guarantee failed", got, connections.Load())
	}
	if outcome == "wrong-certificate" {
		if authenticated.Load() != 0 || len(bodies) != 0 {
			t.Fatal("invalid certificate exposed SMTP credentials or body")
		}
	} else {
		if authenticated.Load() != 1 {
			t.Fatal("SMTP authentication did not occur")
		}
		select {
		case body := <-bodies:
			expectedKey := digest([]byte("notification-test:" + job.ID + ":1"))
			if !strings.Contains(body, "管理员主动发送") || !strings.Contains(body, "Message-ID: <"+expectedKey+"@webscan.local>") || strings.Contains(body, "PRIVATE-notification-fixture") {
				t.Fatal("SMTP content or stable message identity incorrect")
			}
		case <-time.After(time.Second):
			t.Fatal("SMTP server did not receive test body")
		}
	}
	t.Log("SMTP_PROCESS_VERIFIED", mode, outcome)
}
