package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"webscan/internal/common"
)

func TestPinnedHostKeyWhenServerAlsoExposesOtherAlgorithms(t *testing.T) {
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edSigner, _ := ssh.NewSignerFromKey(priv)
	ecSigner, _ := ssh.NewSignerFromKey(ec)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(ecSigner)
	cfg.AddHostKey(edSigner)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				c, chs, req, e := ssh.NewServerConn(conn, cfg)
				if e != nil {
					conn.Close()
					return
				}
				defer c.Close()
				go ssh.DiscardRequests(req)
				for ch := range chs {
					ch.Reject(ssh.Prohibited, "unused")
				}
			}()
		}
	}()
	b, _ := x509.MarshalPKCS8PrivateKey(clientKey)
	path := filepath.Join(t.TempDir(), "key")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0600)
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	node := common.Map{"host": "127.0.0.1", "ssh": common.Map{"username": "root", "auth_method": "key", "private_key_path": path, "port": p, "connect_timeout_seconds": 5, "host_key_sha256": ssh.FingerprintSHA256(edSigner.PublicKey())}}
	_ = pub
	r, e := Connect(context.Background(), node)
	if e != nil {
		t.Fatalf("pinned Ed25519 refused on multi-key host: %v", e)
	}
	r.Close()
	common.M(node["ssh"])["host_key_sha256"] = ssh.FingerprintSHA256(ecSigner.PublicKey())
	r, e = Connect(context.Background(), node)
	if e != nil {
		t.Fatalf("pinned ECDSA refused: %v", e)
	}
	r.Close()
	store := filepath.Join(t.TempDir(), "ssh_known_hosts")
	if err := os.WriteFile(store, []byte(knownhosts.Line([]string{listener.Addr().String()}, ecSigner.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	common.M(node["ssh"])["host_key_sha256"] = ""
	r, e = connectWithHostKeys(context.Background(), node, store)
	if e != nil {
		t.Fatalf("recorded ECDSA refused on multi-key host: %v", e)
	}
	r.Close()
	common.M(node["ssh"])["host_key_sha256"] = "SHA256:incorrect"
	if r, e = Connect(context.Background(), node); e == nil {
		r.Close()
		t.Fatal("wrong fingerprint accepted")
	}
}
