package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestDeploymentSSHPinnedConnectionUsingEncryptedCredential(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.PutNode(ctx, nodeFixture("node-a"), 0, 256); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if conn.User() != "root" || string(password) != credentialFixture().Password {
			return nil, ErrCredentialUnavailable
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				conn, channels, requests, err := ssh.NewServerConn(raw, config)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					channel.Reject(ssh.Prohibited, "no shell in fixture")
				}
			}()
		}
	}()
	defer func() { listener.Close(); <-done; wg.Wait() }()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	c := credentialFixture()
	c.Host = host
	c.Port = p
	c.Fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
	v, _ := testVault(t)
	raw, err := s.AddCredential(ctx, v, "admin", "ssh-fixture", "node-a", 1, c)
	if err != nil {
		t.Fatal(err)
	}
	var id struct {
		ID string `json:"id"`
	}
	json.Unmarshal(raw, &id)
	in := DeploymentRequest{Node: "node-a", Kind: "install", Expected: 1, Credential: id.ID, Release: "v3.0.0", SHA256: strings.Repeat("a", 64)}
	createDeployment(t, s, in, "one")
	j := claimDeployment(t, s, "ssh-one")
	remote, err := s.ConnectDeploymentSSH(ctx, v, j)
	if err != nil {
		t.Fatal(err)
	}
	if remote.Fingerprint != c.Fingerprint {
		remote.Close()
		t.Fatal("host identity")
	}
	remote.Close()
	// Rebind a credential with the wrong verified fingerprint to a fresh task.
	if err = s.FailDeployment(ctx, j, "preflight-failed"); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	c.Fingerprint = credentialFixture().Fingerprint
	raw, err = s.AddCredential(ctx, v, "admin", "wrong-pin", "node-a", 1, c)
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(raw, &id)
	in.Credential = id.ID
	createDeployment(t, s, in, "two")
	j = claimDeployment(t, s, "ssh-two")
	if remote, err = s.ConnectDeploymentSSH(ctx, v, j); err == nil {
		remote.Close()
		t.Fatal("wrong pin accepted")
	}
	if strings.Contains(err.Error(), c.Password) {
		t.Fatal("SSH error leaked password")
	}
	if _, err = s.DB.Exec("UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if remote, err = s.ConnectDeploymentSSH(ctx, v, j); err == nil {
		remote.Close()
		t.Fatal("expired job connected")
	}
}
