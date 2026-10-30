package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testVault(t *testing.T) (*Vault, string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateTestDir(t), "master.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(b)), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := OpenVault(path)
	if err != nil {
		t.Fatal(err)
	}
	return v, path
}
func credentialFixture() SSHCredential {
	return SSHCredential{Host: "192.0.2.1", Port: 22, Fingerprint: "SHA256:" + strings.Repeat("A", 43), Password: "isolated-fixture-password"}
}
func addCredential(t *testing.T, s *Store, v *Vault, node string) string {
	t.Helper()
	raw, err := s.AddCredential(context.Background(), v, "admin", "credential-"+token()[:16], node, 1, credentialFixture())
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.ID
}
func TestVaultRejectsInvalidCredentialAndInsecureMasterKey(t *testing.T) {
	v, path := testVault(t)
	c := credentialFixture()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SSHCredential){
		func(c *SSHCredential) { c.Fingerprint = "" }, func(c *SSHCredential) { c.Fingerprint = "SHA256:bad" },
		func(c *SSHCredential) { c.Host = "host\ncommand" }, func(c *SSHCredential) { c.Port = 0 },
		func(c *SSHCredential) { c.PrivateKey = "public key" }, func(c *SSHCredential) { c.Password = "" },
		func(c *SSHCredential) { c.Password = strings.Repeat("a", 4097) },
	} {
		bad := c
		change(&bad)
		if err := bad.validate(); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	c.Password = ""
	c.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	if err = c.validate(); err != nil {
		t.Fatal(err)
	}
	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(private, "fixture", []byte("passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	c.PrivateKey = string(pem.EncodeToMemory(encrypted))
	if err = c.validate(); err == nil {
		t.Fatal("encrypted key accepted")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", c, c), "BEGIN") {
		t.Fatal("formatted credential leaked")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenVault(path); err == nil {
		t.Fatal("insecure key accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenVault(link); err == nil {
		t.Fatal("symlink key accepted")
	}
	if _, _, _, err = (*Vault)(nil).seal("id", "node", 1, credentialFixture()); err == nil {
		t.Fatal("nil vault accepted")
	}
	key, nonce, sealed, err := v.seal("id", "node", 1, credentialFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range []struct {
		id, node, key string
		rev           int64
	}{{"other", "node", key, 1}, {"id", "other", key, 1}, {"id", "node", key, 2}, {"id", "node", "absent", 1}} {
		if _, err = v.open(args.id, args.node, args.key, args.rev, nonce, sealed); !errors.Is(err, ErrCredentialUnavailable) {
			t.Fatal("AAD not checked", err)
		}
	}
	sealed[0] ^= 1
	if _, err = v.open("id", "node", key, 1, nonce, sealed); err == nil {
		t.Fatal("tamper accepted")
	}
}
func TestVaultPostgresEncryptionRotationAndBackup(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	v, oldPath := testVault(t)
	if err := s.PutNode(ctx, nodeFixture("node-a"), 0, 256); err != nil {
		t.Fatal(err)
	}
	c := credentialFixture()
	response, err := s.AddCredential(ctx, v, "admin", "one", "node-a", 1, c)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.AddCredential(ctx, v, "admin", "one", "node-a", 1, c)
	if err != nil || !sameJSON(replay, response) {
		t.Fatal("idempotent replay", string(replay), err)
	}
	c.Password = "a-different-secret"
	if _, err = s.AddCredential(ctx, v, "admin", "one", "node-a", 1, c); !errors.Is(err, ErrRequestConflict) {
		t.Fatal("key reused", err)
	}
	var out struct {
		ID string `json:"id"`
	}
	json.Unmarshal(response, &out)
	if _, err = s.ReadCredential(ctx, v, out.ID, "other-node"); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("node binding", err)
	}
	restored, err := s.ReadCredential(ctx, v, out.ID, "node-a")
	if err != nil || restored.Password != credentialFixture().Password {
		t.Fatal("decrypt", err)
	}
	var all string
	if err = s.DB.QueryRow("SELECT row_to_json(c)::text FROM v3_credentials c").Scan(&all); err != nil || strings.Contains(all, credentialFixture().Password) {
		t.Fatal("plaintext ciphertext", err)
	}
	for _, table := range []string{"v3_requests", "v3_audit"} {
		rows, err := s.DB.Query("SELECT row_to_json(t)::text FROM " + quotePG(table) + " t")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var raw string
			if err = rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(raw, credentialFixture().Password) || strings.Contains(raw, "192.0.2.1") {
				t.Fatal("secret in receipt/audit")
			}
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	_, newPath := testVault(t)
	next, err := OpenVault(newPath, oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RewrapCredential(ctx, next, out.ID, "node-a"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadCredential(ctx, v, out.ID, "node-a"); err == nil {
		t.Fatal("old key decrypted new ciphertext")
	}
	onlyNew, err := OpenVault(newPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadCredential(ctx, onlyNew, out.ID, "node-a"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(snapshot)
	if err != nil || strings.Contains(string(raw), credentialFixture().Password) {
		t.Fatal("secret in backup", err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err = target.ReadCredential(ctx, onlyNew, out.ID, "node-a"); err != nil {
		t.Fatal("restore credentials", err)
	}
	if _, err = s.DB.Exec("UPDATE v3_credentials SET revision=revision+1 WHERE id=$1", out.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadCredential(ctx, onlyNew, out.ID, "node-a"); err == nil {
		t.Fatal("revision tamper accepted")
	}
}
