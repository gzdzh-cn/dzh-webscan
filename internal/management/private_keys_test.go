package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	"webscan/internal/config"
	"webscan/internal/deploy"
)

func fixturePrivateKey(t *testing.T, format string) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	switch format {
	case "openssh":
		block, err = ssh.MarshalPrivateKey(key, "")
	case "encrypted":
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte("fixture-passphrase"))
	default:
		var raw []byte
		raw, err = x509.MarshalPKCS8PrivateKey(key)
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: raw}
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}
func keyEdit(t *testing.T, s *Service, content string) Edit {
	t.Helper()
	c, err := config.Load(s.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	node := common.Map{}
	for _, field := range []string{"id", "name", "host", "enabled", "deployment"} {
		node[field] = c.Nodes[0][field]
	}
	node["ssh"] = common.Map{"username": "root", "port": 22, "auth_method": "key", "private_key_path": "", "password": ""}
	return Edit{Revision: revision(t, s), NodeID: common.S(node["id"]), Node: node, SSHPrivateKeyContent: content}
}
func storedNode(t *testing.T, s *Service) common.Map {
	t.Helper()
	c, e := config.Load(s.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	return c.Nodes[0]
}
func keyFiles(t *testing.T, s *Service) []string {
	t.Helper()
	paths, e := filepath.Glob(filepath.Join(s.StateDir, "ssh-keys", "*"))
	if e != nil {
		t.Fatal(e)
	}
	return paths
}

func TestPrivateKeyPreviewSaveReplaceAndPreserve(t *testing.T) {
	for _, format := range []string{"pem", "openssh"} {
		t.Run(format, func(t *testing.T) {
			s := managerFixture(t)
			key := fixturePrivateKey(t, format)
			edit := keyEdit(t, s, key)
			before, _ := os.ReadFile(s.ConfigPath)
			code, result := request(t, s, "POST", "/settings/preview", edit)
			if code != 200 {
				t.Fatal(result)
			}
			if strings.Contains(string(common.JSON(result)), key) || len(keyFiles(t, s)) != 0 {
				t.Fatal("preview leaked or persisted private key")
			}
			after, _ := os.ReadFile(s.ConfigPath)
			if !bytes.Equal(before, after) {
				t.Fatal("preview modified YAML")
			}
			code, result = request(t, s, "PUT", "/settings", edit)
			if code != 200 {
				t.Fatal(result)
			}
			node := storedNode(t, s)
			path := common.S(common.M(node["ssh"])["private_key_path"])
			data, e := os.ReadFile(path)
			if e != nil || string(data) != key {
				t.Fatal("saved key mismatch", e)
			}
			st, _ := os.Stat(path)
			dir, _ := os.Stat(filepath.Dir(path))
			if st.Mode().Perm() != 0600 || dir.Mode().Perm() != 0700 {
				t.Fatal("unsafe key permissions")
			}
			raw, _ := os.ReadFile(s.ConfigPath)
			if bytes.Contains(raw, []byte("PRIVATE KEY")) {
				t.Fatal("private content persisted in YAML")
			}
			_, settings := request(t, s, "GET", "/settings", nil)
			public := string(common.JSON(settings))
			if strings.Contains(public, key) || strings.Contains(public, path) {
				t.Fatal("key response leak")
			}
			edit = keyEdit(t, s, "")
			if code, res := request(t, s, "PUT", "/settings", edit); code != 200 {
				t.Fatal(res)
			}
			if common.S(common.M(storedNode(t, s)["ssh"])["private_key_path"]) != path {
				t.Fatal("blank edit erased key path")
			}
			replacement := fixturePrivateKey(t, "openssh")
			edit = keyEdit(t, s, replacement)
			if code, res := request(t, s, "PUT", "/settings", edit); code != 200 {
				t.Fatal(res)
			}
			newPath := common.S(common.M(storedNode(t, s)["ssh"])["private_key_path"])
			if newPath == path || len(keyFiles(t, s)) != 2 {
				t.Fatal("replacement overwrote recovery key")
			}
			old, _ := os.ReadFile(path)
			if string(old) != key {
				t.Fatal("old key changed")
			}
			// Backup YAML still references the retained, usable old key.
			rows, e := s.DB.Query("SELECT path FROM config_backups")
			if e != nil {
				t.Fatal(e)
			}
			defer rows.Close()
			found := false
			for rows.Next() {
				var backup string
				rows.Scan(&backup)
				b, _ := os.ReadFile(backup)
				found = found || bytes.Contains(b, []byte(path))
			}
			if !found {
				t.Fatal("no recovery configuration for old key")
			}
		})
	}
}

func TestPrivateKeyInvalidAndFailurePreserveConfiguration(t *testing.T) {
	cases := []struct {
		name, content string
		mutate        func(Edit) Edit
	}{
		{"encrypted", fixturePrivateKey(t, "encrypted"), nil},
		{"public", "ssh-ed25519 AAAA fixture", nil}, {"invalid", "not a key", nil}, {"oversize", strings.Repeat("x", maxPrivateKeyBytes+1), nil},
		{"both", fixturePrivateKey(t, "pem"), func(e Edit) Edit { common.M(e.Node["ssh"])["private_key_path"] = "/root/old-key"; return e }},
		{"password", fixturePrivateKey(t, "pem"), func(e Edit) Edit { common.M(e.Node["ssh"])["auth_method"] = "password"; return e }},
		{"no-node", fixturePrivateKey(t, "pem"), func(e Edit) Edit { e.Node = nil; return e }},
		{"stale", fixturePrivateKey(t, "pem"), func(e Edit) Edit { e.Revision = "old"; return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := managerFixture(t)
			before, _ := os.ReadFile(s.ConfigPath)
			edit := keyEdit(t, s, tc.content)
			if tc.mutate != nil {
				edit = tc.mutate(edit)
			}
			for _, method := range []string{"POST", "PUT"} {
				url := "/settings"
				if method == "POST" {
					url += "/preview"
				}
				code, res := request(t, s, method, url, edit)
				if code == 200 {
					t.Fatal("invalid key accepted")
				}
				if strings.Contains(string(common.JSON(res)), tc.content) {
					t.Fatal("invalid secret echoed")
				}
			}
			after, _ := os.ReadFile(s.ConfigPath)
			if !bytes.Equal(before, after) || len(keyFiles(t, s)) != 0 {
				t.Fatal("failed validation mutated configuration")
			}
		})
	}
	for _, kind := range []string{"symlink-dir", "unsafe-dir", "backup-failure"} {
		t.Run(kind, func(t *testing.T) {
			s := managerFixture(t)
			before, _ := os.ReadFile(s.ConfigPath)
			target := t.TempDir()
			path := filepath.Join(s.StateDir, "ssh-keys")
			switch kind {
			case "symlink-dir":
				os.Symlink(target, path)
			case "unsafe-dir":
				os.Mkdir(path, 0755)
			case "backup-failure":
				os.WriteFile(filepath.Join(s.StateDir, "config-backups"), []byte("blocked"), 0600)
			}
			code, _ := request(t, s, "PUT", "/settings", keyEdit(t, s, fixturePrivateKey(t, "pem")))
			if code == 200 {
				t.Fatal("unsafe save accepted")
			}
			after, _ := os.ReadFile(s.ConfigPath)
			entries, _ := os.ReadDir(target)
			if !bytes.Equal(before, after) || len(entries) != 0 || len(keyFiles(t, s)) != 0 {
				t.Fatal("failed save modified files")
			}
		})
	}
}

func TestPrivateKeyCommitFailureAndTargetSymlink(t *testing.T) {
	s := managerFixture(t)
	edit := keyEdit(t, s, fixturePrivateKey(t, "pem"))
	path := s.newPrivateKeyPath(edit)
	after, _, e := prepareWithKeyPath(s.ConfigPath, edit, path)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(s.ConfigPath)
	// Reject YAML replacement after the key has been written, then clean only
	// this request's unreferenced key.
	original := s.ConfigPath
	s.ConfigPath = filepath.Join(filepath.Dir(original), "linked.yaml")
	os.Symlink(original, s.ConfigPath)
	if e = s.commitConfig(before, after, edit, path, "编辑前"); e == nil {
		t.Fatal("symlink config replaced")
	}
	if len(keyFiles(t, s)) != 0 {
		t.Fatal("unreferenced key not cleaned")
	}
	s.ConfigPath = original
	os.MkdirAll(filepath.Join(s.StateDir, "ssh-keys"), 0700)
	target := filepath.Join(t.TempDir(), "existing")
	os.WriteFile(target, []byte("unchanged"), 0600)
	os.Symlink(target, path)
	if _, e = s.writePrivateKey(path, edit.SSHPrivateKeyContent); e == nil {
		t.Fatal("symlink key replaced")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "unchanged" {
		t.Fatal("target modified")
	}
}

func TestPrivateKeySavedJobFailureRetainsKeyAndNoPayload(t *testing.T) {
	s := managerFixture(t)
	s.execute = func(context.Context, string, string, string) error { return errors.New("fixture deployment failed") }
	edit := keyEdit(t, s, fixturePrivateKey(t, "pem"))
	code, res := request(t, s, "POST", "/jobs", Start{Key: "private-key-job", Revision: edit.Revision, Kind: "add-node", Node: edit.NodeID, Edit: &edit})
	if code != 202 {
		t.Fatal(res)
	}
	id := common.S(res["id"])
	deadline := time.Now().Add(3 * time.Second)
	for {
		var status string
		s.DB.QueryRow("SELECT status FROM jobs WHERE id=?", id).Scan(&status)
		if status == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	path := common.S(common.M(storedNode(t, s)["ssh"])["private_key_path"])
	b, e := os.ReadFile(path)
	if e != nil || string(b) != edit.SSHPrivateKeyContent {
		t.Fatal("committed key lost after deployment failure")
	}
	_, details := request(t, s, "GET", "/jobs/"+id, nil)
	if strings.Contains(string(common.JSON(details)), edit.SSHPrivateKeyContent) {
		t.Fatal("job leaked payload")
	}
	// A duplicate job submission must not create another key or task.
	if code, _ = request(t, s, "POST", "/jobs", Start{Key: "private-key-job", Revision: edit.Revision, Kind: "add-node", Node: edit.NodeID, Edit: &edit}); code != 200 || len(keyFiles(t, s)) != 1 {
		t.Fatal("duplicate request rewrote key")
	}
}

func TestSavedPrivateKeyConnectsToIsolatedSSH(t *testing.T) {
	s := managerFixture(t)
	edit := keyEdit(t, s, fixturePrivateKey(t, "openssh"))
	if code, res := request(t, s, "PUT", "/settings", edit); code != 200 {
		t.Fatal(res)
	}
	client, _ := ssh.ParsePrivateKey([]byte(edit.SSHPrivateKeyContent))
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "root" || !bytes.Equal(key.Marshal(), client.PublicKey().Marshal()) {
			return nil, errors.New("unexpected key")
		}
		return nil, nil
	}}
	cfg.AddHostKey(host)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		server, channels, requests, e := ssh.NewServerConn(conn, cfg)
		if e != nil {
			conn.Close()
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for ch := range channels {
			ch.Reject(ssh.Prohibited, "fixture")
		}
	}()
	node := storedNode(t, s)
	node["host"] = "127.0.0.1"
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	c := common.M(node["ssh"])
	c["port"] = p
	c["connect_timeout_seconds"] = 2
	c["host_key_sha256"] = ssh.FingerprintSHA256(host.PublicKey())
	remote, e := deploy.Connect(context.Background(), node)
	if e != nil {
		t.Fatal(e)
	}
	remote.Close()
}

func TestPrivateKeyNewNodeAndInheritedPath(t *testing.T) {
	s := managerFixture(t)
	edit := keyEdit(t, s, fixturePrivateKey(t, "pem"))
	edit.NodeID = ""
	edit.Node["id"] = "new-private-node"
	edit.Node["host"] = "198.51.100.99"
	edit.Node["deployment"] = common.Map{"mode": "native"}
	edit.Node["enabled"] = false
	if code, res := request(t, s, "PUT", "/settings", edit); code != 200 {
		t.Fatal(res)
	}
	c, e := config.Load(s.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, node := range c.Nodes {
		if common.S(node["id"]) == "new-private-node" {
			found = true
			key := common.S(common.M(node["ssh"])["private_key_path"])
			b, e := os.ReadFile(key)
			if e != nil || string(b) != edit.SSHPrivateKeyContent {
				t.Fatal("new node key not saved")
			}
		}
	}
	if !found {
		t.Fatal("new node not added")
	}
	// A redacted form cannot echo an inherited key path. An empty edit must keep
	// the effective path rather than overriding it with an empty YAML value.
	for _, raw := range common.A(c.Raw["nodes"]) {
		node := common.M(raw)
		if common.S(node["id"]) == "new-private-node" {
			delete(common.M(node["ssh"]), "private_key_path")
		}
	}
	common.M(common.M(c.Raw["node_defaults"])["ssh"])["private_key_path"] = "/root/inherited-key"
	b, e := yaml.Marshal(c.Raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(s.ConfigPath, b, 0600); e != nil {
		t.Fatal(e)
	}
	edit.Revision = revision(t, s)
	edit.NodeID = "new-private-node"
	edit.SSHPrivateKeyContent = ""
	if code, res := request(t, s, "PUT", "/settings", edit); code != 200 {
		t.Fatal(res)
	}
	c, e = config.Load(s.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range c.Nodes {
		if common.S(n["id"]) == edit.NodeID && common.S(common.M(n["ssh"])["private_key_path"]) != "/root/inherited-key" {
			t.Fatal("inherited key lost")
		}
	}
}

func TestRedactedPrivateKeyConfiguredFlagIsStable(t *testing.T) {
	for i := 0; i < 100; i++ {
		out := Redact(common.Map{"ssh": common.Map{"private_key_path": "/root/private", "password": "fixture"}})
		ssh := common.M(out["ssh"])
		if ssh["private_key_path"] != "" || ssh["private_key_path_configured"] != true || ssh["password_configured"] != true {
			t.Fatal("redaction erased configured flag")
		}
	}
}

func TestPrivateKeyCommitRejectsChangedConfiguration(t *testing.T) {
	s := managerFixture(t)
	edit := keyEdit(t, s, fixturePrivateKey(t, "pem"))
	path := s.newPrivateKeyPath(edit)
	after, _, e := prepareWithKeyPath(s.ConfigPath, edit, path)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(s.ConfigPath)
	updated := append([]byte("# external edit\n"), before...)
	os.WriteFile(s.ConfigPath, updated, 0600)
	if e = s.commitConfig(before, after, edit, path, "编辑前"); e == nil {
		t.Fatal("concurrent change overwritten")
	}
	current, _ := os.ReadFile(s.ConfigPath)
	if !bytes.Equal(current, updated) || len(keyFiles(t, s)) != 0 {
		t.Fatal("concurrent YAML or files modified")
	}
}
