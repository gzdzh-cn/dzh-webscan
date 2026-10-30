package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/nodepki"
)

type configurationLocalFixture struct {
	c         Config
	v         *Vault
	now       time.Time
	authority *nodepki.Authority
	collector nodepki.Bundle
	crl       []byte
	f         trustToolFixture
}

func newConfigurationLocalFixture(t *testing.T) configurationLocalFixture {
	t.Helper()
	f := configurationLocalFixture{c: configurationBootstrapFixture(t), now: time.Now().UTC().Truncate(time.Second), f: newTrustToolFixture(t)}
	f.c.DeploymentTrust = f.f.config()
	var err error
	f.v, err = OpenVault(f.c.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	f.authority, err = nodepki.NewAuthority(f.now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := f.authority.Export()
	if err != nil {
		t.Fatal(err)
	}
	f.collector, err = f.authority.Issue(nodepki.Collector, "collector-local", nil, f.now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.crl, err = f.authority.Revoke(nil, nil, f.now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.c.Database.DSNFile = filepath.Join(f.f.root, "postgres.dsn")
	f.c.Collector.CAFile = filepath.Join(f.f.root, "ca.crt")
	f.c.Collector.CertFile = filepath.Join(f.f.root, "collector.crt")
	f.c.Collector.KeyFile = filepath.Join(f.f.root, "collector.key")
	f.c.Collector.RevocationFile = filepath.Join(f.f.root, "ca.crl")
	f.c.Collector.RevocationStateDirectory = filepath.Join(f.f.root, "collector-state")
	f.c.Central.ExportDirectory = filepath.Join(f.f.root, "exports")
	f.c.Metrics.SpoolDir = filepath.Join(f.f.root, "spool")
	f.c.Executor = ExecutorConfig{Enabled: true, ConfigurationDirectory: filepath.Join(f.f.root, "node-configurations")}
	f.c.NodePKI = NodePKIConfig{Enabled: true, AuthorityDirectory: filepath.Join(f.f.root, "issuer")}
	for _, dir := range []string{f.c.Collector.RevocationStateDirectory, f.c.Central.ExportDirectory, f.c.Metrics.SpoolDir, f.c.Executor.ConfigurationDirectory, f.c.NodePKI.AuthorityDirectory} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range map[string][]byte{
		f.c.Database.DSNFile: []byte("postgres://local-user:private-dsn-password@192.0.2.17:5432/no-connection?sslmode=disable"),
		f.c.Collector.CAFile: ca.CA, f.c.Collector.CertFile: f.collector.Certificate, f.c.Collector.KeyFile: f.collector.Key, f.c.Collector.RevocationFile: f.crl,
		filepath.Join(f.c.Collector.RevocationStateDirectory, "ca.crt"): ca.CA,
		filepath.Join(f.c.Collector.RevocationStateDirectory, "ca.crl"): f.crl,
		filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crt"):         ca.CA,
		filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key"):         ca.Key,
		filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"):         f.crl,
	} {
		localWrite(t, name, raw)
	}
	server, err := f.authority.Issue(nodepki.Node, "console-local", []string{"monitor.example.test"}, f.now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.c.Central.CertFile = filepath.Join(f.f.root, "server.crt")
	f.c.Central.KeyFile = filepath.Join(f.f.root, "server.key")
	localWrite(t, f.c.Central.CertFile, server.Certificate)
	localWrite(t, f.c.Central.KeyFile, server.Key)
	if err := f.c.Validate(); err != nil {
		t.Fatal(err)
	}
	return f
}

func localWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f configurationLocalFixture) document(t *testing.T) configurationDocument {
	t.Helper()
	d, err := newConfigurationDocument(f.c, []byte(`{}`), 1, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func localReportCheck(t *testing.T, r configurationLocalReport, component string) configurationLocalCheck {
	t.Helper()
	for _, c := range r.Checks {
		if c.Component == component {
			return c
		}
	}
	t.Fatalf("missing component %s", component)
	return configurationLocalCheck{}
}

func localTree(t *testing.T, root string) map[string]string {
	t.Helper()
	r := map[string]string{}
	err := filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		value := fmt.Sprintf("%v %d %d", st.Mode(), st.Size(), st.ModTime().UnixNano())
		if st.Mode().IsRegular() {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			value += " " + digest(b)
		}
		r[path] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestConfigurationRestoreLocalReadOnlyPrivateAndNoConnections(t *testing.T) {
	f := newConfigurationLocalFixture(t)
	// Every configured network destination is a local tripwire. The method
	// does not use a dialer; even DSN syntax is deliberately a later phase.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f.c.Metrics.WriteURL = "http://" + l.Addr().String()
	f.c.Metrics.QueryURL = f.c.Metrics.WriteURL
	localWrite(t, f.c.Database.DSNFile, []byte("postgres://user:private-dsn-password@"+l.Addr().String()+"/test?sslmode=disable"))
	before := localTree(t, f.f.root)
	r, err := checkConfigurationLocalMaterial(context.Background(), f.document(t), f.v, f.now)
	if err != nil || !r.LocalChecksPassed || !r.RequiresApplyChecks || len(r.Checks) != 10 {
		t.Fatal("local material rejected", err, r)
	}
	for _, c := range r.Checks {
		if c.Status != "passed" {
			t.Fatal("unexpected non-pass", c)
		}
	}
	if !reflect.DeepEqual(before, localTree(t, f.f.root)) {
		t.Fatal("read-only check modified local material")
	}
	listener := l.(*net.TCPListener)
	listener.SetDeadline(time.Now().Add(20 * time.Millisecond))
	if conn, e := listener.Accept(); e == nil {
		conn.Close()
		t.Fatal("local inspection made a network connection")
	}
	raw, _ := json.Marshal(r)
	dsn, _ := os.ReadFile(f.c.Database.DSNFile)
	key, _ := os.ReadFile(f.c.Collector.KeyFile)
	for _, secret := range [][]byte{[]byte(f.f.root), dsn, key, []byte("private-dsn-password"), []byte("collector-local"), []byte("monitor.example.test"), []byte(f.v.active)} {
		if bytes.Contains(raw, secret) {
			t.Fatal("report disclosed local material")
		}
	}
	// A successful old report cannot be consumed as authority. The next read
	// fails on the same path after key replacement, even with unchanged YAML.
	localWrite(t, f.c.Collector.KeyFile, []byte("broken-key"))
	r, err = checkConfigurationLocalMaterial(context.Background(), f.document(t), f.v, f.now)
	if err != nil || r.LocalChecksPassed || localReportCheck(t, r, "collector_tls").Status != "failed" {
		t.Fatal("cached a stale validation", err)
	}
}

func TestConfigurationRestoreLocalRejectsUnsafeFilesAndRetainsOtherResults(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "public-permission", "symlink", "ancestor-symlink", "hardlink", "fifo", "too-large", "relative"} {
		t.Run(kind, func(t *testing.T) {
			f := newConfigurationLocalFixture(t)
			path := f.c.Database.DSNFile
			switch kind {
			case "missing":
				os.Remove(path)
			case "empty":
				localWrite(t, path, []byte(" \n"))
			case "public-permission":
				os.Chmod(path, 0644)
			case "symlink":
				os.Remove(path)
				if e := os.Symlink(f.c.Collector.KeyFile, path); e != nil {
					t.Fatal(e)
				}
			case "ancestor-symlink":
				alias := filepath.Join(f.f.root, "alias")
				if e := os.Symlink(f.f.root, alias); e != nil {
					t.Fatal(e)
				}
				f.c.Database.DSNFile = filepath.Join(alias, "postgres.dsn")
			case "hardlink":
				if e := os.Link(path, filepath.Join(f.f.root, "second-link")); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				os.Remove(path)
				if e := unix.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "too-large":
				localWrite(t, path, bytes.Repeat([]byte("x"), (64<<10)+1))
			case "relative":
				f.c.Database.DSNFile = "postgres.dsn"
			}
			r, e := checkConfigurationLocalMaterial(context.Background(), f.document(t), f.v, f.now)
			if e != nil || r.LocalChecksPassed || localReportCheck(t, r, "database_credentials").Status != "failed" || localReportCheck(t, r, "collector_tls").Status != "passed" || len(r.Checks) != 10 {
				t.Fatal("unsafe file accepted or later checks lost", e, r)
			}
		})
	}
}

func TestConfigurationRestoreLocalCertificateAndRevocationFailures(t *testing.T) {
	for _, kind := range []string{"hostname", "server-key", "server-client-only", "server-expired", "collector-role", "collector-key", "collector-ca", "collector-expired", "revoked", "crl-expired", "crl-missing", "floor-missing", "floor-corrupt", "floor-root", "floor-rollback", "floor-unrevocation", "issuer-key", "issuer-ca", "issuer-crl"} {
		t.Run(kind, func(t *testing.T) {
			f := newConfigurationLocalFixture(t)
			component := "collector_tls"
			switch kind {
			case "hostname":
				f.c.Central.PublicURL = "https://another.example.test"
				component = "central_tls"
			case "server-key":
				localWrite(t, f.c.Central.KeyFile, f.collector.Key)
				component = "central_tls"
			case "server-client-only":
				ca, e := f.authority.Export()
				if e != nil {
					t.Fatal(e)
				}
				root, e := provisioningCertificate(ca.CA)
				if e != nil {
					t.Fatal(e)
				}
				block, _ := pem.Decode(ca.Key)
				signer, e := x509.ParsePKCS8PrivateKey(block.Bytes)
				if e != nil {
					t.Fatal(e)
				}
				original, e := os.ReadFile(f.c.Central.CertFile)
				if e != nil {
					t.Fatal(e)
				}
				leaf, e := provisioningCertificate(original)
				if e != nil {
					t.Fatal(e)
				}
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
				der, e := x509.CreateCertificate(rand.Reader, leaf, root, leaf.PublicKey, signer)
				if e != nil {
					t.Fatal(e)
				}
				localWrite(t, f.c.Central.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
				component = "central_tls"
			case "server-expired":
				f.now = f.now.Add(25 * time.Hour)
				component = "central_tls"
			case "collector-role":
				cert, key, e := configurationLocalPair(f.c.Central.CertFile, f.c.Central.KeyFile)
				if e != nil {
					t.Fatal(e)
				}
				localWrite(t, f.c.Collector.CertFile, cert)
				localWrite(t, f.c.Collector.KeyFile, key)
			case "collector-key":
				localWrite(t, f.c.Collector.KeyFile, []byte("invalid private key"))
			case "collector-ca":
				a, e := nodepki.NewAuthority(f.now, 365*24*time.Hour)
				if e != nil {
					t.Fatal(e)
				}
				b, e := a.Export()
				if e != nil {
					t.Fatal(e)
				}
				localWrite(t, f.c.Collector.CAFile, b.CA)
			case "collector-expired":
				f.now = f.now.Add(25 * time.Hour)
			case "revoked":
				crl, e := f.authority.Revoke(f.crl, [][]byte{f.collector.Certificate}, f.now, time.Hour)
				if e != nil {
					t.Fatal(e)
				}
				localWrite(t, f.c.Collector.RevocationFile, crl)
			case "crl-expired":
				f.now = f.now.Add(24 * time.Hour)
			case "crl-missing":
				os.Remove(f.c.Collector.RevocationFile)
			case "floor-missing":
				os.RemoveAll(f.c.Collector.RevocationStateDirectory)
				component = "collector_revocation_floor"
			case "floor-corrupt":
				localWrite(t, filepath.Join(f.c.Collector.RevocationStateDirectory, "ca.crl"), []byte("invalid"))
				component = "collector_revocation_floor"
			case "floor-root":
				a, e := nodepki.NewAuthority(f.now, 365*24*time.Hour)
				if e != nil {
					t.Fatal(e)
				}
				b, e := a.Export()
				if e != nil {
					t.Fatal(e)
				}
				localWrite(t, filepath.Join(f.c.Collector.RevocationStateDirectory, "ca.crt"), b.CA)
				component = "collector_revocation_floor"
			case "floor-rollback", "floor-unrevocation":
				crl, e := f.authority.Revoke(f.crl, [][]byte{f.collector.Certificate}, f.now, time.Hour)
				if e != nil {
					t.Fatal(e)
				}
				localWrite(t, filepath.Join(f.c.Collector.RevocationStateDirectory, "ca.crl"), crl)
				component = "collector_revocation_floor"
				if kind == "floor-unrevocation" {
					// Advance the clean branch to a higher signed number, but omit
					// the previously accepted revocation. It must still be refused.
					clean, e := f.authority.Revoke(f.crl, nil, f.now, time.Hour)
					if e != nil {
						t.Fatal(e)
					}
					clean, e = f.authority.Revoke(clean, nil, f.now, time.Hour)
					if e != nil {
						t.Fatal(e)
					}
					localWrite(t, f.c.Collector.RevocationFile, clean)
				}
			case "issuer-key":
				localWrite(t, filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key"), f.collector.Key)
				component = "node_issuer"
			case "issuer-ca":
				localWrite(t, filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crt"), f.collector.Certificate)
				component = "node_issuer"
			case "issuer-crl":
				localWrite(t, filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"), []byte("bad"))
				component = "node_issuer"
			}
			before := localTree(t, f.f.root)
			r, e := checkConfigurationLocalMaterial(context.Background(), f.document(t), f.v, f.now)
			if e != nil || r.LocalChecksPassed || localReportCheck(t, r, component).Status != "failed" {
				t.Fatal("invalid trust accepted", e, r)
			}
			if !reflect.DeepEqual(before, localTree(t, f.f.root)) {
				t.Fatal("check initialized or advanced trust state")
			}
		})
	}
}

func TestConfigurationRestoreLocalExpiredAuthenticFloorAndReadOnlyRenewal(t *testing.T) {
	f := newConfigurationLocalFixture(t)
	// The old floor may be expired. A valid renewal can be inspected without
	// publishing it or modifying the on-disk floor.
	f.now = f.now.Add(25 * time.Hour)
	crl, err := f.authority.Revoke(f.crl, nil, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, f.c.Collector.RevocationFile, crl)
	collector, err := f.authority.Issue(nodepki.Collector, "collector-local", nil, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, f.c.Collector.CertFile, collector.Certificate)
	localWrite(t, f.c.Collector.KeyFile, collector.Key)
	f.c.Central.CertFile = ""
	f.c.Central.KeyFile = ""
	f.c.NodePKI.Enabled = false
	before := localTree(t, f.f.root)
	r, err := checkConfigurationLocalMaterial(context.Background(), f.document(t), f.v, f.now)
	if err != nil || !r.LocalChecksPassed || localReportCheck(t, r, "collector_revocation_floor").Status != "passed" {
		t.Fatal("authentic renewal rejected", err, r)
	}
	if !reflect.DeepEqual(before, localTree(t, f.f.root)) {
		t.Fatal("renewal advanced the accepted floor")
	}
}

func TestConfigurationRestoreLocalSignedArtifactsAndVaultContinuity(t *testing.T) {
	for _, kind := range []string{"helper", "native", "image", "signature", "vault", "missing-current-vault", "new-key-only", "rotation-with-old-key", "remove-trust"} {
		t.Run(kind, func(t *testing.T) {
			f := newConfigurationLocalFixture(t)
			component := "deployment_trust"
			switch kind {
			case "helper":
				localWrite(t, f.c.DeploymentTrust.HelperFile, []byte("changed"))
			case "native":
				localWrite(t, f.c.DeploymentTrust.NativeBundleFile, []byte("changed"))
			case "image":
				localWrite(t, f.c.DeploymentTrust.ImageArchiveFile, []byte("changed"))
			case "signature":
				localWrite(t, f.c.DeploymentTrust.SignatureFile, []byte("changed"))
			case "vault":
				localWrite(t, f.c.DeploymentTrust.VaultKeyFile, []byte("broken-key"))
			case "missing-current-vault":
				f.v = nil
				component = "vault_continuity"
			case "new-key-only", "rotation-with-old-key":
				keyDir := filepath.Join(f.f.root, "new-vault")
				if e := VaultCommand(context.Background(), VaultOptions{Action: "init-key", Output: keyDir}, &bytes.Buffer{}); e != nil {
					t.Fatal(e)
				}
				if kind == "rotation-with-old-key" {
					f.c.DeploymentTrust.PreviousKeyFiles = []string{f.c.DeploymentTrust.VaultKeyFile}
				}
				f.c.DeploymentTrust.VaultKeyFile = filepath.Join(keyDir, "vault.key")
				component = "vault_continuity"
			case "remove-trust":
				f.c.DeploymentTrust = DeploymentTrustConfig{}
				f.c.Executor = ExecutorConfig{}
				component = "vault_continuity"
			}
			r, e := checkConfigurationLocalMaterial(context.Background(), f.document(t), f.v, f.now)
			if kind == "rotation-with-old-key" {
				if e != nil || !r.LocalChecksPassed {
					t.Fatal("safe key rotation rejected", e, r)
				}
			} else if e != nil || r.LocalChecksPassed || localReportCheck(t, r, component).Status != "failed" {
				t.Fatal("unsafe material accepted", e, r)
			}
		})
	}
}

func TestConfigurationRestoreLocalDirectoriesAndCancellation(t *testing.T) {
	for _, kind := range []string{"missing", "public", "symlink", "file", "relative", "cancelled", "incomplete"} {
		t.Run(kind, func(t *testing.T) {
			f := newConfigurationLocalFixture(t)
			ctx := context.Background()
			switch kind {
			case "missing":
				os.Remove(f.c.Central.ExportDirectory)
			case "public":
				os.Chmod(f.c.Central.ExportDirectory, 0755)
			case "symlink":
				os.Remove(f.c.Central.ExportDirectory)
				if e := os.Symlink(f.c.Metrics.SpoolDir, f.c.Central.ExportDirectory); e != nil {
					t.Fatal(e)
				}
			case "file":
				os.Remove(f.c.Central.ExportDirectory)
				localWrite(t, f.c.Central.ExportDirectory, []byte("not-a-directory"))
			case "relative":
				f.c.Metrics.SpoolDir = "spool"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			doc := f.document(t)
			if kind == "incomplete" {
				doc.Omitted = []string{"/bootstrap/database/dsn_file"}
				delete(doc.Bootstrap["database"].(map[string]any), "dsn_file")
			}
			r, e := checkConfigurationLocalMaterial(ctx, doc, f.v, f.now)
			if kind == "cancelled" || kind == "incomplete" {
				if e == nil || r.LocalChecksPassed {
					t.Fatal("unusable request succeeded", e, r)
				}
				if kind == "cancelled" && !errors.Is(e, context.Canceled) {
					t.Fatal("lost cancellation", e)
				}
				return
			}
			component := "exports_directory"
			if kind == "relative" {
				component = "metrics_spool_directory"
			}
			if e != nil || r.LocalChecksPassed || localReportCheck(t, r, component).Status != "failed" {
				t.Fatal("unsafe directory accepted", e, r)
			}
			if kind == "missing" {
				if _, e := os.Stat(f.c.Central.ExportDirectory); !os.IsNotExist(e) {
					t.Fatal("check created missing directory")
				}
			}
		})
	}
}

func TestConfigurationRestoreLocalHAKeysAndOptionalComponents(t *testing.T) {
	f := newConfigurationLocalFixture(t)
	f.c.Central.Topology = "ha"
	f.c.HA.Entrypoint = "https://ha.example.test"
	for i := 1; i <= 3; i++ {
		f.c.HA.Members = append(f.c.HA.Members, HAMember{ID: fmt.Sprintf("central-%d", i), Host: fmt.Sprintf("192.0.2.%d", i), PrivateAddress: fmt.Sprintf("10.1.0.%d", i), SSHPort: 22, SSHKeyFile: f.c.Collector.KeyFile})
	}
	r, e := checkConfigurationLocalMaterial(context.Background(), f.document(t), f.v, f.now)
	if e != nil || !r.LocalChecksPassed || localReportCheck(t, r, "ha_ssh_keys").Status != "passed" {
		t.Fatal("valid HA local keys rejected", e, r)
	}
	f.c.HA.Members[1].SSHKeyFile = filepath.Join(f.f.root, "missing-ha.key")
	r, e = checkConfigurationLocalMaterial(context.Background(), f.document(t), f.v, f.now)
	if e != nil || r.LocalChecksPassed || localReportCheck(t, r, "ha_ssh_keys").Status != "failed" {
		t.Fatal("missing HA key accepted", e)
	}
	f.c.Central.Topology = "single"
	f.c.Central.CertFile = ""
	f.c.Central.KeyFile = ""
	f.c.Collector.RevocationFile = ""
	f.c.Collector.RevocationStateDirectory = ""
	f.c.Executor = ExecutorConfig{}
	f.c.NodePKI = NodePKIConfig{}
	f.c.Metrics.SpoolDir = ""
	r, e = checkConfigurationLocalMaterial(context.Background(), f.document(t), f.v, f.now)
	if e != nil || !r.LocalChecksPassed || !r.RequiresApplyChecks {
		t.Fatal("optional legacy components rejected", e, r)
	}
	for _, component := range []string{"central_tls", "collector_revocation", "executor_directory", "node_issuer", "metrics_spool_directory"} {
		if localReportCheck(t, r, component).Status != "not_configured" {
			t.Fatal("unconfigured check claimed as passed", component)
		}
	}
}

func TestConfigurationRestoreLocalIntentRevalidatesAndDoesNotApply(t *testing.T) {
	s := testStore(t)
	f := newConfigurationLocalFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('admin','not-a-login','admin'),('other-admin','not-a-login','admin')`)
	raw, e := s.createConfigurationBackup(ctx, f.v, f.c, "admin", "local-source")
	id := configurationBackupReceiptID(t, raw, e)
	p, e := s.previewConfigurationRestore(ctx, f.v, f.c, "admin", id, configurationRestoreOptions{})
	if e != nil {
		t.Fatal(e)
	}
	raw, e = s.stageConfigurationRestore(ctx, f.v, f.c, "admin", "local-stage", p.Token)
	stage := configurationStageReceipt(t, raw, e)
	before := localTree(t, f.f.root)
	counts := []int{tableCount(t, s, "v3_audit"), tableCount(t, s, "v3_configuration_backups"), tableCount(t, s, "v3_configuration_backup_pins"), tableCount(t, s, "v3_requests")}
	r, e := s.inspectConfigurationRestoreLocal(ctx, f.v, f.c, "admin", stage.ID)
	if e != nil || !r.LocalChecksPassed || !r.RequiresApplyChecks {
		t.Fatal("intent material failed", e, r)
	}
	after := []int{tableCount(t, s, "v3_audit"), tableCount(t, s, "v3_configuration_backups"), tableCount(t, s, "v3_configuration_backup_pins"), tableCount(t, s, "v3_requests")}
	if !reflect.DeepEqual(counts, after) || !reflect.DeepEqual(before, localTree(t, f.f.root)) {
		t.Fatal("inspection wrote state")
	}
	live, _, e := s.configurationRestoreStage(ctx, "admin", stage.ID)
	if e != nil || live.Status != "pending_validation" {
		t.Fatal("inspection falsely applied intent", e)
	}
	if _, e = s.inspectConfigurationRestoreLocal(ctx, f.v, f.c, "other-admin", stage.ID); e == nil {
		t.Fatal("other admin continued owner intent")
	}
	// A changed file at the same configured path is not covered by the document
	// state proof. Local checks must reject it without consuming the intent.
	localWrite(t, f.c.Database.DSNFile, []byte("\n"))
	r, e = s.inspectConfigurationRestoreLocal(ctx, f.v, f.c, "admin", stage.ID)
	if e != nil || r.LocalChecksPassed || localReportCheck(t, r, "database_credentials").Status != "failed" {
		t.Fatal("same-path change was ignored", e, r)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
	if _, e = s.inspectConfigurationRestoreLocal(ctx, f.v, f.c, "admin", stage.ID); e == nil {
		t.Fatal("stale intent inspected using old proof")
	}
}

func TestConfigurationRestoreLocalMalformedBootstrapNoLeak(t *testing.T) {
	f := newConfigurationLocalFixture(t)
	doc := f.document(t)
	doc.Bootstrap["unknown-private-path"] = f.f.root
	r, e := checkConfigurationLocalMaterial(context.Background(), doc, f.v, f.now)
	if e == nil || r.LocalChecksPassed || strings.Contains(e.Error(), f.f.root) {
		t.Fatal("invalid bootstrap accepted or disclosed", e)
	}
}

func TestConfigurationRestoreLocalLowDisk(t *testing.T) {
	root := os.Getenv("WEBSCAN_V3_CONFIGURATION_LOW_DISK_DIRECTORY")
	if root == "" {
		t.Skip("requires a disposable bounded tmpfs; never fill the host disk")
	}
	// Do not make an arbitrary directory pass as the special fixture.
	d, e := trustDirectory(root, true)
	if e != nil {
		t.Fatal("invalid low-disk fixture", e)
	}
	var fs unix.Statfs_t
	e = unix.Fstatfs(int(d.Fd()), &fs)
	d.Close()
	if e != nil || uint64(fs.Bavail)*uint64(fs.Bsize) > 2<<20 {
		t.Fatal("fixture is not a bounded small filesystem", e)
	}
	if e = configurationLocalDirectory(root); e == nil {
		t.Fatal("insufficient reserve accepted")
	}
}
