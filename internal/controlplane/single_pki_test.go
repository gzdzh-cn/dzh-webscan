package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/nodepki"
)

func prepareSinglePKIFixture(t *testing.T) (singleInstallSpec, string, time.Time) {
	t.Helper()
	s := singleSpecFixture(t)
	s.Format = 2
	binary := []byte("synthetic isolated single-pki fixture")
	if err := prepareSingleInstallation(context.Background(), s, binary, "isolated-password-123", "/usr/bin/docker"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(s.Root, "state"), 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := initializeSinglePKI(context.Background(), s, now); err != nil {
		t.Fatal(err)
	}
	return s, digest(binary), now
}

func TestSinglePKINodeSigningCannotBlockLocalTrustOrBootstrap(t *testing.T) {
	for _, scenario := range []string{"database-down", "partial-signing", "uninitialized", "local-trust-failed"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, now := prepareSinglePKIFixture(t)
			if scenario == "local-trust-failed" {
				if err := os.Remove(filepath.Join(s.Root, "authority", "ca.key")); err != nil {
					t.Fatal(err)
				}
			}
			called := 0
			worker := func(context.Context, singleInstallSpec) (nodeRenewalSigningResult, error) {
				called++
				if scenario == "partial-signing" {
					return nodeRenewalSigningResult{Signed: 1, Failed: 1}, nil
				}
				return nodeRenewalSigningResult{}, errors.New("synthetic-private-database-credential")
			}
			r, err := maintainSinglePKICycle(context.Background(), s, now, scenario != "uninitialized", worker)
			if scenario == "local-trust-failed" {
				if err == nil || r.State != "failed" || called != 0 {
					t.Fatal("broken local trust allowed startup/signing", err)
				}
				return
			}
			if err != nil || r.State != "healthy" {
				t.Fatal("node signing created a database/center boot cycle", err)
			}
			if scenario == "uninitialized" {
				if called != 0 || r.NodeRenewals != nil {
					t.Fatal("bootstrap tried PostgreSQL before its checkpoint")
				}
			} else if called != 1 || r.NodeRenewals == nil || r.NodeRenewals.State != map[string]string{"database-down": "deferred", "partial-signing": "failed"}[scenario] || r.NodeRenewals.Error == "" {
				t.Fatal("independent signing failure hidden", r)
			}
			raw, err := os.ReadFile(filepath.Join(s.Root, "state", "pki-maintenance.json"))
			var persisted singlePKIReceipt
			if err != nil || json.Unmarshal(raw, &persisted) != nil || persisted.State != "healthy" || bytes.Contains(raw, []byte("synthetic-private-database-credential")) {
				t.Fatal("maintenance result missing or leaked", err)
			}
		})
	}
}

func TestSinglePKIManagedInstallRenewalKeepsManifestAndOldIdentity(t *testing.T) {
	s, bin, now := prepareSinglePKIFixture(t)
	ctx := context.Background()
	c := s.configuration()
	if c.Collector.IdentityFile == "" || c.Collector.CertFile != "" || c.Collector.KeyFile != "" {
		t.Fatal("not using managed identity")
	}
	_, before, err := nodepki.ReadIdentity(c.Collector.CAFile, c.Collector.IdentityFile, nodepki.Collector, s.Instance, now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := maintainSinglePKI(ctx, s, now)
	if err != nil || first.State != "healthy" || first.Identity.Changed {
		t.Fatal("unnecessary renewal", err)
	}
	advanced := now.Add(24 * 24 * time.Hour)
	next, err := maintainSinglePKI(ctx, s, advanced)
	if err != nil || !next.Identity.Changed || next.Identity.CertificateSHA256 == before.CertificateSHA256 || !next.Identity.ExpiresAt.After(before.ExpiresAt) {
		t.Fatal("scheduled renewal", err)
	}
	if _, err := readSingleInstallation(s, bin); err != nil {
		t.Fatal("rotation broke immutable resume", err)
	}
	if _, err := os.Stat(c.Collector.IdentityFile + ".history/" + before.CertificateSHA256 + ".pem"); err != nil {
		t.Fatal("missing prior key", err)
	}
	if err := initializeSinglePKI(ctx, s, advanced); err != nil {
		t.Fatal("initialization resume lowered identity", err)
	}
	_, current, err := nodepki.ReadIdentity(c.Collector.CAFile, c.Collector.IdentityFile, nodepki.Collector, s.Instance, advanced)
	if err != nil || current.CertificateSHA256 != next.Identity.CertificateSHA256 {
		t.Fatal("bootstrap replaced live key", err)
	}
	if err := verifySinglePKI(s, advanced); err != nil {
		t.Fatal("verification", err)
	}
	raw, _ := os.ReadFile(filepath.Join(s.Root, "state", "pki-maintenance.json"))
	if bytes.Contains(raw, []byte("PRIVATE")) || bytes.Contains(raw, []byte("BEGIN")) {
		t.Fatal("private receipt")
	}
}

func TestSinglePKIFailureDoesNotResetStateAndRecordsFailure(t *testing.T) {
	for _, kind := range []string{"identity-corrupt", "identity-link", "identity-public", "source-crl-corrupt", "authority-key-missing", "floor-missing", "floor-corrupt", "binding-other-id"} {
		t.Run(kind, func(t *testing.T) {
			s, bin, now := prepareSinglePKIFixture(t)
			c := s.configuration()
			before, _ := os.ReadFile(c.Collector.IdentityFile)
			switch kind {
			case "identity-corrupt":
				os.WriteFile(c.Collector.IdentityFile, []byte("broken"), 0600)
			case "identity-link":
				os.Rename(c.Collector.IdentityFile, c.Collector.IdentityFile+".original")
				os.Symlink(c.Collector.IdentityFile+".original", c.Collector.IdentityFile)
			case "identity-public":
				os.Chmod(c.Collector.IdentityFile, 0644)
			case "source-crl-corrupt":
				os.WriteFile(c.Collector.RevocationFile, []byte("broken"), 0600)
			case "authority-key-missing":
				os.Remove(filepath.Join(s.Root, "authority", "ca.key"))
			case "floor-missing":
				os.Remove(filepath.Join(c.Collector.RevocationStateDirectory, "ca.crl"))
			case "floor-corrupt":
				os.WriteFile(filepath.Join(c.Collector.RevocationStateDirectory, "ca.crl"), []byte("broken"), 0600)
			case "binding-other-id":
				path := filepath.Join(s.Root, "collector-pki", "binding.json")
				raw, _ := os.ReadFile(path)
				var b singlePKIBinding
				json.Unmarshal(raw, &b)
				b.ID = "other"
				raw, _ = json.Marshal(b)
				os.WriteFile(path, raw, 0600)
			}
			if _, err := maintainSinglePKI(context.Background(), s, now.Add(time.Hour)); err == nil {
				t.Fatal("damaged state accepted")
			}
			if _, err := readSingleInstallation(s, bin); err != nil {
				t.Fatal("failure changed bootstrap", err)
			}
			if kind != "identity-corrupt" {
				after, _ := os.ReadFile(c.Collector.IdentityFile)
				if !bytes.Equal(before, after) {
					t.Fatal("failure changed leaf")
				}
			}
			if kind != "binding-other-id" {
				raw, _ := os.ReadFile(filepath.Join(s.Root, "state", "pki-maintenance.json"))
				var receipt singlePKIReceipt
				if json.Unmarshal(raw, &receipt) != nil || receipt.State != "failed" {
					t.Fatal("last success masked failure")
				}
			}
		})
	}
}

func TestSinglePKILockCancellationAndDowntimeRecovery(t *testing.T) {
	s, _, now := prepareSinglePKIFixture(t)
	lock, err := singlePKILock(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := maintainSinglePKI(ctx, s, now); err == nil {
		t.Fatal("maintenance ignored active writer")
	}
	lock.Close()
	receipt, err := maintainSinglePKI(context.Background(), s, now.Add(31*24*time.Hour))
	if err != nil || receipt.State != "healthy" || !receipt.Identity.Changed {
		t.Fatal("offline expired identity/CRL recovery", err)
	}
}

func TestSinglePKIComposeDirectoryAndSystemdDependency(t *testing.T) {
	s := singleSpecFixture(t)
	s.Format = 2
	var compose struct {
		Services map[string]struct {
			Volumes []struct {
				Source, Target string
				ReadOnly       bool `yaml:"read_only"`
			} `yaml:"volumes"`
		} `yaml:"services"`
	}
	raw := singleCompose(s, "isolated-proof")
	if yaml.Unmarshal(raw, &compose) != nil {
		t.Fatal("bad compose")
	}
	found := false
	for _, v := range compose.Services["central"].Volumes {
		if v.Source == filepath.Join(s.Root, "collector-pki") {
			found = true
			if !v.ReadOnly || v.Target != v.Source {
				t.Fatal("identity directory not read-only")
			}
		}
		for _, forbidden := range []string{"authority", "ca.key", "collector.key", "admin.hash"} {
			if strings.Contains(v.Source, forbidden) {
				t.Fatal("excess credential exposure", v.Source)
			}
		}
	}
	if !found {
		t.Fatal("identity still bound by inode")
	}
	service, timer := singlePKIUnits(s)
	if !bytes.Contains(service, []byte("--action maintain-single-pki")) || !bytes.Contains(service, []byte("ProtectSystem=strict")) || !bytes.Contains(timer, []byte("OnCalendar=hourly")) || !bytes.Contains(timer, []byte("Persistent=true")) {
		t.Fatal("missing scheduled policy")
	}
	if !bytes.Contains(singleUnit(s, "/usr/bin/docker"), []byte("Requires=docker.service "+singleProject(s.Root)+"-pki.service")) {
		t.Fatal("boot can start before certificate maintenance")
	}
}

func TestSinglePKIResumeCannotRecreateMissingFloor(t *testing.T) {
	s, _, now := prepareSinglePKIFixture(t)
	c := s.configuration()
	before, _ := os.ReadFile(c.Collector.IdentityFile)
	if err := os.Remove(filepath.Join(c.Collector.RevocationStateDirectory, "ca.crl")); err != nil {
		t.Fatal(err)
	}
	if err := initializeSinglePKI(context.Background(), s, now.Add(24*24*time.Hour)); err == nil {
		t.Fatal("resume recreated missing durable floor")
	}
	after, _ := os.ReadFile(c.Collector.IdentityFile)
	if !bytes.Equal(before, after) {
		t.Fatal("failed resume changed identity before checking floor")
	}
	if _, err := os.Lstat(filepath.Join(c.Collector.RevocationStateDirectory, "ca.crl")); !os.IsNotExist(err) {
		t.Fatal("missing floor was silently repaired")
	}
}

func TestSinglePKIRevokedCollectorCannotBeRenewed(t *testing.T) {
	s, _, now := prepareSinglePKIFixture(t)
	c := s.configuration()
	before, _ := os.ReadFile(c.Collector.IdentityFile)
	var out bytes.Buffer
	if err := nodepki.Command(context.Background(), nodepki.Options{Action: "revoke", Authority: filepath.Join(s.Root, "authority"), Certificate: filepath.Join(s.Root, "collector.crt")}, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := maintainSinglePKI(context.Background(), s, now.Add(24*24*time.Hour)); err == nil {
		t.Fatal("revoked collector renewed")
	}
	after, _ := os.ReadFile(c.Collector.IdentityFile)
	if !bytes.Equal(before, after) {
		t.Fatal("revoked leaf replaced")
	}
	if verifySinglePKI(s, now.Add(24*24*time.Hour)) == nil {
		t.Fatal("revoked/expired trust accepted by final verification")
	}
}

func TestSinglePKIVerificationRequiresPrivateIssuer(t *testing.T) {
	s, _, now := prepareSinglePKIFixture(t)
	path := filepath.Join(s.Root, "authority", "ca.key")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if verifySinglePKI(s, now) == nil {
		t.Fatal("unmaintainable installation accepted")
	}
}

func TestSinglePKIVerificationCannotRecreateDeletedTrustDirectory(t *testing.T) {
	s, _, now := prepareSinglePKIFixture(t)
	path := s.configuration().Collector.RevocationStateDirectory
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := verifySinglePKI(s, now); err == nil {
		t.Fatal("deleted trust directory accepted")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("verification recreated trust directory")
	}
}

func TestSinglePKITimerFailurePreventsStackActivation(t *testing.T) {
	s, _, _ := prepareSinglePKIFixture(t)
	unitDir, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(unitDir, 0700)
	failed := false
	started := false
	i := singleInstaller{unitDirectory: unitDir, docker: "/usr/bin/docker", run: func(ctx context.Context, command string, args ...string) ([]byte, error) {
		if command == "/usr/bin/docker" {
			return nil, nil
		}
		if command == "systemctl" && len(args) == 3 && args[0] == "enable" {
			if strings.HasSuffix(args[2], "-pki.timer") && !failed {
				failed = true
				return nil, errors.New("deliberate timer activation failure")
			}
			if args[2] == singleProject(s.Root)+".service" {
				started = true
			}
		}
		return nil, nil
	}}
	if err := i.start(context.Background(), s); err == nil || started || !failed {
		t.Fatal("stack activation did not depend on timer", err)
	}
	if err := i.start(context.Background(), s); err != nil || !started {
		t.Fatal("timer failure could not resume", err)
	}
}

// This verifies unit syntax/dependencies, not execution of the sandbox or boot.
func TestSinglePKIActualSystemdUnitVerification(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_SYSTEMD_ANALYZE") != "1" {
		t.Skip("requires explicit isolated systemd validator")
	}
	s, _, _ := prepareSinglePKIFixture(t)
	dir := t.TempDir()
	name := singleProject(s.Root)
	service, timer := singlePKIUnits(s)
	units := map[string][]byte{
		name + ".service":     singleUnit(s, "/bin/true"),
		name + "-pki.service": service,
		name + "-pki.timer":   timer,
		"docker.service":      []byte("[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n"),
	}
	args := []string{"verify", "--man=no"}
	for unit, raw := range units {
		path := filepath.Join(dir, unit)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		args = append(args, path)
	}
	cmd := exec.Command("systemd-analyze", args...)
	cmd.Env = append(os.Environ(), "SYSTEMD_UNIT_PATH="+dir+":", "SYSTEMD_LOG_LEVEL=warning", "SYSTEMD_COLORS=0")
	if raw, err := cmd.CombinedOutput(); err != nil || len(bytes.TrimSpace(raw)) != 0 {
		t.Fatalf("actual systemd unit verification: %v %s", err, raw)
	}
}
