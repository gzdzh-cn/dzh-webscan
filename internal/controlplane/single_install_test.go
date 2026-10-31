package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func singleSpecFixture(t *testing.T) singleInstallSpec {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	s := singleInstallSpec{Format: 1, Root: filepath.Join(parent, "single"), Instance: "central-1", Username: "admin", PublicURL: "https://monitor.example.test",
		RuntimeImage:  "docker.io/gzdzh/webscan-central@sha256:" + strings.Repeat("a", 64),
		PostgresImage: "docker.io/library/postgres@sha256:" + strings.Repeat("b", 64),
		MetricsImage:  "docker.io/victoriametrics/victoria-metrics@sha256:" + strings.Repeat("c", 64)}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	return s
}
func prepareSingleFixture(t *testing.T) (singleInstallSpec, string) {
	t.Helper()
	s := singleSpecFixture(t)
	binary := []byte("explicit synthetic executable fixture")
	if err := prepareSingleInstallation(context.Background(), s, binary, "local-test-password-123", "/usr/bin/docker"); err != nil {
		t.Fatal(err)
	}
	return s, digest(binary)
}

func TestSingleInstallPreviewIsReadOnlyAndStrict(t *testing.T) {
	s := singleSpecFixture(t)
	spec, _ := json.Marshal(s)
	source := filepath.Join(filepath.Dir(s.Root), "request.json")
	if err := os.WriteFile(source, spec, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Command(context.Background(), Options{Action: "preview-single-install", Source: source, Config: "/absent/not-read.yaml"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(s.Root); !os.IsNotExist(err) {
		t.Fatal("preview wrote installation")
	}
	if !strings.Contains(out.String(), `"environment_verified":false`) || !strings.Contains(out.String(), `"fresh_only":true`) {
		t.Fatal(out.String())
	}
	for _, raw := range [][]byte{append(spec, []byte(` {}`)...), []byte(strings.Replace(string(spec), `"format":1`, `"format":1,"format":1`, 1)), []byte(strings.Replace(string(spec), `"format":1`, `"format":1,"password":"must-not-appear"`, 1))} {
		os.WriteFile(source, raw, 0600)
		out.Reset()
		if err := singleInstallCommand(context.Background(), Options{Action: "preview-single-install", Source: source}, &out); err == nil || strings.Contains(fmt.Sprint(err), "must-not-appear") {
			t.Fatal("unsafe request accepted or leaked", err)
		}
	}
}

func TestSingleInstallRejectsMutableImagesPathsAndPorts(t *testing.T) {
	base := singleSpecFixture(t)
	for name, change := range map[string]func(*singleInstallSpec){
		"tag": func(s *singleInstallSpec) { s.RuntimeImage = "gzdzh/webscan-central:latest" },
		"repository": func(s *singleInstallSpec) {
			s.PostgresImage = "docker.io/other/postgres@sha256:" + strings.Repeat("b", 64)
		},
		"relative":   func(s *singleInstallSpec) { s.Root = "relative/single" },
		"escape":     func(s *singleInstallSpec) { s.Root += "/../other" },
		"systemd":    func(s *singleInstallSpec) { s.Root += "/%n" },
		"colliding":  func(s *singleInstallSpec) { s.APIPort = s.MetricsPort },
		"privileged": func(s *singleInstallSpec) { s.PostgresPort = 443 },
		"url":        func(s *singleInstallSpec) { s.PublicURL = "http://monitor.example.test" },
	} {
		t.Run(name, func(t *testing.T) {
			s := base
			change(&s)
			if s.validate() == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
	if base.APIPort != 19444 || base.PostgresPort != 5432 || base.MetricsPort != 8428 {
		t.Fatal("defaults", base)
	}
}

func TestSingleInstallPreservesVersionedPinnedImages(t *testing.T) {
	s := singleSpecFixture(t)
	s.RuntimeImage = strings.Replace(s.RuntimeImage, "@", ":v3.0.0@", 1)
	s.PostgresImage = strings.Replace(s.PostgresImage, "@", ":17.6@", 1)
	s.MetricsImage = strings.Replace(s.MetricsImage, "@", ":v1.128.0@", 1)
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	var compose struct {
		Services map[string]struct{ Image string }
	}
	if err := yaml.Unmarshal(singleCompose(s, "test"), &compose); err != nil {
		t.Fatal(err)
	}
	for service, expected := range map[string]string{"central": s.RuntimeImage, "postgres": s.PostgresImage, "metrics": s.MetricsImage} {
		if compose.Services[service].Image != expected {
			t.Fatal("version or digest dropped", service)
		}
	}
}

func TestSingleInstallPackageIsPrivateAndResumePinsEveryArtifact(t *testing.T) {
	s, bin := prepareSingleFixture(t)
	j, err := readSingleInstallation(s, bin)
	if err != nil || j.Step != 0 {
		t.Fatal(j, err)
	}
	st, _ := os.Stat(s.Root)
	if st.Mode().Perm() != 0700 {
		t.Fatal(st.Mode())
	}
	entries, _ := os.ReadDir(s.Root)
	for _, entry := range entries {
		st, _ := os.Lstat(filepath.Join(s.Root, entry.Name()))
		if st.Mode().Perm()&0077 != 0 {
			t.Fatal("public artifact", entry.Name(), st.Mode())
		}
	}
	config, err := LoadConfig(filepath.Join(s.Root, "config.yaml"))
	if err != nil || config.Central.Topology != "single" || config.Executor.Enabled {
		t.Fatal(err)
	}
	if _, err := CollectorTLS(config); err != nil {
		t.Fatal("real collector TLS rejected", err)
	}
	if err := prepareSingleInstallation(context.Background(), s, []byte("different"), "different-password-123", "/usr/bin/docker"); err == nil {
		t.Fatal("existing package replaced")
	}
	if _, err := readSingleInstallation(s, strings.Repeat("f", 64)); err == nil {
		t.Fatal("different program resumed")
	}
	changed := s
	changed.PostgresPort++
	if _, err := readSingleInstallation(changed, bin); err == nil {
		t.Fatal("different saved spec resumed")
	}
	for _, name := range []string{"postgres.dsn", "ca.key", "collector.key", "compose.yaml", "stack.service", "webscan", "admin.hash"} {
		path := filepath.Join(s.Root, name)
		original, _ := os.ReadFile(path)
		os.WriteFile(path, append(append([]byte{}, original...), byte('x')), 0600)
		if _, err := readSingleInstallation(s, bin); err == nil {
			t.Fatal("changed artifact accepted", name)
		}
		os.WriteFile(path, original, 0600)
	}
	if err := saveSingleJournal(s.Root, singleInstallJournal{Format: 1, Manifest: j.Manifest, Step: 3}); err != nil {
		t.Fatal(err)
	}
	if got, err := readSingleInstallation(s, bin); err != nil || got.Step != 3 {
		t.Fatal(got, err)
	}
	for _, raw := range []string{`{"format":1,"step":99}`, `{"format":1,"format":1,"step":0}`} {
		os.WriteFile(filepath.Join(s.Root, "journal.json"), []byte(raw), 0600)
		if _, err := readSingleInstallation(s, bin); err == nil {
			t.Fatal("invalid journal accepted")
		}
	}
}

func TestSingleInstallSymlinkAndHardlinkRejected(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public", "root-link"} {
		t.Run(kind, func(t *testing.T) {
			s, bin := prepareSingleFixture(t)
			if kind == "root-link" {
				old := s.Root + "-original"
				os.Rename(s.Root, old)
				os.Symlink(old, s.Root)
			} else {
				path := filepath.Join(s.Root, "postgres.dsn")
				switch kind {
				case "public":
					os.Chmod(path, 0644)
				case "hardlink":
					os.Link(path, path+"-copy")
				case "symlink":
					os.Rename(path, path+"-original")
					os.Symlink(path+"-original", path)
				}
			}
			if _, err := readSingleInstallation(s, bin); err == nil {
				t.Fatal("unsafe storage accepted")
			}
		})
	}
}

func TestSingleInstallComposeHasNoPublishedDatabaseOrDockerSocket(t *testing.T) {
	s := singleSpecFixture(t)
	raw := singleCompose(s, "installation-proof")
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 3 {
		t.Fatal("missing services")
	}
	for name, service := range doc.Services {
		if service["ports"] != nil || service["network_mode"] != "host" || service["platform"] != "linux/amd64" || service["privileged"] != nil {
			t.Fatal(name, service)
		}
	}
	for _, forbidden := range []string{"docker.sock", "ca.key", "POSTGRES_PASSWORD:", "admin.hash"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("secret/privilege mounted", forbidden)
		}
	}
	if !strings.Contains(string(raw), "127.0.0.1") || !strings.Contains(string(raw), "$$(cat /run/webscan-postgres-password)") {
		t.Fatal(string(raw))
	}
	if os.Getenv("WEBSCAN_V3_TEST_SINGLE_COMPOSE") == "1" {
		path := filepath.Join(filepath.Dir(s.Root), "compose.yaml")
		os.WriteFile(path, raw, 0600)
		cmd := exec.Command("docker", "compose", "--project-name", singleProject(s.Root), "--file", path, "config", "--format", "json")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("real Compose validation: %v %s", err, output)
		}
		var resolved struct {
			Services map[string]struct{ Entrypoint []string }
		}
		if json.Unmarshal(output, &resolved) != nil || !strings.Contains(resolved.Services["postgres"].Entrypoint[2], `$(cat /run/webscan-postgres-password)`) {
			t.Fatal("password-file interpolation changed")
		}
	}
}

func TestSingleInstallUnitPublicationAndConflictingUnitProtection(t *testing.T) {
	s, _ := prepareSingleFixture(t)
	unitDir, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(unitDir, 0700)
	calls := 0
	i := singleInstaller{unitDirectory: unitDir, docker: "/usr/bin/docker", run: func(ctx context.Context, command string, args ...string) ([]byte, error) {
		if command == "/usr/bin/docker" {
			return nil, nil
		} // no existing service objects
		calls++
		if calls == 2 {
			return nil, errors.New("deliberate activation failure containing private-text")
		}
		return nil, nil
	}}
	if err := i.start(context.Background(), s); err == nil || strings.Contains(err.Error(), "private-text") {
		t.Fatal("activation failure", err)
	}
	path := filepath.Join(unitDir, singleProject(s.Root)+".service")
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := i.start(context.Background(), s); err != nil {
		t.Fatal("resume complete unit", err)
	}
	second, _ := os.ReadFile(path)
	if !bytes.Equal(first, second) {
		t.Fatal("unit changed")
	}
	if err := os.WriteFile(path, []byte("another administrator's service"), 0600); err != nil {
		t.Fatal(err)
	}
	before := calls
	if err := i.start(context.Background(), s); err == nil || calls != before {
		t.Fatal("conflicting unit overwritten or activated")
	}
	after, _ := os.ReadFile(path)
	if string(after) != "another administrator's service" {
		t.Fatal("changed original")
	}
	entries, _ := os.ReadDir(unitDir)
	if len(entries) != 1 {
		t.Fatal("temporary unit leak", entries)
	}
}

func TestSingleInstallFailureKeepsExactResumeAndDoesNotLeakToolOutput(t *testing.T) {
	s, bin := prepareSingleFixture(t)
	i := singleInstaller{docker: "docker", run: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("secret-tool-output"), errors.New("secret-tool-error")
	}}
	var out bytes.Buffer
	err := i.resume(context.Background(), s, bin, &out)
	if err == nil || strings.Contains(err.Error()+out.String(), "secret-tool") || !strings.Contains(out.String(), "resume-single-install") {
		t.Fatal(err, out.String())
	}
	j, err := readSingleInstallation(s, bin)
	if err != nil || j.Step != 0 {
		t.Fatal(j, err)
	}
	password, _ := os.ReadFile(filepath.Join(s.Root, "postgres-password"))
	if err := i.resume(context.Background(), s, bin, &out); err == nil {
		t.Fatal("repeat did not fail")
	}
	next, _ := os.ReadFile(filepath.Join(s.Root, "postgres-password"))
	if !bytes.Equal(password, next) {
		t.Fatal("failure regenerated database password")
	}
}

func TestSingleInstallContainerIdentityChecks(t *testing.T) {
	s, _ := prepareSingleFixture(t)
	bin, _ := os.ReadFile(filepath.Join(s.Root, "webscan"))
	for _, kind := range []string{"valid", "containerd", "containerd-other-manifest", "containerd-other-platform", "containerd-other-reference", "other-image", "other-label", "other-config", "other-network", "stopped", "multiple"} {
		t.Run(kind, func(t *testing.T) {
			i := singleInstaller{docker: "docker", run: func(ctx context.Context, command string, args ...string) ([]byte, error) {
				joined := strings.Join(args, " ")
				switch {
				case strings.Contains(joined, "ps --all --quiet"):
					if kind == "multiple" {
						return []byte("abcdef012345\nabcdef123456"), nil
					}
					return []byte("abcdef012345"), nil
				case strings.HasPrefix(joined, "inspect "):
					label := digest([]byte(s.Root + digest(bin) + s.Instance))
					image := "sha256:" + strings.Repeat("d", 64)
					hash := "expected-config"
					network := "host"
					if kind == "other-image" {
						image = "other"
					}
					if kind == "other-label" {
						label = "other"
					}
					if kind == "other-config" {
						hash = "other"
					}
					if kind == "other-network" {
						network = "bridge"
					}
					ref := s.RuntimeImage
					var descriptor any
					if strings.HasPrefix(kind, "containerd") {
						image = s.RuntimeImage[strings.LastIndex(s.RuntimeImage, "@")+1:]
						selected, arch := "sha256:"+strings.Repeat("d", 64), "amd64"
						if kind == "containerd-other-manifest" {
							selected = "sha256:" + strings.Repeat("e", 64)
						}
						if kind == "containerd-other-platform" {
							arch = "arm64"
						}
						if kind == "containerd-other-reference" {
							ref = "other@" + image
						}
						descriptor = map[string]any{"digest": selected, "platform": map[string]string{"os": "linux", "architecture": arch}}
					}
					raw, _ := json.Marshal([]any{map[string]any{"Image": image, "ImageManifestDescriptor": descriptor, "State": map[string]any{"Running": kind != "stopped"}, "HostConfig": map[string]string{"NetworkMode": network}, "Config": map[string]any{"Image": ref, "Labels": map[string]string{"io.webscan.single-install": label, "com.docker.compose.project": singleProject(s.Root), "com.docker.compose.service": "central", "com.docker.compose.config-hash": hash}}}})
					return raw, nil
				case strings.Contains(joined, "image inspect"):
					return []byte("sha256:" + strings.Repeat("d", 64)), nil
				case strings.Contains(joined, "config --hash"):
					return []byte("central expected-config"), nil
				default:
					return nil, errors.New("unexpected test command")
				}
			}}
			err := i.checkContainers(context.Background(), s, []string{"central"}, true)
			if (err == nil) != (kind == "valid" || kind == "containerd") {
				t.Fatal("identity guard", err)
			}
		})
	}
}

func TestSingleInstallHealthRejectsRedirectAndWaitCancels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://example.test", 302) }))
	defer server.Close()
	if singleHTTPHealth(context.Background(), server.URL) == nil {
		t.Fatal("redirect accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if singleWait(ctx, func(context.Context) error { return errors.New("unavailable") }) == nil || time.Since(started) > time.Second {
		t.Fatal("cancelled wait hung")
	}
	problem := singleInstallProblem{"database-readiness", "database unavailable"}
	err := singleWait(ctx, func(context.Context) error { return problem })
	var reason singleInstallProblem
	if !errors.Is(err, context.Canceled) || !errors.As(err, &reason) || reason.Code != problem.Code {
		t.Fatal("readiness wait lost cancellation or safe failure reason", err)
	}
}

func TestSingleInstallDatabaseAccountResumeProtectsExistingPassword(t *testing.T) {
	store := testStore(t)
	s := singleSpecFixture(t)
	os.Mkdir(s.Root, 0700)
	os.WriteFile(filepath.Join(s.Root, "postgres.dsn"), environmentDSN(t, store), 0600)
	hash, err := bcrypt.GenerateFromPassword([]byte("first-password-123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(s.Root, "admin.hash"), hash, 0600)
	for n := 0; n < 2; n++ {
		if err := singleInstallAccount(context.Background(), s); err != nil {
			t.Fatal("resume", err)
		}
	}
	var count int
	store.DB.QueryRow(`SELECT count(*) FROM v3_accounts`).Scan(&count)
	if count != 1 {
		t.Fatal("duplicate accounts", count)
	}
	if err := store.ResetPassword(context.Background(), "admin", "changed-password-123"); err != nil {
		t.Fatal(err)
	}
	if err := singleInstallAccount(context.Background(), s); err == nil {
		t.Fatal("resume silently reset changed password")
	}
	var got string
	store.DB.QueryRow(`SELECT password_hash FROM v3_accounts WHERE username='admin'`).Scan(&got)
	if bcrypt.CompareHashAndPassword([]byte(got), []byte("changed-password-123")) != nil {
		t.Fatal("existing password lost")
	}
	if err := os.WriteFile(filepath.Join(s.Root, "admin.hash"), []byte(got), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`INSERT INTO v3_schema(version) VALUES($1)`, SchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := singleInstallAccount(context.Background(), s); err == nil {
		t.Fatal("account phase accepted a changed database schema")
	}
}
