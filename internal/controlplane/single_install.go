package controlplane

// The fresh single-machine installer is deliberately separate from v2 and
// topology migration. It never adopts a pre-existing database or deployment.
import (
	"bytes"
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"webscan/internal/nodepki"
	"webscan/internal/progress"
)

var errSingleInstall = errors.New("单中心安装资料不匹配、路径不安全或存在已有安装；未覆盖原数据，请核对原请求后继续")

type singleInstallProblem struct{ Code, Hint string }

func (e singleInstallProblem) Error() string { return e.Hint }

type singleInstallSpec struct {
	Backup        *singleInstallBackupPolicy `json:"backup_policy,omitempty"`
	ReleaseTrust  *DeploymentTrustConfig     `json:"deployment_trust,omitempty"`
	RulesFile     string                     `json:"rules_file,omitempty"`
	Format        int                        `json:"format"`
	Root          string                     `json:"root"`
	Instance      string                     `json:"instance"`
	PublicURL     string                     `json:"public_url"`
	Username      string                     `json:"username"`
	APIPort       int                        `json:"api_port"`
	PostgresPort  int                        `json:"postgres_port"`
	MetricsPort   int                        `json:"metrics_port"`
	RuntimeImage  string                     `json:"runtime_image"`
	PostgresImage string                     `json:"postgres_image"`
	MetricsImage  string                     `json:"metrics_image"`
}

type singleInstallBackupPolicy struct {
	Directory string `json:"directory"`
	Keep      int    `json:"keep"`
}

func (s *singleInstallSpec) validate() error {
	if s.Backup != nil {
		if s.Format != 3 || s.Backup.Keep < 1 || s.Backup.Keep > 365 || !singlePKIUpgradePath(s.Backup.Directory) || singleBackupContains(s.Root, s.Backup.Directory) || singleBackupContains(s.Backup.Directory, s.Root) {
			return errSingleInstall
		}
	}
	if s.APIPort == 0 {
		s.APIPort = 19444
	}
	if s.PostgresPort == 0 {
		s.PostgresPort = 5432
	}
	if s.MetricsPort == 0 {
		s.MetricsPort = 8428
	}
	if (s.Format != 1 && s.Format != 2 && s.Format != 3) || !identifier.MatchString(s.Instance) || !identifier.MatchString(s.Username) ||
		!regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`).MatchString(s.Root) || filepath.Clean(s.Root) != s.Root || s.Root == "/" {
		return errSingleInstall
	}
	seen := map[int]bool{}
	for _, p := range []int{s.APIPort, s.PostgresPort, s.MetricsPort} {
		if p < 1024 || p > 65535 || seen[p] {
			return errors.New("三个单中心本机端口须为互不相同的 1024～65535 整数")
		}
		seen[p] = true
	}
	for _, image := range []struct{ value, repository string }{
		{s.RuntimeImage, "docker.io/gzdzh/webscan-central"},
		{s.PostgresImage, "docker.io/library/postgres"},
		{s.MetricsImage, "docker.io/victoriametrics/victoria-metrics"},
	} {
		if !regexp.MustCompile(`^` + regexp.QuoteMeta(image.repository) + `(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})?@sha256:[a-f0-9]{64}$`).MatchString(image.value) {
			return errors.New("单中心镜像须为明确仓库及不可变 SHA256 摘要，不接受 latest 或其他仓库")
		}
	}
	if s.Format == 3 {
		if s.ReleaseTrust == nil || s.RulesFile == "" || !filepath.IsAbs(s.RulesFile) || filepath.Clean(s.RulesFile) != s.RulesFile {
			return errSingleInstall
		}
		t := *s.ReleaseTrust
		t.VaultKeyFile = filepath.Join(s.Root, "vault.key")
		if t.validate() != nil || t.HelperFile == "" || t.NativeBundleFile == "" {
			return errSingleInstall
		}
	} else if s.ReleaseTrust != nil || s.RulesFile != "" {
		return errSingleInstall
	}
	c := s.configuration()
	return c.Validate()
}

func (s singleInstallSpec) configuration() Config {
	var c Config
	c.Version = 3
	c.Central.Topology, c.Central.Instance = "single", s.Instance
	c.Central.Listen, c.Central.PublicURL = fmt.Sprintf("127.0.0.1:%d", s.APIPort), s.PublicURL
	c.Central.ExportDirectory = filepath.Join(s.Root, "state", "exports")
	c.Central.TrustedProxies = []string{"127.0.0.1", "::1"}
	c.Database.DSNFile = filepath.Join(s.Root, "postgres.dsn")
	c.Metrics.WriteURL = fmt.Sprintf("http://127.0.0.1:%d", s.MetricsPort)
	c.Metrics.QueryURL, c.Metrics.SpoolDir = c.Metrics.WriteURL, filepath.Join(s.Root, "state", "metrics-spool")
	c.Collector.CAFile, c.Collector.CertFile, c.Collector.KeyFile = filepath.Join(s.Root, "ca.crt"), filepath.Join(s.Root, "collector.crt"), filepath.Join(s.Root, "collector.key")
	if s.Format >= 2 {
		c.Collector.CAFile = filepath.Join(s.Root, "collector-pki", "ca.crt")
		c.Collector.IdentityFile = filepath.Join(s.Root, "collector-pki", "collector.pem")
		c.Collector.CertFile, c.Collector.KeyFile = "", ""
		c.Collector.RevocationFile = filepath.Join(s.Root, "collector-pki", "ca.crl")
		c.Collector.RevocationStateDirectory = filepath.Join(s.Root, "state", "collector-trust")
	}
	if s.Format == 3 {
		c.DeploymentTrust = DeploymentTrustConfig{VaultKeyFile: filepath.Join(s.Root, "vault.key"), PublicKeyFile: filepath.Join(s.Root, "release.pub"), ManifestFile: filepath.Join(s.Root, "release.json"), SignatureFile: filepath.Join(s.Root, "release.sig")}
		c.Executor = ExecutorConfig{Enabled: true, Mode: "external"}
	}
	return c
}

type singleInstallManifest struct {
	Format int               `json:"format"`
	Spec   singleInstallSpec `json:"spec"`
	Files  map[string]string `json:"files"`
}
type singleInstallJournal struct {
	Format   int    `json:"format"`
	Manifest string `json:"manifest"`
	Step     int    `json:"step"`
}

type singleInstaller struct {
	run           func(context.Context, string, ...string) ([]byte, error)
	unitDirectory string
	docker        string
}

func newSingleInstaller() singleInstaller {
	return singleInstaller{run: func(ctx context.Context, command string, args ...string) ([]byte, error) {
		// Command output may contain credentials from third-party tools. Never
		// propagate it into progress, terminal errors or a task record.
		var output boundedSingleOutput
		cmd := exec.CommandContext(ctx, command, args...)
		cmd.Stdout, cmd.Stderr = &output, io.Discard
		err := cmd.Run()
		return output.Bytes(), err
	}, unitDirectory: "/etc/systemd/system", docker: "docker"}
}

type boundedSingleOutput struct{ bytes.Buffer }

func (b *boundedSingleOutput) Write(p []byte) (int, error) {
	n := len(p)
	if left := (1 << 20) - b.Len(); left > 0 {
		_, _ = b.Buffer.Write(p[:min(left, len(p))])
	}
	return n, nil
}

func singleInstallCommand(ctx context.Context, o Options, out io.Writer) (result error) {
	defer func() {
		// All child output is discarded at the command boundary. These errors
		// are our own safe diagnostics; preserve them in the shared CLI instead
		// of falling through to the legacy generic deployment/resume message.
		if result != nil {
			result = &progress.Failure{Code: "single_center_install_failed", Message: result.Error()}
		}
	}()
	var spec singleInstallSpec
	raw, err := readTrustData(o.Source, true, 64<<10)
	if err != nil {
		return errSingleInstall
	}
	if singleDecode(raw, &spec) != nil {
		return errSingleInstall
	}
	// New installations receive the daily/seven policy once. Original
	// immutable requests and resumes retain the absence or existing policy.
	if o.Action != "resume-single-install" && spec.Format == 3 && spec.Backup == nil {
		spec.Backup = &singleInstallBackupPolicy{Directory: spec.Root + "-backups", Keep: 7}
	}
	if err := spec.validate(); err != nil {
		return err
	}
	if o.Action == "resume-single-install" && spec.Backup == nil {
		// The caller can reuse the original request with omitted defaults. Read
		// only this optional policy from the saved manifest; resume authenticates
		// the entire immutable installation before any service operation.
		installed, err := readTrustData(filepath.Join(spec.Root, "install.json"), true, 64<<10)
		var manifest singleInstallManifest
		if err != nil || singleDecode(installed, &manifest) != nil {
			return errSingleInstall
		}
		spec.Backup = manifest.Spec.Backup
		if err := spec.validate(); err != nil {
			return err
		}
	}
	if o.Topology != "" && o.Topology != "single" {
		return errors.New("此安装入口只支持全新 single，HA 和已有拓扑迁移必须使用专门流程")
	}
	if o.Action == "preview-single-install" {
		return json.NewEncoder(out).Encode(map[string]any{"topology": "single", "fresh_only": true, "root": spec.Root, "public_url": spec.PublicURL, "loopback_ports": []int{spec.APIPort, spec.PostgresPort, spec.MetricsPort}, "services": []string{"postgres", "metrics", "central"}, "requires_existing_https_proxy": true, "environment_verified": false, "backup_policy": spec.Backup})
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errors.New("单中心安装须在 Linux amd64 上以 root 执行")
	}
	installer := newSingleInstaller()
	if installer.docker, err = exec.LookPath("docker"); err != nil {
		return errors.New("需要先安装并启动可用的 Docker 和 Compose；不会重装或重启现有引擎")
	}
	binary, err := os.Executable()
	if err != nil {
		return errSingleInstall
	}
	bin, err := os.ReadFile(binary)
	if err != nil || len(bin) > 256<<20 {
		return errSingleInstall
	}
	e, err := elf.NewFile(bytes.NewReader(bin))
	if err != nil || e.Machine != elf.EM_X86_64 || e.Class != elf.ELFCLASS64 {
		return errSingleInstall
	}
	parent, err := trustDirectory(filepath.Dir(spec.Root), true)
	if err != nil {
		return err
	}
	defer parent.Close()
	lockName := ".single-install-" + digest([]byte(spec.Root))[:16] + ".lock"
	fd, err := unix.Openat(int(parent.Fd()), lockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return errSingleInstall
	}
	lock := os.NewFile(uintptr(fd), lockName)
	defer lock.Close()
	if !singlePrivateFile(lock) || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("该单中心安装正在执行或锁文件不安全")
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	resume := o.Action == "resume-single-install"
	if !resume && spec.Format != 3 {
		return errors.New("新安装请使用 format: 3，以启用外部执行器及共享密钥；旧格式仅允许按原资料继续")
	}
	if err := installer.preflight(ctx, spec, !resume); err != nil {
		return err
	}
	if !resume {
		password, err := ReadSecret(o.PasswordFile)
		if err != nil || len(password) < 12 || len(password) > 72 {
			return errors.New("首次管理员密码须从私有文件读取，长度为 12～72 字节")
		}
		if err := prepareSingleInstallation(ctx, spec, bin, password, installer.docker); err != nil {
			return err
		}
	}
	return installer.resume(ctx, spec, digest(bin), out)
}

func (i singleInstaller) preflight(ctx context.Context, s singleInstallSpec, fresh bool) error {
	for _, probe := range []struct {
		command string
		args    []string
	}{
		{i.docker, []string{"info", "--format", "{{.ServerVersion}}"}}, {i.docker, []string{"compose", "version", "--short"}},
		{"systemctl", []string{"show", "--property=Version", "--value"}},
	} {
		probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		result, err := i.run(probeCtx, probe.command, probe.args...)
		cancel()
		if err != nil || len(bytes.TrimSpace(result)) == 0 {
			return errors.New("Docker、Compose 或 systemd 不可用；请修复已有环境后重试")
		}
	}
	var fs unix.Statfs_t
	if unix.Statfs(filepath.Dir(s.Root), &fs) != nil || uint64(fs.Bavail)*uint64(fs.Bsize) < 2<<30 || fs.Ffree < 1024 {
		return errors.New("单中心安装目录需要至少 2 GiB 可用空间和 1024 个空闲 inode，镜像及长期数据还需额外容量")
	}
	if fresh {
		if _, err := os.Lstat(s.Root); !os.IsNotExist(err) {
			return errSingleInstall
		}
		for _, p := range []int{s.APIPort, s.PostgresPort, s.MetricsPort} {
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				return fmt.Errorf("本机 TCP %d 已占用；不会停止原服务", p)
			}
			_ = l.Close()
		}
	}
	return nil
}

func singleCompose(s singleInstallSpec, label string) []byte {
	volume := func(name, target string, ro bool) map[string]any {
		return map[string]any{"type": "bind", "source": filepath.Join(s.Root, name), "target": target, "read_only": ro, "bind": map[string]any{"create_host_path": false}}
	}
	service := func(image string) map[string]any {
		return map[string]any{"image": image, "platform": "linux/amd64", "network_mode": "host", "restart": "unless-stopped", "labels": map[string]string{"io.webscan.single-install": label}, "logging": map[string]any{"driver": "json-file", "options": map[string]string{"max-size": "10m", "max-file": "3"}}}
	}
	pg := service(s.PostgresImage)
	pg["environment"] = map[string]string{"POSTGRES_DB": "webscan", "POSTGRES_USER": "webscan", "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256 --auth-local=trust"}
	pg["entrypoint"] = []string{"/bin/sh", "-ec", `export POSTGRES_PASSWORD="$$(cat /run/webscan-postgres-password)"; exec /usr/local/bin/docker-entrypoint.sh postgres -h 127.0.0.1 -p ` + strconv.Itoa(s.PostgresPort)}
	pg["volumes"] = []any{volume("postgres-password", "/run/webscan-postgres-password", true), volume("postgres-data", "/var/lib/postgresql/data", false)}
	vm := service(s.MetricsImage)
	vm["command"] = []string{"-httpListenAddr=127.0.0.1:" + strconv.Itoa(s.MetricsPort), "-storageDataPath=/storage", "-retentionPeriod=15d"}
	vm["volumes"] = []any{volume("metrics-data", "/storage", false)}
	central := service(s.RuntimeImage)
	central["entrypoint"] = []string{"/usr/local/bin/webscan"}
	central["command"] = []string{"control-v3", "--config", filepath.Join(s.Root, "config.yaml"), "--action", "run", "--role", "all"}
	central["read_only"], central["cap_drop"], central["security_opt"] = true, []string{"ALL"}, []string{"no-new-privileges:true"}
	central["tmpfs"] = []string{"/tmp:rw,noexec,nosuid,size=64m"}
	volumes := []any{volume("state", filepath.Join(s.Root, "state"), false)}
	if s.Format < 3 {
		volumes = append(volumes, volume("webscan", "/usr/local/bin/webscan", true))
	}
	names := []string{"config.yaml", "postgres.dsn", "ca.crt", "collector.crt", "collector.key"}
	if s.Format >= 2 {
		names = []string{"config.yaml", "postgres.dsn", "collector-pki"}
	}
	if s.Format == 3 {
		names = append(names, "vault.key", "release.pub", "release.json", "release.sig")
	}
	for _, name := range names {
		volumes = append(volumes, volume(name, filepath.Join(s.Root, name), true))
	}
	central["volumes"] = volumes
	raw, _ := yaml.Marshal(map[string]any{"services": map[string]any{"postgres": pg, "metrics": vm, "central": central}})
	return raw
}

func singleProject(root string) string { return "webscan-v3-single-" + digest([]byte(root))[:12] }
func singleUnit(s singleInstallSpec, docker string) []byte {
	dependency := ""
	if s.Format >= 2 {
		dependency = " " + singleProject(s.Root) + "-pki.service"
	}
	return []byte("[Unit]\nDescription=Webscan v3 single-center stack\nRequires=docker.service" + dependency + "\nAfter=docker.service network-online.target" + dependency + "\nWants=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nUMask=0077\nTimeoutStartSec=180\nTimeoutStopSec=90\nExecStart=" + strconv.Quote(docker) + " compose --project-name " + singleProject(s.Root) + " --file " + strconv.Quote(filepath.Join(s.Root, "compose.yaml")) + " up -d --no-recreate --pull never\nExecStop=" + strconv.Quote(docker) + " compose --project-name " + singleProject(s.Root) + " --file " + strconv.Quote(filepath.Join(s.Root, "compose.yaml")) + " stop --timeout 60\n\n[Install]\nWantedBy=multi-user.target\n")
}

func prepareSingleInstallation(ctx context.Context, s singleInstallSpec, binary []byte, password, docker string) error {
	if !filepath.IsAbs(docker) || strings.ContainsAny(docker, "%\r\n\x00") {
		return errSingleInstall
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return errSingleInstall
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := nodepki.NewAuthority(now, 5*365*24*time.Hour)
	if err != nil {
		return err
	}
	caBundle, err := ca.Export()
	if err != nil {
		return err
	}
	defer clear(caBundle.Key)
	collector, err := ca.Issue(nodepki.Collector, s.Instance, nil, now, 30*24*time.Hour)
	if err != nil {
		return err
	}
	defer clear(collector.Key)
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	defer clear(secret[:])
	pgPassword := hex.EncodeToString(secret[:])
	c := s.configuration()
	if err := c.Validate(); err != nil {
		return err
	}
	config, _ := yaml.Marshal(c)
	files := map[string][]byte{"config.yaml": config, "webscan": binary, "postgres-password": []byte(pgPassword), "postgres.dsn": []byte(fmt.Sprintf("postgres://webscan:%s@127.0.0.1:%d/webscan?sslmode=disable", pgPassword, s.PostgresPort)), "admin.hash": passwordHash, "ca.crt": caBundle.CA, "ca.key": caBundle.Key, "collector.crt": collector.Certificate, "collector.key": collector.Key}
	if s.Format >= 2 {
		crl, err := ca.Revoke(nil, nil, now, 24*time.Hour)
		if err != nil {
			return err
		}
		files["seed.crl"] = crl
		files["pki-maintenance.service"], files["pki-maintenance.timer"] = singlePKIUnits(s)
	}
	if s.Format == 3 {
		if err := prepareSingleWebDeployment(ctx, s, files); err != nil {
			return err
		}
	}
	if s.Backup != nil {
		// The destination does not exist until atomic publication. Authenticate
		// the exact in-memory metadata already copied from independent trust.
		trusted, _, err := verifyTrustedReleaseData(files["release.json"], files["release.sig"], files["release.pub"])
		if err != nil {
			return err
		}
		policy := singleBackupSchedule{Format: 1, Spec: singleBackupScheduleSpec{Format: 1, Directory: s.Backup.Directory, Keep: s.Backup.Keep, Request: singleBackupSpec{Format: 1, Installation: filepath.Join(s.Root, "install.json"), HostConfig: filepath.Join(s.Root, "executor.yaml"), APIConfig: filepath.Join(s.Root, "config.yaml"), ComposeFile: filepath.Join(s.Root, "compose.yaml")}}, Helper: filepath.Join(s.Root, "webscan"), Hash: trusted.manifest.Helper.SHA256, Release: trusted.manifest.Release}
		files["backup-schedule.json"], _ = json.Marshal(policy)
		files["backup.service"], files["backup.timer"] = singleBackupScheduleUnits(policy, filepath.Join(s.Root, "backup-schedule.json"))
	}
	label := digest([]byte(s.Root + digest(binary) + s.Instance))
	files["compose.yaml"], files["stack.service"] = singleCompose(s, label), singleUnit(s, docker)
	m := singleInstallManifest{Format: 1, Spec: s, Files: map[string]string{}}
	for name, raw := range files {
		m.Files[name] = digest(raw)
	}
	files["install.json"], _ = json.Marshal(m)
	files["journal.json"], _ = json.Marshal(singleInstallJournal{Format: 1, Manifest: digest(files["install.json"])})
	if err := publishTrustFiles(ctx, s.Root, files); err != nil {
		return err
	}
	// The package is already durable. Any failure below is resumed, never
	// repaired by regenerating credentials or overwriting a previous package.
	return os.Chmod(filepath.Join(s.Root, "webscan"), 0700)
}

func readSingleInstallation(s singleInstallSpec, binaryDigest string) (singleInstallJournal, error) {
	dir, err := trustDirectory(s.Root, true)
	if err != nil {
		return singleInstallJournal{}, err
	}
	dir.Close()
	read := func(name string, v any) ([]byte, error) {
		raw, err := readTrustData(filepath.Join(s.Root, name), true, 64<<10)
		if err != nil {
			return nil, errSingleInstall
		}
		if singleDecode(raw, v) != nil {
			return nil, errSingleInstall
		}
		return raw, nil
	}
	var m singleInstallManifest
	raw, err := read("install.json", &m)
	if err != nil || m.Format != 1 || !reflect.DeepEqual(m.Spec, s) {
		return singleInstallJournal{}, errSingleInstall
	}
	var j singleInstallJournal
	_, err = read("journal.json", &j)
	if err != nil || j.Format != 1 || j.Manifest != digest(raw) || j.Step < 0 || j.Step > 6 {
		return j, errSingleInstall
	}
	names := []string{"config.yaml", "webscan", "postgres-password", "postgres.dsn", "admin.hash", "ca.crt", "ca.key", "collector.crt", "collector.key", "compose.yaml", "stack.service"}
	if s.Format >= 2 {
		names = append(names, "seed.crl", "pki-maintenance.service", "pki-maintenance.timer")
	}
	if s.Format == 3 {
		names = append(names, singleWebDeploymentFiles...)
	}
	if s.Backup != nil {
		names = append(names, "backup-schedule.json", "backup.service", "backup.timer")
	}
	if len(m.Files) != len(names) || m.Files["webscan"] != binaryDigest {
		return j, errSingleInstall
	}
	for _, name := range names {
		raw, err := readTrustData(filepath.Join(s.Root, name), true, 256<<20)
		if err != nil || m.Files[name] != digest(raw) {
			return j, errSingleInstall
		}
	}
	return j, nil
}

func singleDecode(raw []byte, v any) error {
	if uniqueBackupJSON(json.NewDecoder(bytes.NewReader(raw)), 0) != nil {
		return errSingleInstall
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errSingleInstall
	}
	return nil
}

func saveSingleJournal(root string, j singleInstallJournal) error {
	dir, err := trustDirectory(root, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	name := ".journal-" + token()
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errSingleInstall
	}
	f := os.NewFile(uintptr(fd), name)
	defer unix.Unlinkat(int(dir.Fd()), name, 0)
	raw, _ := json.Marshal(j)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil || unix.Renameat(int(dir.Fd()), name, int(dir.Fd()), "journal.json") != nil || dir.Sync() != nil {
		return errSingleInstall
	}
	return nil
}

func singlePrivateFile(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	o, ok := st.Sys().(*syscall.Stat_t)
	return ok && st.Mode().IsRegular() && st.Mode().Perm() == 0600 && o.Uid == uint32(os.Geteuid()) && o.Nlink == 1
}

func (i singleInstaller) compose(ctx context.Context, s singleInstallSpec, args ...string) ([]byte, error) {
	base := []string{"compose", "--project-name", singleProject(s.Root), "--file", filepath.Join(s.Root, "compose.yaml")}
	return i.run(ctx, i.docker, append(base, args...)...)
}

func (i singleInstaller) resume(ctx context.Context, s singleInstallSpec, binaryDigest string, out io.Writer) error {
	j, err := readSingleInstallation(s, binaryDigest)
	if err != nil {
		return err
	}
	// Publication may have succeeded before chmod or the first journal write.
	// Only fix the executable bit after authenticating the complete package.
	if err := os.Chmod(filepath.Join(s.Root, "webscan"), 0700); err != nil {
		return errSingleInstall
	}
	stages := []struct {
		name    string
		execute func(context.Context) error
	}{
		{"校验并准备固定摘要镜像", func(ctx context.Context) error { return i.images(ctx, s) }},
		{"启动本机数据库和时序库", func(ctx context.Context) error { return i.infrastructure(ctx, s) }},
		{"初始化独立 v3 数据库", func(ctx context.Context) error {
			store, err := Open(ctx, s.configuration())
			if err != nil {
				return err
			}
			defer store.DB.Close()
			return store.Migrate(ctx)
		}},
		{"创建首次管理员", func(ctx context.Context) error { return singleInstallAccount(ctx, s) }},
		{"安装开机自启并启动中心", func(ctx context.Context) error { return i.start(ctx, s) }},
		{"验收数据库、时序库和中心", func(ctx context.Context) error { return i.verify(ctx, s) }},
	}
	for j.Step < len(stages) {
		stage := stages[j.Step]
		_ = json.NewEncoder(out).Encode(map[string]any{"stage": stage.name, "state": "running", "step": j.Step + 1})
		stepCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		err := stage.execute(stepCtx)
		cancel()
		if err != nil {
			feedback := map[string]any{"stage": stage.name, "state": "failed", "step": j.Step + 1, "resume_action": "resume-single-install"}
			var problem singleInstallProblem
			if errors.As(err, &problem) {
				feedback["code"], feedback["suggestion"] = problem.Code, problem.Hint
			}
			_ = json.NewEncoder(out).Encode(feedback)
			return fmt.Errorf("单中心安装第 %d 阶段失败；资料和已写入数据已保留，请按原请求继续，不要重新初始化", j.Step+1)
		}
		j.Step++
		if err := saveSingleJournal(s.Root, j); err != nil {
			return err
		}
		_ = json.NewEncoder(out).Encode(map[string]any{"stage": stage.name, "state": "completed", "step": j.Step})
	}
	// Even a completed installation is rechecked, without resetting accounts
	// or recreating any running container.
	if err := i.verify(ctx, s); err != nil {
		feedback := map[string]any{"stage": "复核已完成安装", "state": "failed"}
		var problem singleInstallProblem
		if errors.As(err, &problem) {
			feedback["code"], feedback["suggestion"] = problem.Code, problem.Hint
		}
		_ = json.NewEncoder(out).Encode(feedback)
		return errors.New("已完成安装当前验收失败；未重建、回退或清空任何服务")
	}
	if s.Backup != nil {
		if err := i.activateSingleBackup(ctx, s); err != nil {
			return err
		}
	}
	return json.NewEncoder(out).Encode(map[string]any{"status": "installed", "topology": "single", "config": filepath.Join(s.Root, "config.yaml"), "service": singleProject(s.Root) + ".service", "https_proxy_configured": false, "executor_enabled": s.Format == 3, "pki_automatic_renewal": s.Format >= 2})
}

func (i singleInstaller) images(ctx context.Context, s singleInstallSpec) error {
	for _, ref := range []string{s.RuntimeImage, s.PostgresImage, s.MetricsImage} {
		raw, err := i.imageInspect(ctx, "{{.Os}}/{{.Architecture}}", ref)
		if err != nil || strings.TrimSpace(string(raw)) != "linux/amd64" {
			if _, err := i.run(ctx, i.docker, "pull", "--platform", "linux/amd64", ref); err != nil {
				return singleInstallProblem{"image-unavailable", "固定摘要镜像下载失败；请检查镜像仓库连接及本机缓存，按原请求继续，不会改用其他版本"}
			}
		}
		raw, err = i.imageInspect(ctx, "{{.Os}}/{{.Architecture}}", ref)
		if err != nil || strings.TrimSpace(string(raw)) != "linux/amd64" {
			return singleInstallProblem{"image-platform", "固定摘要镜像不是可用的 Linux amd64；请核对镜像平台和本机缓存后重试"}
		}
	}
	raw, err := i.imageInspect(ctx, "{{json .Config.Env}}", s.PostgresImage)
	var env []string
	if err != nil || json.Unmarshal(raw, &env) != nil {
		return errSingleInstall
	}
	for _, entry := range env {
		if entry == "PG_MAJOR=17" {
			if s.Format == 3 {
				return i.verifyCentralExecutable(ctx, s)
			}
			return nil
		}
	}
	return errors.New("本安装器只接受 PostgreSQL 17；其他主版本需要独立迁移")
}

func (i singleInstaller) imageInspect(ctx context.Context, format, ref string) ([]byte, error) {
	// Newer multi-platform daemons can hold both architectures under one
	// digest. Older x86 daemons lack --platform; the caller still checks the
	// returned architecture and immutable image ID before using it.
	raw, err := i.run(ctx, i.docker, "image", "inspect", "--platform", "linux/amd64", "--format", format, ref)
	if err != nil {
		return i.run(ctx, i.docker, "image", "inspect", "--format", format, ref)
	}
	return raw, nil
}

func (i singleInstaller) infrastructure(ctx context.Context, s singleInstallSpec) error {
	for _, name := range []string{"postgres-data", "metrics-data", "state"} {
		path := filepath.Join(s.Root, name)
		if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return err
		}
		// PostgreSQL legitimately chowns its data directory on the first run.
		// Its private root parent is still ours; never accept a symlink or a
		// directory accessible to other users on a resumed infrastructure step.
		st, err := os.Lstat(path)
		if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
			return errSingleInstall
		}
	}
	if s.Format == 3 {
		if err := os.Mkdir(filepath.Join(s.Root, "state", "node-configurations"), 0700); err != nil && !os.IsExist(err) {
			return err
		}
		d, err := trustDirectory(filepath.Join(s.Root, "state", "node-configurations"), true)
		if err != nil {
			return err
		}
		d.Close()
	}
	if s.Format >= 2 {
		if err := initializeSinglePKI(ctx, s, time.Now().UTC()); err != nil {
			return err
		}
	}
	if err := i.checkContainers(ctx, s, []string{"postgres", "metrics", "central"}, false); err != nil {
		return err
	}
	if _, err := i.compose(ctx, s, "up", "-d", "--no-recreate", "--pull", "never", "postgres", "metrics"); err != nil {
		return errSingleInstall
	}
	return singleWait(ctx, func(op context.Context) error {
		store, err := Open(op, s.configuration())
		if err != nil {
			return err
		}
		store.DB.Close()
		return singleHTTPHealth(op, s.configuration().Metrics.QueryURL+"/health")
	})
}

func singleInstallAccount(ctx context.Context, s singleInstallSpec) error {
	hash, err := readTrustData(filepath.Join(s.Root, "admin.hash"), true, 256)
	if err != nil {
		return err
	}
	if _, err := bcrypt.Cost(hash); err != nil {
		return errSingleInstall
	}
	store, err := Open(ctx, s.configuration())
	if err != nil {
		return err
	}
	defer store.DB.Close()
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	version, err := currentSchema(ctx, tx)
	if err != nil || version != SchemaVersion {
		return errSingleInstall
	}
	if held, err := migrationHeld(ctx, tx); err != nil || held {
		return errSingleInstall
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_accounts(username,password_hash,role) VALUES($1,$2,'admin') ON CONFLICT DO NOTHING`, s.Username, string(hash)); err != nil {
		return errSingleInstall
	}
	var got, role string
	if err := tx.QueryRowContext(ctx, `SELECT password_hash,role FROM v3_accounts WHERE username=$1 FOR UPDATE`, s.Username).Scan(&got, &role); err != nil || got != string(hash) || role != "admin" {
		return errSingleInstall
	}
	return tx.Commit()
}

func (i singleInstaller) start(ctx context.Context, s singleInstallSpec) error {
	if err := i.checkContainers(ctx, s, []string{"postgres", "metrics", "central"}, false); err != nil {
		return err
	}
	unit, err := readTrustData(filepath.Join(s.Root, "stack.service"), true, 64<<10)
	if err != nil {
		return err
	}
	if err := i.publishSingleUnit(singleProject(s.Root)+".service", unit); err != nil {
		return err
	}
	if s.Format >= 2 {
		for _, suffix := range []string{"service", "timer"} {
			raw, err := readTrustData(filepath.Join(s.Root, "pki-maintenance."+suffix), true, 64<<10)
			if err != nil {
				return err
			}
			if err := i.publishSingleUnit(singleProject(s.Root)+"-pki."+suffix, raw); err != nil {
				return err
			}
		}
	}
	if s.Format == 3 {
		raw, err := readTrustData(filepath.Join(s.Root, "executor.service"), true, 64<<10)
		if err != nil {
			return err
		}
		if err = i.publishSingleUnit(singleProject(s.Root)+"-executor.service", raw); err != nil {
			return err
		}
	}
	if _, err := i.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return errSingleInstall
	}
	if s.Format >= 2 {
		if _, err := maintainSinglePKI(ctx, s, time.Now().UTC()); err != nil {
			return err
		}
		if _, err := i.run(ctx, "systemctl", "enable", "--now", singleProject(s.Root)+"-pki.timer"); err != nil {
			return errSingleInstall
		}
	}
	if s.Format == 3 {
		if _, err := i.run(ctx, "systemctl", "enable", "--now", singleProject(s.Root)+"-executor.service"); err != nil {
			return errSingleInstall
		}
	}
	if _, err := i.run(ctx, "systemctl", "enable", "--now", singleProject(s.Root)+".service"); err != nil {
		return errSingleInstall
	}
	return nil
}

func (i singleInstaller) publishSingleUnit(name string, unit []byte) error {
	if filepath.Base(name) != name || name == "." || name == "" {
		return errSingleInstall
	}
	path := filepath.Join(i.unitDirectory, name)
	dir, err := trustDirectory(i.unitDirectory, false)
	if err != nil {
		return err
	}
	defer dir.Close()
	// Publish a complete unit with no-replace semantics. A killed installer
	// must not leave a partial unit that its own resume cannot accept.
	tmp := ".webscan-unit-" + token()
	fd, err := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errSingleInstall
	}
	defer unix.Unlinkat(int(dir.Fd()), tmp, 0)
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(unit)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil {
		return errSingleInstall
	}
	err = unix.Linkat(int(dir.Fd()), tmp, int(dir.Fd()), filepath.Base(path), 0)
	if err == unix.EEXIST {
		existing, err := readTrustData(path, true, 64<<10)
		if err != nil || !bytes.Equal(existing, unit) {
			return errSingleInstall
		}
	} else if err != nil {
		return errSingleInstall
	}
	if unix.Unlinkat(int(dir.Fd()), tmp, 0) != nil || dir.Sync() != nil {
		return errSingleInstall
	}
	return nil
}

func (i singleInstaller) verify(ctx context.Context, s singleInstallSpec) error {
	unit, err := readTrustData(filepath.Join(s.Root, "stack.service"), true, 64<<10)
	installed, err2 := readTrustData(filepath.Join(i.unitDirectory, singleProject(s.Root)+".service"), true, 64<<10)
	if err != nil || err2 != nil || !bytes.Equal(unit, installed) {
		return errSingleInstall
	}
	for _, state := range []string{"is-enabled", "is-active"} {
		if _, err := i.run(ctx, "systemctl", state, "--quiet", singleProject(s.Root)+".service"); err != nil {
			return errSingleInstall
		}
	}
	if s.Format >= 2 {
		for _, suffix := range []string{"service", "timer"} {
			expected, e1 := readTrustData(filepath.Join(s.Root, "pki-maintenance."+suffix), true, 64<<10)
			actual, e2 := readTrustData(filepath.Join(i.unitDirectory, singleProject(s.Root)+"-pki."+suffix), true, 64<<10)
			if e1 != nil || e2 != nil || !bytes.Equal(expected, actual) {
				return errSingleInstall
			}
		}
		for _, state := range []string{"is-enabled", "is-active"} {
			if _, err := i.run(ctx, "systemctl", state, "--quiet", singleProject(s.Root)+"-pki.timer"); err != nil {
				return errSingleInstall
			}
		}
		if err := verifySinglePKI(s, time.Now().UTC()); err != nil {
			return singleInstallProblem{"pki-readiness", "采集器身份或吊销信任校验失败，请检查证书维护服务；未替换密钥"}
		}
	}
	if s.Format == 3 {
		if err := i.verifySingleWebDeployment(ctx, s); err != nil {
			return singleInstallProblem{"executor-service", "宿主执行器服务或固定服务定义校验失败，请检查原服务状态"}
		}
	}
	// Keep the original overall readiness deadline. Each service is a separate
	// bounded probe: sharing one 12-second attempt across twelve Docker/Compose
	// processes can repeatedly cancel a healthy later service on a slower host.
	// No identity, platform, ownership or Compose hash check is omitted.
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for _, service := range []string{"postgres", "metrics", "central"} {
		if err := singleWait(ctx, func(op context.Context) error {
			if err := i.checkContainers(op, s, []string{service}, true); err != nil {
				return singleInstallProblem{"container-readiness", "容器运行、镜像身份或固定 Compose 配置核验未通过，请检查原服务和引擎响应"}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return singleWait(ctx, func(op context.Context) error {
		store, err := Open(op, s.configuration())
		if err != nil {
			return singleInstallProblem{"database-readiness", "无法连接已安装的业务数据库，请检查 PostgreSQL 状态"}
		}
		defer store.DB.Close()
		if s.Format == 3 {
			availability := NewAPI(store, s.configuration()).deploymentAvailability(op)
			if !availability.Available {
				return singleInstallProblem{"deployment-readiness", availability.Reason}
			}
		}
		var version int
		if err := store.DB.QueryRowContext(op, `SELECT max(version) FROM v3_schema`).Scan(&version); err != nil || version != SchemaVersion {
			return singleInstallProblem{"database-schema", "业务数据库结构未达到当前程序版本，请按原安装请求继续"}
		}
		if err := singleHTTPHealth(op, s.configuration().Metrics.QueryURL+"/health"); err != nil {
			return singleInstallProblem{"metrics-readiness", "时序库健康检查失败，请检查已安装的时序服务"}
		}
		if err := singleHTTPHealth(op, "http://"+s.configuration().Central.Listen+"/healthz"); err != nil {
			return singleInstallProblem{"central-readiness", "中心健康检查失败，请检查原中心容器日志"}
		}
		return nil
	})
}

func (i singleInstaller) checkContainers(ctx context.Context, s singleInstallSpec, services []string, required bool) error {
	binary, err := readTrustData(filepath.Join(s.Root, "webscan"), true, 256<<20)
	if err != nil {
		return err
	}
	label := digest([]byte(s.Root + digest(binary) + s.Instance))
	images := map[string]string{"central": s.RuntimeImage, "postgres": s.PostgresImage, "metrics": s.MetricsImage}
	for _, service := range services {
		ids, err := i.compose(ctx, s, "ps", "--all", "--quiet", service)
		id := strings.TrimSpace(string(ids))
		if err != nil {
			return errSingleInstall
		}
		if id == "" && !required {
			continue
		}
		if !regexp.MustCompile(`^[a-f0-9]{12,64}$`).MatchString(id) {
			return errSingleInstall
		}
		raw, err := i.run(ctx, i.docker, "inspect", id)
		var containers []struct {
			Image  string
			State  struct{ Running bool }
			Config struct {
				Image  string
				Labels map[string]string
			}
			HostConfig              struct{ NetworkMode string }
			ImageManifestDescriptor struct {
				Digest   string
				Platform struct{ OS, Architecture string }
			}
		}
		if err != nil || json.Unmarshal(raw, &containers) != nil || len(containers) != 1 {
			return errSingleInstall
		}
		container := containers[0]
		if required && !container.State.Running || container.Config.Labels["io.webscan.single-install"] != label || container.Config.Labels["com.docker.compose.project"] != singleProject(s.Root) || container.Config.Labels["com.docker.compose.service"] != service || container.HostConfig.NetworkMode != "host" {
			return errSingleInstall
		}
		imageID, err := i.imageInspect(ctx, "{{.Id}}", images[service])
		if err != nil {
			return errSingleInstall
		}
		selectedID := strings.TrimSpace(string(imageID))
		if container.Image != selectedID {
			// Docker 29/containerd may report the pinned index in Image and
			// the actually selected platform manifest separately. Bind both;
			// accepting the index alone would also accept a different platform.
			ref := images[service]
			at := strings.LastIndex(ref, "@")
			d := container.ImageManifestDescriptor
			if at < 0 || container.Image != ref[at+1:] || container.Config.Image != ref || d.Digest != selectedID || d.Platform.OS != "linux" || d.Platform.Architecture != "amd64" {
				return errSingleInstall
			}
		}
		hashes, err := i.compose(ctx, s, "config", "--hash", service)
		fields := strings.Fields(string(hashes))
		if err != nil || len(fields) != 2 || fields[0] != service || fields[1] != container.Config.Labels["com.docker.compose.config-hash"] {
			return errSingleInstall
		}
	}
	return nil
}

func singleHTTPHealth(ctx context.Context, address string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return errSingleInstall
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	r, err := client.Do(req)
	if err != nil {
		return errSingleInstall
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return errSingleInstall
	}
	return nil
}
func singleWait(ctx context.Context, check func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for {
		op, stop := context.WithTimeout(ctx, 12*time.Second)
		err := check(op)
		stop()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(time.Second):
		}
	}
}
