package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func metricsRetentionFixture(t *testing.T) (*Store, MetricsRetentionSpec, singleBackupPlan, *Vault) {
	t.Helper()
	s := testStore(t)
	plan, _ := newSingleBackupFixtureOptions(t, "", 3, false, false, true)
	state, backups := plan.spec.Root+"-retention", plan.spec.Root+"-retention-backups"
	for _, directory := range []string{state, backups} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	request := plan.request
	request.RecoveryDirectories = []string{state}
	var err error
	plan, err = planSingleBackup(context.Background(), request, filepath.Join(backups, "binding-check"))
	if err != nil {
		t.Fatal(err)
	}
	p := MetricsRetentionSpec{Format: 1, Instance: plan.spec.Instance, Root: plan.spec.Root, InstallationFile: request.Installation, HostConfigFile: request.HostConfig, ComposeFile: request.ComposeFile, HelperFile: plan.config.DeploymentTrust.HelperFile, StateDirectory: state, BackupDirectory: backups, BackupRequest: request}
	for _, item := range []struct {
		path string
		hash *string
	}{{p.InstallationFile, &p.InstallationSHA256}, {p.HostConfigFile, &p.HostConfigSHA256}, {p.ComposeFile, &p.ComposeSHA256}, {p.HelperFile, &p.HelperSHA256}} {
		raw, err := os.ReadFile(item.path)
		if err != nil {
			t.Fatal(err)
		}
		*item.hash = digest(raw)
	}
	v, err := OpenVault(plan.config.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	p.KeyID = v.active
	p.Proof, _ = metricsRetentionMAC(v, p.KeyID, "spec", p)
	return s, p, plan, v
}

type metricsRetentionDockerFixture struct {
	t                       *testing.T
	p                       MetricsRetentionSpec
	spec                    singleInstallSpec
	v                       *Vault
	hashes                  map[string]string
	up                      int
	lost, foreign, wrongCmd bool
}

func (f *metricsRetentionDockerFixture) installer() singleInstaller {
	return singleInstaller{docker: "synthetic-docker", run: f.run}
}

func (f *metricsRetentionDockerFixture) run(ctx context.Context, command string, args ...string) ([]byte, error) {
	f.t.Helper()
	if command != "synthetic-docker" || len(args) == 0 {
		return nil, errors.New("unexpected command")
	}
	if args[0] == "image" {
		return []byte("sha256:" + strings.Repeat("c", 64)), nil
	}
	if args[0] == "inspect" {
		service := "metrics"
		if strings.HasPrefix(args[1], "b") {
			service = "metrics-raw"
		}
		helper, _ := os.ReadFile(filepath.Join(f.spec.Root, "webscan"))
		label := digest([]byte(f.spec.Root + digest(helper) + f.spec.Instance))
		if f.foreign {
			label = "not-ours"
		}
		overlay := ""
		if f.hashes[service] != "base" {
			entries, _ := os.ReadDir(f.p.StateDirectory)
			for _, entry := range entries {
				if filepath.Ext(entry.Name()) != ".yaml" {
					continue
				}
				path := filepath.Join(f.p.StateDirectory, entry.Name())
				raw, _ := os.ReadFile(path)
				if digest(raw) == f.hashes[service] {
					overlay = path
					break
				}
			}
		}
		commands, err := metricsRetentionExpectedCommands(f.spec, overlay)
		if err != nil {
			f.t.Fatal(err)
		}
		cmd := commands[service]
		if f.wrongCmd {
			cmd = []string{"-retentionPeriod=99d"}
		}
		raw, _ := json.Marshal([]any{map[string]any{"Image": "sha256:" + strings.Repeat("c", 64), "State": map[string]bool{"Running": true}, "Config": map[string]any{"Image": f.spec.MetricsImage, "Cmd": cmd, "Labels": map[string]string{"io.webscan.single-install": label, "com.docker.compose.project": singleProject(f.spec.Root), "com.docker.compose.service": service, "com.docker.compose.config-hash": f.hashes[service]}}, "HostConfig": map[string]string{"NetworkMode": "host"}}})
		return raw, nil
	}
	if len(args) < 6 || !reflect.DeepEqual(args[:5], []string{"compose", "--project-name", singleProject(f.spec.Root), "--file", f.p.ComposeFile}) {
		return nil, errors.New("wrong project")
	}
	args = args[5:]
	hash := "base"
	if args[0] == "--file" {
		raw, err := readTrustData(args[1], true, 64<<10)
		if err != nil {
			return nil, err
		}
		hash = digest(raw)
		args = args[2:]
	}
	service := args[len(args)-1]
	switch args[0] {
	case "ps":
		if service == "metrics" {
			return []byte(strings.Repeat("a", 64)), nil
		}
		if service == "metrics-raw" {
			return []byte(strings.Repeat("b", 64)), nil
		}
	case "config":
		return []byte(service + " " + hash), nil
	case "up":
		if !reflect.DeepEqual(args, []string{"up", "--detach", "--no-deps", "--force-recreate", "metrics", "metrics-raw"}) {
			f.t.Fatal("recreated unapproved service", args)
		}
		j, err := readMetricsRetentionJournal(f.p, f.v)
		if err != nil || j.Phase != "applying" || j.Backup == nil {
			f.t.Fatal("recreate before durable backup/applying", err)
		}
		if manifest, err := verifySingleBackup(ctx, j.Backup.Directory, j.Backup.ManifestSHA256); err != nil || manifest.RawMetrics == "" {
			f.t.Fatal("recreate without complete dual-store backup", err)
		}
		f.up++
		f.hashes["metrics"], f.hashes["metrics-raw"] = hash, hash
		if f.lost {
			f.lost = false
			return nil, errors.New("synthetic lost response")
		}
		return nil, nil
	}
	return nil, errors.New("unexpected docker args")
}

func metricsRetentionHealthyFixture(t *testing.T, plan singleBackupPlan) singleBackupPlan {
	t.Helper()
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Error("unexpected health request")
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(health.Close)
	// Snapshot transports and directories remain the independently bound dual
	// fixtures. Only readiness uses this explicitly synthetic health service.
	plan.config.Metrics.QueryURL, plan.config.Metrics.RawURL = health.URL, health.URL
	return plan
}

func TestMetricsRetentionRuntimeBacksUpBothLayersThenResumesLostResponseWithoutRecreate(t *testing.T) {
	s, p, plan, v := metricsRetentionFixture(t)
	plan = metricsRetentionHealthyFixture(t, plan)
	ctx := context.Background()
	if _, err := s.DB.Exec(`UPDATE v3_settings SET version=version+1,payload='{"monitoring":{"raw_hours":24,"history_days":7}}'`); err != nil {
		t.Fatal(err)
	}
	docker := &metricsRetentionDockerFixture{t: t, p: p, spec: plan.spec, v: v, hashes: map[string]string{"metrics": "base", "metrics-raw": "base"}, lost: true}
	first, err := s.runMetricsRetentionRuntime(ctx, p, plan, v, docker.installer())
	if err == nil || first.State != "failed" || first.Effective != nil || docker.up != 1 {
		t.Fatal("lost response pretended applied", first, err, docker.up)
	}
	j, err := readMetricsRetentionJournal(p, v)
	if err != nil || j.Phase != "applying" || j.Backup == nil {
		t.Fatal(j, err)
	}
	id := j.ID
	if _, err := metricsRetentionActiveOverlay(p, v); err == nil {
		t.Fatal("boot accepted applying base compose")
	}
	// Applying must converge the original authenticated target before a newer
	// settings version is allowed to create the next task.
	if _, err := s.DB.Exec(`UPDATE v3_settings SET version=version+1,payload='{"monitoring":{"raw_hours":48,"history_days":15}}'`); err != nil {
		t.Fatal(err)
	}
	second, err := s.runMetricsRetentionRuntime(ctx, p, plan, v, docker.installer())
	if err != nil || second.State != "confirmed" || second.TaskID != id || second.Effective.RawHours != 24 || second.Desired.RawHours != 48 || docker.up != 1 {
		t.Fatal("resume repeated recreation or lost original target", second, err, docker.up)
	}
	third, err := s.runMetricsRetentionRuntime(ctx, p, plan, v, docker.installer())
	if err != nil || third.Effective.RawHours != 48 || third.TaskID == id || docker.up != 2 {
		t.Fatal(third, err, docker.up)
	}
	latest, err := readMetricsRetentionJournal(p, v)
	if err != nil || latest.PreviousOverlay != j.Overlay {
		t.Fatal("previous overlay lost", latest, err)
	}
	if overlay, err := metricsRetentionActiveOverlay(p, v); err != nil || overlay != latest.Overlay {
		t.Fatal("boot lost confirmed overlay", err)
	}
	var details []byte
	var reason string
	if err := s.DB.QueryRow(`SELECT error,details FROM v3_role_status WHERE role='metrics-retention'`).Scan(&reason, &details); err != nil || reason != "" || !strings.Contains(string(details), `"effective"`) {
		t.Fatal("missing real worker status", err)
	}
}

func TestMetricsRetentionRuntimeRejectsUnknownOwnershipAndFailedBackupBeforeRestart(t *testing.T) {
	for _, mode := range []string{"foreign", "wrong-command", "backup-failure", "below-vm-minimum"} {
		t.Run(mode, func(t *testing.T) {
			s, p, plan, v := metricsRetentionFixture(t)
			ctx := context.Background()
			hours := 24
			if mode == "below-vm-minimum" {
				hours = 23
			}
			payload, _ := json.Marshal(map[string]any{"monitoring": map[string]int{"raw_hours": hours, "history_days": 7}})
			if _, err := s.DB.Exec(`UPDATE v3_settings SET version=version+1,payload=$1`, payload); err != nil {
				t.Fatal(err)
			}
			if mode == "backup-failure" {
				plan.metrics.URL = "http://127.0.0.1:1"
				plan.metrics.HTTP = &http.Client{Timeout: time.Second}
			}
			docker := &metricsRetentionDockerFixture{t: t, p: p, spec: plan.spec, v: v, hashes: map[string]string{"metrics": "base", "metrics-raw": "base"}, foreign: mode == "foreign", wrongCmd: mode == "wrong-command"}
			result, err := s.runMetricsRetentionRuntime(ctx, p, plan, v, docker.installer())
			if err == nil || result.Effective != nil || docker.up != 0 {
				t.Fatal("unsafe restart", result, err, docker.up)
			}
		})
	}
}

func TestMetricsRetentionRuntimeJournalAuthenticatesBindingsAndRejectsPathOrOverlayMutation(t *testing.T) {
	_, p, plan, v := metricsRetentionFixture(t)
	if validateMetricsRetentionSpec(p) != nil {
		t.Fatal("valid spec rejected")
	}
	for _, mutate := range []func(*MetricsRetentionSpec){func(p *MetricsRetentionSpec) { p.StateDirectory = p.Root }, func(p *MetricsRetentionSpec) { p.BackupDirectory = p.StateDirectory }, func(p *MetricsRetentionSpec) { p.ComposeFile = "/tmp/arbitrary-compose.yaml" }, func(p *MetricsRetentionSpec) { p.BackupRequest.RecoveryDirectories = nil }} {
		bad := p
		mutate(&bad)
		if validateMetricsRetentionSpec(bad) == nil {
			t.Fatal("unsafe support accepted")
		}
	}
	body := metricsRetentionOverlay(plan.spec, metricsRetentionTarget{RawHours: 24, HistoryDays: 7, Version: 1})
	if strings.Contains(string(body), "central") || strings.Contains(string(body), "postgres") || strings.Contains(string(body), "volumes") {
		t.Fatal("overlay changed non-metrics structure")
	}
	raw, _ := json.Marshal(p)
	j := metricsRetentionJournal{Format: 1, SpecSHA256: digest(raw), ID: token(), Phase: "prepared", Target: metricsRetentionTarget{RawHours: 24, HistoryDays: 7, Version: 1}}
	j.Overlay = filepath.Join(p.StateDirectory, j.ID+".yaml")
	j.OverlaySHA256 = digest(body)
	if err := metricsRetentionAtomicFile(p.StateDirectory, filepath.Base(j.Overlay), body); err != nil {
		t.Fatal(err)
	}
	if err := writeMetricsRetentionJournal(p, v, &j); err != nil {
		t.Fatal(err)
	}
	if _, err := readMetricsRetentionJournal(p, v); err != nil {
		t.Fatal(err)
	}
	localWrite(t, j.Overlay, []byte("services: {}"))
	if _, err := readMetricsRetentionJournal(p, v); err == nil {
		t.Fatal("overlay mutation accepted")
	}
	localWrite(t, j.Overlay, body)
	raw, _ = os.ReadFile(filepath.Join(p.StateDirectory, "journal.json"))
	raw = []byte(strings.Replace(string(raw), `"phase":"prepared"`, `"phase":"confirmed"`, 1))
	localWrite(t, filepath.Join(p.StateDirectory, "journal.json"), raw)
	if _, err := readMetricsRetentionJournal(p, v); err == nil {
		t.Fatal("journal mutation accepted")
	}
}

func TestMetricsRetentionRuntimeSerializesLocalCoordinator(t *testing.T) {
	s, p, plan, v := metricsRetentionFixture(t)
	f, err := os.OpenFile(filepath.Join(p.StateDirectory, "coordinator.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	docker := &metricsRetentionDockerFixture{t: t, p: p, spec: plan.spec, v: v, hashes: map[string]string{"metrics": "base", "metrics-raw": "base"}}
	if _, err := s.runMetricsRetentionRuntime(context.Background(), p, plan, v, docker.installer()); err == nil || docker.up != 0 {
		t.Fatal("overlapped local coordinator", err)
	}
}

func TestMetricsRetentionRuntimeSerializesPGAndReadsOnlyAppliedSettings(t *testing.T) {
	s, p, plan, v := metricsRetentionFixture(t)
	ctx := context.Background()
	initial, err := s.metricsRetentionDesired(ctx, plan.spec)
	if err != nil || initial.RawHours != 48 || initial.HistoryDays != 15 {
		t.Fatal("immutable defaults not preserved", initial, err)
	}
	// A draft is independent from the applied row consumed by the host task.
	if _, err := s.DB.Exec(`INSERT INTO v3_settings_drafts(id,runtime_version,runtime_digest,payload,proof) VALUES(1,$1,'synthetic','{"monitoring":{"raw_hours":24,"history_days":1}}','synthetic')`, initial.Version); err != nil {
		t.Fatal(err)
	}
	after, err := s.metricsRetentionDesired(ctx, plan.spec)
	if err != nil || after != initial {
		t.Fatal("draft changed retention", after, err)
	}
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	resource := "metrics-retention:" + p.Instance
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, resource); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1,0))`, resource)
	docker := &metricsRetentionDockerFixture{t: t, p: p, spec: plan.spec, v: v, hashes: map[string]string{"metrics": "base", "metrics-raw": "base"}}
	if _, err := s.runMetricsRetentionRuntime(ctx, p, plan, v, docker.installer()); err == nil || docker.up != 0 {
		t.Fatal("overlapped PG coordinator", err)
	}
}

func TestMetricsRetentionRuntimePlanRequiresSignedOriginalDualInstallation(t *testing.T) {
	_, p, _, _ := metricsRetentionFixture(t)
	plan, _, err := metricsRetentionPlan(context.Background(), p)
	if err != nil || plan.rawMetrics == nil {
		t.Fatal("valid signed dual plan rejected", err)
	}
	for _, mutate := range []func(*MetricsRetentionSpec){func(p *MetricsRetentionSpec) { p.HelperSHA256 = strings.Repeat("a", 64) }, func(p *MetricsRetentionSpec) { p.ComposeSHA256 = strings.Repeat("a", 64) }, func(p *MetricsRetentionSpec) { p.HostConfigSHA256 = strings.Repeat("a", 64) }, func(p *MetricsRetentionSpec) { p.InstallationSHA256 = strings.Repeat("a", 64) }} {
		bad := p
		mutate(&bad)
		if _, _, err := metricsRetentionPlan(context.Background(), bad); err == nil {
			t.Fatal("changed immutable binding accepted")
		}
	}
}
