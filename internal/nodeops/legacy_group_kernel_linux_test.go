//go:build linux

package nodeops

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/common"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
	"webscan/internal/persist"
	agentv1 "webscan/sdk/agent/v1"
)

// Actual published v2 Agent, Compose, systemd-managed vendor sidecars, and v3
// target share one independent Linux kernel/daemon. Vector uses a blackhole
// sink: this proves grouped lifecycle/data preservation, not push delivery.
func TestKernelLegacyAgentAndWrappersMigrateAndRollback(t *testing.T) {
	requireDockerKernelGuest(t)
	for _, mode := range []string{"native", "docker"} {
		t.Run("to-"+mode, func(t *testing.T) { runKernelLegacyGroup(t, mode, false) })
	}
}

func TestKernelPureComposeGroupMigrateAndRollback(t *testing.T) {
	requireDockerKernelGuest(t)
	for _, mode := range []string{"native", "docker"} {
		t.Run("to-"+mode, func(t *testing.T) { runKernelLegacyGroup(t, mode, true) })
	}
}

func runKernelLegacyGroup(t *testing.T, mode string, pureCompose bool) {
	t.Helper()
	marker, err := os.ReadFile("/v3-tests/isolated-engine")
	if os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_DIND") != "1" || err != nil || string(marker) != "webscan-v3-disposable-dind\n" {
		t.Fatal("refusing unmarked daemon")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 16*time.Minute)
	defer cancel()
	listing, err := inventoryCommand(ctx, "docker", "--host", "unix:///var/run/docker.sock", "ps", "-aq")
	if err != nil || strings.TrimSpace(listing) != "" {
		t.Fatal("refusing nonempty daemon", err)
	}
	for _, path := range []string{legacyConfigurationRoot, agentDataDirectory, agentLogDirectory, "/var/lib/webscan-vector-v1", nativeUnitPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing existing node state", path, err)
		}
	}
	raw, err := os.ReadFile("/v3-tests/agent-native.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	w, r := stageFixture(t, raw)
	w.probe = probeBundle
	r.Spec.Mode, r.Spec.Release = mode, "v3.0.0-local-test"
	r.Spec.MetricsPort = 19100
	site, err := os.MkdirTemp("/var/tmp", "webscan-v3-legacy-monitor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(site) })
	r.Spec.MonitorDirectories = []string{site}
	baselinePath := filepath.Join(site, "existing-baseline.php")
	if err := os.WriteFile(baselinePath, []byte("<?php /* original baseline remains unchanged */\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if mode == "docker" {
		proof, err := os.ReadFile("/v3-tests/image-proof.json")
		var image Spec
		if err != nil || json.Unmarshal(proof, &image) != nil || !image.imageArchiveValid() {
			t.Fatal("missing pinned target image", err)
		}
		r.Spec.AgentImage, r.Spec.ImageArchiveSHA256, r.Spec.ImageConfigSHA256, r.Spec.ImageArchiveBytes = image.AgentImage, image.ImageArchiveSHA256, image.ImageConfigSHA256, image.ImageArchiveBytes
		dir := filepath.Join(w.root, "images", image.ImageArchiveSHA256)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		source, err := os.Open("/v3-tests/agent-image.tar")
		if err != nil {
			t.Fatal(err)
		}
		target, err := os.OpenFile(filepath.Join(dir, "docker-image.tar"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			source.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(target, source)
		source.Close()
		closeErr := target.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal(copyErr, closeErr)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	node, err := ca.Issue(nodepki.Node, r.Node, []string{"node.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := ca.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ca.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	material := attachConfiguration(t, w, &r, func(m *nodeconfig.Material) {
		m.CA, m.Certificate, m.Key, m.CRL = node.CA, node.Certificate, node.Key, crl
	})
	host := newInstallationHost(w.root)
	var originals []string
	// Stop only exact private units/IDs. Clean between independent target modes.
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		operation, unlock, e := acquireServiceOperation(c, w.root)
		if e != nil {
			t.Error(e)
			return
		}
		for _, name := range legacyWrapperNames {
			path := filepath.Join(filepath.Dir(nativeUnitPath), name)
			if _, e := os.Lstat(path); e == nil {
				if _, e := inventoryCommand(operation, "systemctl", "disable", "--now", name); e != nil {
					t.Error(e)
				}
				if e := os.Remove(path); e != nil {
					t.Error(e)
				}
			}
		}
		for _, id := range originals {
			if _, e := host.docker(operation, "rm", "-f", id); e != nil {
				t.Error("cleanup exact legacy object", e)
			}
		}
		if _, e := inventoryCommand(operation, "systemctl", "daemon-reload"); e != nil {
			t.Error(e)
		}
		unlock()
		cleanupKernelTransition(t, w, host, r.Node)
		for _, path := range []string{legacyConfigurationRoot, "/var/lib/webscan-vector-v1"} {
			if e := os.RemoveAll(path); e != nil {
				t.Error(e)
			}
		}
	})
	for _, path := range []string{legacyConfigurationRoot, agentDataDirectory, agentLogDirectory, "/var/lib/webscan-vector-v1", filepath.Join(agentDataDirectory, "textfile")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	old, err := material.Runtime(legacyConfigurationRoot, "/unused-v3-release")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pull", "transport_mode", "direct_transport", "metrics", "scanner_tools", "config_version", "config_sha256"} {
		delete(old, name)
	}
	old["deployment_mode"], old["release"], old["public_url"], old["token"] = "docker", "v2.0.34", "http://127.0.0.1:19443", "isolated-test-only"
	old["yara_rules"] = filepath.Join(legacyConfigurationRoot, "rules.yar")
	if err := os.MkdirAll(material.Settings.ProbeDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	oldRaw, _ := json.Marshal(old)
	files := map[string][]byte{
		"runtime.json": oldRaw, "rules.yar": material.YARA, "exporter.yml": []byte("{}\n"),
		"vector.yml": []byte("data_dir: /var/lib/vector\nsources:\n  test_files:\n    type: file\n    include: [\"/var/log/webscan-v1/events-*.jsonl\"]\n    read_from: beginning\nsinks:\n  discard:\n    type: blackhole\n    inputs: [test_files]\n"),
	}
	var proof map[string]string
	proofRaw, err := os.ReadFile("/v3-tests/legacy-group-proof.json")
	if err != nil || json.Unmarshal(proofRaw, &proof) != nil || proof["release"] != "v2.0.34" || proof["digest"] != "sha256:453ec55733ec73457e4ddf3ea6a6d23b2d6e4e55c044ec77cd2194aac5c6ee27" || !validDigest(strings.TrimPrefix(proof["id"], "sha256:")) {
		t.Fatal("published v2 Agent proof invalid", err)
	}
	var vendors map[string]string
	raw, err = os.ReadFile("/v3-tests/sidecar-proof.json")
	if err != nil || json.Unmarshal(raw, &vendors) != nil || len(vendors) != 2 {
		t.Fatal("vendor proof unavailable", err)
	}
	compose := common.Map{"name": "webscan-v1-legacy-acceptance", "services": common.Map{"agent": common.Map{
		"image": proof["id"], "container_name": agentContainerName, "network_mode": "host", "restart": "unless-stopped", "read_only": true,
		"command": []string{"agent", "--config", filepath.Join(legacyConfigurationRoot, "runtime.json")},
		"volumes": []string{legacyConfigurationRoot + ":" + legacyConfigurationRoot + ":ro", agentDataDirectory + ":" + agentDataDirectory, agentLogDirectory + ":" + agentLogDirectory, site + ":" + site + ":ro", material.Settings.ProbeDirectory + ":" + material.Settings.ProbeDirectory}, "tmpfs": []string{"/tmp"},
	}}}
	if pureCompose {
		services := common.M(compose["services"])
		for _, role := range []string{"vector", "exporter"} {

			u := legacySidecarUnit{Role: role, SourceImage: vendors[role]}
			if role == "exporter" {
				u.MetricsPort = 19100
			}
			volumes := []string{}
			args := u.runArguments()
			for index, arg := range args {
				if arg == "-v" {
					volumes = append(volumes, args[index+1])
				}
			}
			service := common.Map{"image": vendors[role], "container_name": "webscan-" + role + "-v1", "network_mode": "host", "restart": "unless-stopped", "read_only": true, "cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges"}, "logging": common.Map{"driver": "json-file", "options": common.Map{"max-size": "10m", "max-file": "3"}}, "volumes": volumes}
			if role == "exporter" {
				service["user"], service["pid"] = "0:0", "host"
				for index, arg := range args {
					if arg == u.alias() {
						service["command"] = args[index+1:]
					}
				}
			}
			services[role] = service
		}
	}
	files["compose.yml"], _ = json.Marshal(compose)
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(legacyConfigurationRoot, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}

	func() {
		op, unlock, err := acquireServiceOperation(ctx, w.root)
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		if _, err := host.docker(op, "compose", "-f", filepath.Join(legacyConfigurationRoot, "compose.yml"), "up", "-d", "--pull", "never", "--no-build"); err != nil {
			t.Fatal("start published Agent", err)
		}
		id, err := host.docker(ctx, "ps", "-aq", "--no-trunc", "--filter", "name=^/"+agentContainerName+"$")
		if err != nil || !validDigest(strings.TrimSpace(id)) {
			t.Fatal("old Agent ID", err)
		}
		originals = append(originals, strings.TrimSpace(id))
		for _, role := range []string{"vector", "exporter"} {
			if pureCompose {
				name := "webscan-" + role + "-v1"
				deadline := time.Now().Add(60 * time.Second)
				var side legacyComposeIntent
				for time.Now().Before(deadline) {
					side, err = (legacyComposeTransition{host}).observe(op, r, name)
					if err == nil && side.Object.Identity.Status == "running" {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				if err != nil || side.Object.Identity.Status != "running" {
					t.Fatal("actual Compose sidecar not active", err)
				}
				originals = append(originals, side.Object.Identity.ID)
				continue
			}
			u := legacySidecarUnit{Role: role, SourceImage: vendors[role]}
			if role == "exporter" {
				u.MetricsPort = 19100
			}
			name := "webscan-" + role + "-v1.service"
			if err := os.WriteFile(filepath.Join(filepath.Dir(nativeUnitPath), name), u.definition(), 0644); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", name}} {
				if _, err := inventoryCommand(op, "systemctl", args...); err != nil {
					t.Fatal("start actual vendor wrapper", err)
				}
			}
			deadline := time.Now().Add(60 * time.Second)
			var capture legacyWrapperIntent
			for time.Now().Before(deadline) {
				capture, err = (legacyWrapperTransition{host}).observe(op, r, name)
				if err == nil && capture.Running && capture.Enabled {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if err != nil || !capture.Running || !capture.Enabled {
				t.Fatal("vendor not active", err)
			}
			originals = append(originals, capture.Object.Identity.ID)
		}
	}()
	waitOld := func() {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			raw, err := os.ReadFile(filepath.Join(agentDataDirectory, "textfile/agent.prom"))
			if err == nil && bytes.Contains(raw, []byte("webscan_coverage_ok 1\n")) {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		for _, id := range originals[:1] {
			state, _ := host.docker(ctx, "inspect", id, "--format", "{{json .State}}")
			logs, _ := host.docker(ctx, "logs", "--tail", "30", id)
			t.Logf("private old Agent state=%s logs=%s", state, logs)
		}
		t.Fatal("published Agent not ready")
	}
	waitOld()
	oldEvent := func(name string) string {
		t.Helper()
		path := filepath.Join(site, name+".php")
		if err := os.WriteFile(path, []byte("<?php /* isolated legacy lifecycle */\n"), 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			db, err := persist.OpenReadOnly(filepath.Join(agentDataDirectory, "agent.sqlite3"))
			if err == nil {
				rows, e := db.Query("SELECT id,payload FROM events WHERE exported IS NOT NULL AND accepted IS NULL")
				if e == nil {
					for rows.Next() {
						var id, payload string
						if rows.Scan(&id, &payload) == nil {
							var p map[string]any
							if json.Unmarshal([]byte(payload), &p) == nil && p["path"] == path {
								rows.Close()
								db.Close()
								return id
							}
						}
					}
					rows.Close()
				}
				db.Close()
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("published Agent event/JSONL missing", path)
		return ""
	}
	beforeID := oldEvent("before-migration")
	baseline := kernelLegacyBaseline(t, baselinePath)
	observation, err := host.observeOriginal(ctx, r)
	if err != nil || !observation.grouped || observation.agent.Generation != "v2" || !singleDockerOriginal(observation.agent) {
		t.Fatal("whole original not observed", err)
	}
	var h Handler
	var backup *transitionBackup
	if mode == "native" {
		n := &nativeLifecycle{runtime: w, activation: newNativeActivation(w), resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: LocalPreflight{}}
		h = n
		backup = n.activation.backup
	} else {
		d := &dockerLifecycle{runtime: w, activation: newDockerActivation(w), resources: nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, preflight: LocalPreflight{}, stage: w}
		h = d
		backup = d.activation.backup
	}
	journalRoot := filepath.Join(w.root, "journal")
	j := openTestJournal(t, journalRoot, h)
	apply := func(phases []string) {
		t.Helper()
		for _, phase := range phases {
			r.Phase, r.Operation = phase, "apply"
			result := j.Handle(r)
			t.Logf("target=%s phase=%s result=%+v", mode, phase, result)
			requireResult(t, result, "complete", "ok")
		}
	}
	apply(forward[:3])
	captured, err := backup.readIntent(ctx, r)
	if err != nil || (pureCompose && len(captured.Installed.Sidecars) != 2 || !pureCompose && len(captured.Installed.Wrappers) != 2) || len(captured.Installed.Services) != 1 {
		t.Fatal("whole group not captured", err)
	}
	for _, id := range originals {
		c, err := host.container(ctx, id)
		if err != nil || c.Status == "running" || c.Restart != "no" {
			t.Fatal("original not stopped before activation", id, err)
		}
	}
	snapshot, err := backup.verify(ctx, r)
	if err != nil || snapshot.Database == nil || len(legacyInputFiles(snapshot)) == 0 {
		t.Fatal("consistent DB/JSONL backup missing", err)
	}
	apply([]string{"activate"})
	writer := kernelSingleWriter(t, ctx, w, host, r)
	pair, err := tls.X509KeyPair(collector.Certificate, collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(node.CA)
	conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(r.Spec.MetricsPort)), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: "node.test", RootCAs: roots, Certificates: []tls.Certificate{pair}})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rpc := agentv1.NewAgentServiceClient(conn)
	ready := func(m nodeconfig.Material) {
		t.Helper()
		minimum := time.Now().UnixMilli()
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			call, stop := context.WithTimeout(ctx, 3*time.Second)
			capability, capErr := rpc.Capabilities(call, &agentv1.CapabilitiesRequest{})
			metrics, metErr := rpc.ReadMetrics(call, &agentv1.ReadMetricsRequest{AfterUnixMillis: minimum - 1})
			stop()
			if capErr == nil && metErr == nil && capability.ConfigurationVersion == m.Version && capability.ConfigurationSha256 == m.SourceSHA256 && kernelLatestReadiness(metrics.Samples, minimum) {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("fresh v3 metrics/YARA/mTLS not ready", m.Version)
	}
	ready(material)
	apply(forward[4:])
	if got := kernelLegacyBaseline(t, baselinePath); got != baseline {
		t.Fatal("existing baseline changed during migration")
	}
	path := filepath.Join(site, "during-v3.php")
	if err := os.WriteFile(path, []byte("<?php /* generated by real v3 Agent */\n"), 0600); err != nil {
		t.Fatal(err)
	}
	afterID := ""
	foundBefore := false
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && (afterID == "" || !foundBefore) {
		call, stop := context.WithTimeout(ctx, 3*time.Second)
		batch, err := rpc.FetchEvents(call, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100, WaitSeconds: 1})
		stop()
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range batch.Events {
			if event.Id == beforeID {
				foundBefore = true
			}
			var p map[string]any
			if json.Unmarshal(event.Json, &p) == nil && p["path"] == path {
				afterID = event.Id
			}
		}
	}
	if afterID == "" || !foundBefore {
		t.Fatal("real old/new event IDs not available from v3")
	}
	if kernelSingleWriter(t, ctx, w, host, r).pid != writer.pid {
		t.Fatal("verification restarted target")
	}
	eventIDs := []string{beforeID, afterID}
	originalRequest := r
	if pureCompose {
		// Complete a second real service replacement, then roll it back before
		// restoring v2. Every stage uses the current database, never a snapshot.
		prior := r
		priorPointer, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
		if err != nil {
			t.Fatal(err)
		}
		r.Job, r.PlanDigest, r.Epoch = "compose-successor", strings.Repeat("e", 64), 1
		nextMaterial := attachConfiguration(t, w, &r, func(m *nodeconfig.Material) {
			m.CA, m.Certificate, m.Key, m.CRL = node.CA, node.Certificate, node.Key, crl
			m.Version, m.SourceSHA256 = 2, strings.Repeat("d", 64)
		})
		r.Spec.ConfigVersion, r.Spec.ConfigSourceSHA256 = nextMaterial.Version, nextMaterial.SourceSHA256
		j = openTestJournal(t, journalRoot, h)
		apply(forward[:4])
		ready(nextMaterial)
		apply(forward[4:])
		kernelSingleWriter(t, ctx, w, host, r)
		var active ActiveInstallation
		if _, err := decodePrivateJSON(filepath.Join(w.root, "active.json"), &active, MaxRequestBytes); err != nil {
			t.Fatal(err)
		}
		proofs, err := host.parkedComposeProofs(ctx, &active)
		if err != nil || len(proofs) != 2 {
			t.Fatal("successor parked proofs", err)
		}
		for index, name := range legacyComposeNames {
			if proofs[name].Object.Identity.ID != originals[index+1] {
				t.Fatal("successor lost immutable ID")
			}
		}
		// A policy change cannot be hidden by a later native installation. This
		// does not start the retired Agent or create a competing DB writer.
		changeHistoricalPolicy := func(policy string) {
			t.Helper()
			operation, unlock, err := acquireServiceOperation(ctx, w.root)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			if _, err := host.docker(operation, "update", "--restart="+policy, originals[0]); err != nil {
				t.Fatal(err)
			}
		}
		changeHistoricalPolicy("always")
		if _, err := host.inventory(ctx, r.Node, mode); err == nil {
			t.Fatal("successor ignored historical Agent drift")
		}
		changeHistoricalPolicy("no")
		if _, err := host.inventory(ctx, r.Node, mode); err != nil {
			t.Fatal("restored historical policy", err)
		}
		nextPath := filepath.Join(site, "during-successor.php")
		if err := os.WriteFile(nextPath, []byte("<?php /* real successor event */\n"), 0600); err != nil {
			t.Fatal(err)
		}
		nextID := ""
		deadline = time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) && nextID == "" {
			call, stop := context.WithTimeout(ctx, 3*time.Second)
			batch, err := rpc.FetchEvents(call, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100, WaitSeconds: 1})
			stop()
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range batch.Events {
				var payload map[string]any
				if json.Unmarshal(event.Json, &payload) == nil && payload["path"] == nextPath {
					nextID = event.Id
				}
			}
		}
		if nextID == "" {
			t.Fatal("successor real file event missing")
		}
		eventIDs = append(eventIDs, nextID)
		j = openTestJournal(t, journalRoot, h)
		r.Epoch++
		apply(rollback)
		ready(material)
		restoredPointer, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
		if err != nil || !bytes.Equal(restoredPointer, priorPointer) {
			t.Fatal("successor rollback did not restore exact predecessor", err)
		}
		head := r
		r = prior
		kernelSingleWriter(t, ctx, w, host, r)
		capture, err := readPrivate(filepath.Join(backup.directory(prior), "capture/intent.json"), 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		r.Job, r.PlanDigest, r.Epoch, r.Phase = "compose-original-recovery", strings.Repeat("f", 64), 1, "restore"
		r.Recovery = &RecoveryReference{SourceJob: prior.Job, SourcePlanDigest: prior.PlanDigest, CaptureSHA256: sha(capture), HeadJob: head.Job, HeadPlanDigest: head.PlanDigest, ActiveSHA256: sha(priorPointer)}
		h = withRecovery(h)
		t.Log("completed successor replacement and rollback; historical objects and current event IDs retained; original recovery has a new task identity")
	}
	// Reopen durable journal before rollback; never restore an old database copy.
	j = openTestJournal(t, journalRoot, h)
	if !pureCompose {
		r.Epoch++
	}
	apply(rollback)
	if pureCompose {
		retired := originalRequest
		retired.Phase, retired.Epoch = "restore", 999
		requireResult(t, j.Handle(retired), "unknown", "remote-conflict")
	}
	restoredRaw, err := os.ReadFile(filepath.Join(legacyConfigurationRoot, "runtime.json"))
	if err != nil || !bytes.Equal(restoredRaw, oldRaw) {
		t.Fatal("old runtime not restored", err)
	}
	for _, id := range originals {
		c, err := host.container(ctx, id)
		if err != nil || c.Status != "running" {
			t.Fatal("original ID not restored", id, err)
		}
	}
	if pureCompose {
		for _, name := range legacyComposeNames {
			if err := (legacyComposeTransition{host}).restored(ctx, originalRequest, name); err != nil {
				t.Fatal("Compose sidecar not restored", err)
			}
		}
	} else {
		for _, name := range legacyWrapperNames {
			if err := (legacyWrapperTransition{host}).restored(ctx, r, name); err != nil {
				t.Fatal("wrapper not restored", err)
			}
		}
	}
	db, err := persist.OpenReadOnly(filepath.Join(agentDataDirectory, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range eventIDs {
		var count int
		if err := db.QueryRow("SELECT count(*) FROM events WHERE id=? AND accepted IS NULL AND exported IS NOT NULL", id).Scan(&count); err != nil || count != 1 {
			db.Close()
			t.Fatal("current event lost", id, count, err)
		}
	}
	db.Close()
	ids := kernelLegacyJSONLIDs(t)
	for _, id := range eventIDs {
		if !ids[id] {
			t.Fatal("rollback JSONL cannot replay current ID", id)
		}
	}
	rollbackID := oldEvent("after-rollback")
	if got := kernelLegacyBaseline(t, baselinePath); got != baseline {
		t.Fatal("existing baseline changed during rollback")
	}
	// Completed rollback inspection cannot restart any of the original processes.
	before := map[string]int{}
	for _, id := range originals {
		state, err := host.dockerRuntime(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		before[id] = state.State.Pid
	}
	for _, phase := range rollback {
		r.Phase, r.Operation = phase, "inspect"
		requireResult(t, j.Handle(r), "complete", "ok")
	}
	for _, id := range originals {
		state, err := host.dockerRuntime(ctx, id)
		if err != nil || state.State.Pid != before[id] {
			t.Fatal("rollback inspection restarted original", err)
		}
	}
	if !kernelLegacyJSONLIDs(t)[rollbackID] {
		t.Fatal("restored actual v2 Agent cannot export new event")
	}
	t.Logf("published v2.0.34 + real active Vector/exporter (pure Compose=%t) -> %s -> original exact three IDs: consistent backup, fresh mTLS/YARA, current SQLite and old/new JSONL IDs retained; restored Agent generated another event", pureCompose, mode)
}

func kernelLegacyJSONLIDs(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(agentLogDirectory, "events-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 4096), 2<<20)
		for s.Scan() {
			var p struct {
				ID string `json:"event_id"`
			}
			if json.Unmarshal(s.Bytes(), &p) != nil || p.ID == "" {
				f.Close()
				t.Fatal("invalid legacy JSONL")
			}
			ids[p.ID] = true
		}
		err = s.Err()
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return ids
}

// Query only the fixed test file. The real original Agent must have created
// this baseline; the test neither seeds nor restores any manifest rows.
func kernelLegacyBaseline(t *testing.T, path string) [2]string {
	t.Helper()
	db, err := persist.OpenReadOnly(filepath.Join(agentDataDirectory, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var record [2]string
	if err := db.QueryRow("SELECT hash,stat FROM manifest WHERE path=?", path).Scan(&record[0], &record[1]); err != nil || record[0] == "" || record[1] == "" {
		t.Fatal("original baseline not present", err)
	}
	return record
}
