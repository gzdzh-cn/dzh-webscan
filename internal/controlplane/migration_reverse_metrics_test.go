package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

// Real isolated PG and two independently running VM engines exercise actual
// import/export. The install resolver and systemd/process observer are unit
// boundaries here; this is not a replacement for the Linux host/kernel suite.
func migrationReverseMetricsFixture(t *testing.T, nonempty bool) (*Store, Config, *MigrationLegacySink, *Vault, singleBackupSpec, migrationReverseMetricsRuntime, int64, []string) {
	t.Helper()
	history, raw := os.Getenv("WEBSCAN_V3_TEST_REVERSE_VM"), os.Getenv("WEBSCAN_V3_TEST_REVERSE_RAW_VM")
	if history == "" || raw == "" || history == raw {
		t.Skip("dedicated isolated history and raw VM engines required")
	}
	s, id := migrationTargetJournalFixture(t)
	root := privateTestDir(t)
	c := Config{}
	c.Central.Topology, c.Central.Instance = "single", "reverse-metrics-synthetic"
	c.Database.DSNFile = filepath.Join(root, "dsn")
	c.Metrics.QueryURL, c.Metrics.WriteURL, c.Metrics.RawURL = history, history, raw
	localWrite(t, c.Database.DSNFile, []byte("synthetic-private-binding-not-a-production-DSN"))
	original := singleBackupSpec{Format: 1, Installation: filepath.Join(root, "installation.json"), HostConfig: filepath.Join(root, "executor.yaml"), APIConfig: filepath.Join(root, "config.yaml"), ComposeFile: filepath.Join(root, "compose.yaml")}
	stack := filepath.Join(root, "stack.service")
	localWrite(t, stack, []byte("[Unit]\nDescription=isolated reverse metrics observation\n"))
	localWrite(t, filepath.Join(root, "webscan"), []byte("synthetic-owner-binary-only-not-executed"))
	p := singleBackupPlan{spec: singleInstallSpec{Root: root}, config: c, request: original, installation: digest([]byte("synthetic-original-installation")), bindings: map[string]string{stack: digest([]byte("[Unit]\nDescription=isolated reverse metrics observation\n"))}}
	r := migrationReverseMetricsRuntime{plan: func(_ context.Context, spec singleBackupSpec, _ string) (singleBackupPlan, error) {
		if !reflect.DeepEqual(spec, original) {
			return singleBackupPlan{}, ErrMigrationSession
		}
		return p, nil
	}, host: migrationRecoveryHostObservedFixture(t, p)}
	sink := &MigrationLegacySink{session: id, output: filepath.Join(root, "sink")}
	if e := os.Mkdir(sink.output, 0700); e != nil {
		t.Fatal(e)
	}
	v, _ := testVault(t)
	nodes := []string{}
	if nonempty {
		for _, suffix := range []string{"current", "baseline-retired"} {
			n := "reverse-" + suffix + "-" + token()[:12]
			if e := s.PutNode(context.Background(), nodeFixture(n), 0, 256); e != nil {
				t.Fatal(e)
			}
			nodes = append(nodes, n)
		}
	}
	armed, e := s.ArmMigrationTargetJournal(context.Background(), id, 1)
	if e != nil {
		t.Fatal(e)
	}
	if nonempty {
		n := "reverse-created-retired-" + token()[:12]
		if e = s.PutNode(context.Background(), nodeFixture(n), 0, 256); e != nil {
			t.Fatal(e)
		}
		nodes = append(nodes, n)
		if _, e = s.DB.Exec(`DELETE FROM v3_node_configurations WHERE node=ANY($1::text[])`, nodes[1:]); e != nil {
			t.Fatal(e)
		}
		if _, e = s.DB.Exec(`DELETE FROM v3_nodes WHERE id=ANY($1::text[])`, nodes[1:]); e != nil {
			t.Fatal(e)
		}
	}
	sealed, e := s.SealMigrationTargetJournal(context.Background(), id, armed.SessionVersion)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		for _, endpoint := range []string{history, raw} {
			for _, node := range nodes {
				migrationReverseMetricsDelete(t, endpoint, node)
			}
		}
	})
	return s, c, sink, v, original, r, sealed.SessionVersion, nodes
}
func migrationReverseMetricsDelete(t *testing.T, endpoint, node string) {
	t.Helper()
	q := url.Values{"match[]": {`{node_id=` + strconvQuote(node) + `}`}}
	r, e := http.Post(endpoint+"/api/v1/admin/tsdb/delete_series?"+q.Encode(), "application/octet-stream", nil)
	if e != nil {
		t.Error("cleanup synthetic series", e)
		return
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode != 204 && r.StatusCode != 200 {
		t.Error("cleanup synthetic series", r.StatusCode)
	}
}
func strconvQuote(s string) string { raw, _ := json.Marshal(s); return string(raw) }
func migrationReverseMetricsImport(t *testing.T, c Config, node string, at int64) {
	t.Helper()
	for _, layer := range migrationReverseMetricsLayers(c) {
		name := "webscan_derived_cpu_percent"
		metric := map[string]string{"__name__": name, "node_id": node, "source": "central"}
		if layer.name == "raw" {
			metric = map[string]string{"__name__": "node_disk_read_bytes_total", "node_id": node, "device": "nvme0n1", "mountpoint": "/srv/a,b", "fstype": "ext4"}
		}
		line := migrationMetricLine{Metric: metric, Values: []float64{0, 2.7993779160186625, 19}, Timestamps: []int64{at, at + 23, at + 30017}}
		if e := layer.metrics.writeMetricPayload(context.Background(), layer.metrics.WriteURL, append(common.JSON(line), '\n')); e != nil {
			t.Fatal(e)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			data, _, count, e := migrationReverseMetricsFetch(context.Background(), layer.metrics, node, 1, time.Now().Add(5*time.Minute).UnixMilli())
			if e == nil && count == 3 && bytes.Contains(data, []byte("mountpoint")) == (layer.name == "raw") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("real VM import not visible", layer.name, e, count)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}
func migrationReverseMetricsVerify(t *testing.T, s *Store, c Config, sink *MigrationLegacySink, v *Vault, r migrationReverseMetricsRuntime) (string, error) {
	t.Helper()
	tx, e := s.DB.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	defer tx.Rollback()
	return verifyMigrationReverseMetricsTx(context.Background(), tx, c, sink.session, sink, v, r)
}

func TestMigrationReverseMetricsActualEmptyDualStoreRequiresLiveProof(t *testing.T) {
	s, c, sink, v, original, r, version, _ := migrationReverseMetricsFixture(t, false)
	tx, e := s.DB.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = migrationReverseMetricsStateTx(context.Background(), tx, sink.session, sink); e != nil {
		t.Fatal("state", e)
	}
	p, _, _, e := migrationReverseMetricsPlan(context.Background(), tx, c, sink, original, r)
	if e != nil {
		t.Fatal("plan", e)
	}
	if _, e = r.host.isolation(context.Background(), p); e != nil {
		t.Fatal("isolation", e)
	}
	tx.Rollback()
	for _, l := range migrationReverseMetricsLayers(c) {
		if _, e = migrationReverseMetricsInventory(context.Background(), l.metrics, time.Now().Add(5*time.Minute).UnixMilli(), nil); e != nil {
			t.Fatal("inventory", l.name, e)
		}
	}
	if _, e := migrationReverseMetricsVerify(t, s, c, sink, v, r); e == nil {
		t.Fatal("absence of a manifest was accepted as empty")
	}
	bad := r
	bad.host.processes = func(context.Context, singleBackupPlan) (string, error) { return "", ErrMigrationRecovery }
	if _, e := s.archiveMigrationReverseMetrics(context.Background(), c, sink.session, version, sink, v, original, bad); e == nil {
		t.Fatal("active writer was accepted")
	}
	report, e := s.archiveMigrationReverseMetrics(context.Background(), c, sink.session, version, sink, v, original, r)
	if e != nil || !report.Complete || report.Points != 0 || report.Nodes != 0 || !releaseDigest(report.ManifestSHA256) {
		t.Fatal(report, e)
	}
	if hash, e := migrationReverseMetricsVerify(t, s, c, sink, v, r); e != nil || hash != report.ManifestSHA256 {
		t.Fatal("actual empty store proof", hash, e)
	}
	if _, e := migrationReverseMetricsVerify(t, s, c, sink, v, bad); e == nil {
		t.Fatal("old empty receipt overrode a new running writer")
	}
	drift := c
	drift.Metrics.RawURL = "http://127.0.0.1:1"
	if _, e := migrationReverseMetricsVerify(t, s, drift, sink, v, r); e == nil {
		t.Fatal("runtime target drift accepted")
	}
}

func TestMigrationReverseMetricsActualFullDualStorePreservesMillisecondsAndRemovedNodes(t *testing.T) {
	s, c, sink, v, original, r, version, nodes := migrationReverseMetricsFixture(t, true)
	at := time.Now().Add(-2 * time.Minute).UnixMilli()
	for _, node := range nodes {
		migrationReverseMetricsImport(t, c, node, at)
	}
	// A successful latest node status is neither supplied nor required: full
	// samples exist only in the two real VM engines and retired node journal.
	report, e := s.archiveMigrationReverseMetrics(context.Background(), c, sink.session, version, sink, v, original, r)
	if e != nil || !report.Complete || report.Nodes != 3 || report.Points != 18 || !strings.Contains(report.LegacyUI, "旧版页面") {
		t.Fatal(report, e)
	}
	m, exists, e := migrationReverseMetricsReadManifest(sink)
	if e != nil || !exists || len(m.Layers) != 2 {
		t.Fatal(m, e)
	}
	if len(m.Layers[0].Nodes) != 3 || len(m.Layers[1].Nodes) != 3 {
		t.Fatal("retired node omitted")
	}
	for _, layer := range m.Layers {
		for _, chunk := range layer.Chunks {
			raw, e := os.ReadFile(filepath.Join(sink.output, "metrics-history", chunk.File))
			if e != nil {
				t.Fatal(e)
			}
			var line migrationMetricLine
			if json.Unmarshal(bytes.TrimSpace(raw), &line) != nil {
				t.Fatal("one synthetic series expected")
			}
			if len(line.Timestamps) != 3 || line.Timestamps[0] != at || line.Timestamps[1] != at+23 || line.Timestamps[2] != at+30017 || line.Values[0] != 0 {
				t.Fatal("milliseconds/zero lost", line)
			}
			if layer.Name == "raw" && (line.Metric["mountpoint"] != "/srv/a,b" || line.Metric["device"] != "nvme0n1" || line.Metric["fstype"] != "ext4") {
				t.Fatal("raw dimensions lost", line.Metric)
			}
		}
	}
	if hash, e := migrationReverseMetricsVerify(t, s, c, sink, v, r); e != nil || hash != report.ManifestSHA256 {
		t.Fatal("intact actual export", hash, e)
	}
	again, e := s.archiveMigrationReverseMetrics(context.Background(), c, sink.session, version, sink, v, original, r)
	if e != nil || again.ManifestSHA256 != report.ManifestSHA256 {
		t.Fatal("retry rewrote immutable archive", again, e)
	}
	chunk := m.Layers[1].Chunks[0]
	file := filepath.Join(sink.output, "metrics-history", chunk.File)
	actual, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, append(append([]byte{}, actual...), byte(' ')), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = migrationReverseMetricsVerify(t, s, c, sink, v, r); e == nil {
		t.Fatal("archive tamper accepted")
	}
	if e = os.WriteFile(file, actual, 0600); e != nil {
		t.Fatal(e)
	} // test-only restore.
	if _, e = s.DB.Exec(`UPDATE v3_migration_reverse_metric_receipts SET target_digest=repeat('f',64) WHERE session=$1`, sink.session); e != nil {
		t.Fatal(e)
	}
	if _, e = migrationReverseMetricsVerify(t, s, c, sink, v, r); e == nil {
		t.Fatal("receipt tamper accepted")
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_reverse_metric_receipts SET target_digest=$2 WHERE session=$1`, sink.session, m.Target); e != nil {
		t.Fatal(e)
	}
	bad := r
	bad.host.processes = func(context.Context, singleBackupPlan) (string, error) { return "", ErrMigrationRecovery }
	if _, e = migrationReverseMetricsVerify(t, s, c, sink, v, bad); e == nil {
		t.Fatal("running writer accepted from stale manifest")
	}
	// An unrecorded version increment is not a lost reply.
	if _, e = s.DB.Exec(`UPDATE v3_migration_sessions SET version=version+1 WHERE id=$1`, sink.session); e != nil {
		t.Fatal(e)
	}
	if _, e = migrationReverseMetricsVerify(t, s, c, sink, v, r); e == nil {
		t.Fatal("unrelated newer version accepted")
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_sessions SET version=version-1 WHERE id=$1`, sink.session); e != nil {
		t.Fatal(e)
	}
	// The only version exception is a real independently authenticated final
	// rollback receipt. Its business mapping is exercised by the cutover suite.
	evidence := MigrationLegacyProjectionEvidence{Session: sink.session, Phase: "rollback", Verified: true, Coverage: "legacy-business-and-metric-archive", MetricsSHA256: report.ManifestSHA256, KeyID: v.active}
	evidence.SHA256 = migrationLegacyEvidenceMAC(v, evidence)
	encoded := common.JSON(evidence)
	proof := migrationCutoverProof(v, v.active, sink.session, "rollback", version, version+1, encoded)
	if _, e = s.DB.Exec(`INSERT INTO v3_migration_cutovers(session,action,request_version,finished_version,evidence,key_id,proof) VALUES($1,'rollback',$2,$3,$4,$5,$6)`, sink.session, version, version+1, encoded, v.active, proof); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_sessions SET phase='rolled_back',version=version+1 WHERE id=$1`, sink.session); e != nil {
		t.Fatal(e)
	}
	if _, e = migrationReverseMetricsVerify(t, s, c, sink, v, r); e != nil {
		t.Fatal("authenticated lost rollback response", e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_cutovers SET proof=repeat('a',64) WHERE session=$1 AND action='rollback'`, sink.session); e != nil {
		t.Fatal(e)
	}
	if _, e = migrationReverseMetricsVerify(t, s, c, sink, v, r); e == nil {
		t.Fatal("tampered lost-reply proof accepted")
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_cutovers SET proof=$2 WHERE session=$1 AND action='rollback'`, sink.session, proof); e != nil {
		t.Fatal(e)
	}
	// Deleting a raw history stream after archiving cannot be hidden by intact
	// derived history, PG receipts, or the last status snapshot.
	migrationReverseMetricsDelete(t, c.Metrics.RawURL, nodes[0])
	if _, e = migrationReverseMetricsVerify(t, s, c, sink, v, r); e == nil {
		t.Fatal("actual raw stream deletion accepted")
	}
}
