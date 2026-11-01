package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"webscan/internal/telemetry"
	agentv1 "webscan/sdk/agent/v1"
)

func deviceSample(at time.Time, value int, boot int, devices bool, omit string) *agentv1.MetricsSample {
	var raw strings.Builder
	fmt.Fprintf(&raw, "node_memory_MemTotal_bytes 1024\nnode_boot_time_seconds %d\n", boot)
	if devices {
		for _, metric := range consoleDeviceMetrics {
			if metric.Metric == omit {
				continue
			}
			name := "sda"
			if metric.Kind == "network" {
				name = "eth0"
			}
			fmt.Fprintf(&raw, "%s{device=%q} %d\n", metric.Raw, name, value)
		}
	}
	return &agentv1.MetricsSample{UnixMillis: at.UnixMilli(), PrometheusText: []byte(raw.String())}
}
func deviceSampleMetric(t *testing.T, sample *agentv1.MetricsSample, name, device string) (float64, bool) {
	t.Helper()
	metrics, e := telemetry.Parse(string(sample.PrometheusText))
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range metrics {
		if m.Name == name && m.Labels["device"] == device {
			return m.Value, true
		}
	}
	return 0, false
}
func TestDeviceDerivedRatesPreserveFirstResetMissingGapAndRebootAsUnknown(t *testing.T) {
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	offsets := []int{0, 30, 60, 90, 120, 150, 240, 270, 300, 330}
	samples := []*agentv1.MetricsSample{}
	for i, seconds := range offsets {
		boot := 1
		if i >= 8 {
			boot = 2
		}
		present := i != 3
		value := 100 * (i + 1)
		if i == 2 {
			value = 1
		}
		samples = append(samples, deviceSample(base.Add(time.Duration(seconds)*time.Second), value, boot, present, ""))
	}
	prepared, e := derivedSamples(samples, telemetry.Baseline{})
	if e != nil {
		t.Fatal(e)
	}
	for i, sample := range prepared {
		_, present := deviceSampleMetric(t, sample, "webscan_device_disk_read", "sda")
		want := i == 1 || i == 5 || i == 7 || i == 9
		if present != want {
			t.Fatal("unknown device rate became a value", i, present, want, string(sample.PrometheusText))
		}
		if i <= 3 {
			if _, present := deviceSampleMetric(t, sample, "webscan_device_disk_sample_time_seconds", "sda"); !present {
				t.Fatal("missing explicit current-sample marker", i)
			}
		}
	}
	if value, ok := deviceSampleMetric(t, prepared[1], "webscan_device_disk_read", "sda"); !ok || value != 100.0/30 {
		t.Fatal("device rate changed", value, ok)
	}
	if !strings.Contains(string(prepared[1].PrometheusText), "webscan_derived_disk_read{source=\"central\"}") {
		t.Fatal("aggregate regression")
	}
}
func TestDeviceDerivedNamespaceAndDeviceNamesAreBounded(t *testing.T) {
	now := time.Now().Add(-time.Minute).Truncate(time.Second)
	first := deviceSample(now, 100, 1, true, "")
	first.PrometheusText = append(first.PrometheusText, []byte("webscan_device_disk_read{source=\"central\",device=\"sda\"} 999\nnode_disk_read_bytes_total{device=\"bad/path\"} 10\n")...)
	prepared, e := derivedSamples([]*agentv1.MetricsSample{first}, telemetry.Baseline{})
	if e != nil {
		t.Fatal(e)
	}
	if _, present := deviceSampleMetric(t, prepared[0], "webscan_device_disk_read", "sda"); present {
		t.Fatal("agent spoofed central device namespace")
	}
	if _, present := deviceSampleMetric(t, prepared[0], "webscan_device_disk_sample_time_seconds", "bad/path"); present {
		t.Fatal("unbounded device identity persisted")
	}
	for _, name := range []string{"sda", "nvme0n1p1", "dm-0", "vethabc@if3", "eth0:1"} {
		id := consoleDeviceID("disk", name)
		kind, got, ok := decodeConsoleDeviceID(id)
		if !ok || kind != "disk" || got != name {
			t.Fatal("valid Linux device rejected", name)
		}
	}
	for _, id := range []string{"disk:", "unknown:c2Rh", "disk:L2Rldi9zZGE", "disk:YVwib3IgdmVjdG9yKDEp", "disk:" + strings.Repeat("a", 300), "disk:c2Rh="} {
		if _, _, ok := decodeConsoleDeviceID(id); ok {
			t.Fatal("noncanonical/injectable id accepted", id)
		}
	}
}
func TestDeviceDerivedMissingCounterDoesNotBecomeZero(t *testing.T) {
	now := time.Now().Add(-time.Minute).Truncate(time.Second)
	prepared, e := derivedSamples([]*agentv1.MetricsSample{deviceSample(now, 100, 1, true, ""), deviceSample(now.Add(30*time.Second), 200, 1, true, "net_receive_errors"), deviceSample(now.Add(time.Minute), 300, 1, true, "")}, telemetry.Baseline{})
	if e != nil {
		t.Fatal(e)
	}
	for _, index := range []int{1, 2} {
		if _, ok := deviceSampleMetric(t, prepared[index], "webscan_device_net_receive_errors", "eth0"); ok {
			t.Fatal("missing previous/current counter was filled")
		}
		if _, ok := deviceSampleMetric(t, prepared[index], "webscan_device_net_receive", "eth0"); !ok {
			t.Fatal("independent valid device counter was suppressed")
		}
	}
}
func TestDeviceMetricCursorRetainsBootAndPresenceAcrossCollectorRestart(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	node := nodeFixture("device-cursor")
	if e := s.PutNode(ctx, node, 0, 256); e != nil {
		t.Fatal(e)
	}
	lease, e := s.Acquire(ctx, shardResource(node.Shard), "device-cursor-worker")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().Add(-time.Minute).Truncate(time.Second)
	first := deviceSample(now, 100, 1, true, "")
	if e = s.CommitMetrics(ctx, node, lease, &agentv1.MetricsBatch{NodeId: node.ID, Samples: []*agentv1.MetricsSample{first}}, telemetry.Baseline{}); e != nil {
		t.Fatal(e)
	}
	_, baseline, e := s.MetricCursor(ctx, node.ID)
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := derivedSamples([]*agentv1.MetricsSample{deviceSample(now.Add(30*time.Second), 200, 1, true, "")}, baseline)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := deviceSampleMetric(t, prepared[0], "webscan_device_disk_read", "sda"); !ok {
		t.Fatal("collector restart discarded durable rate baseline")
	}
	changed, e := derivedSamples([]*agentv1.MetricsSample{deviceSample(now.Add(30*time.Second), 200, 2, true, "")}, baseline)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := deviceSampleMetric(t, changed[0], "webscan_device_disk_read", "sda"); ok {
		t.Fatal("persisted baseline hid a host reboot")
	}
}
func TestDeviceMetricsVictoriaMetricsActualHistoryAndUnknownGaps(t *testing.T) {
	baseURL := os.Getenv("WEBSCAN_V3_TEST_VM")
	if baseURL == "" {
		t.Skip("set WEBSCAN_V3_TEST_VM to isolated VictoriaMetrics")
	}
	metrics := &Metrics{WriteURL: baseURL, QueryURL: baseURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
	ctx := context.Background()
	node := "device-vm-" + token()[:12]
	base := time.Now().Add(-20 * time.Minute).Truncate(time.Second)
	samples := []*agentv1.MetricsSample{deviceSample(base, 100, 1, true, ""), deviceSample(base.Add(30*time.Second), 200, 1, true, ""), deviceSample(base.Add(time.Minute), 1, 1, true, ""), deviceSample(base.Add(90*time.Second), 200, 1, false, ""), deviceSample(base.Add(120*time.Second), 300, 1, true, ""), deviceSample(base.Add(150*time.Second), 400, 1, true, ""), deviceSample(base.Add(240*time.Second), 500, 1, true, ""), deviceSample(base.Add(270*time.Second), 600, 1, true, ""), deviceSample(base.Add(300*time.Second), 700, 2, true, ""), deviceSample(base.Add(330*time.Second), 800, 2, true, "")}
	prepared, e := derivedSamples(samples, telemetry.Baseline{})
	if e != nil {
		t.Fatal(e)
	}
	if e = metrics.Write(ctx, node, prepared); e != nil {
		t.Fatal(e)
	}
	// Raw-only historical identities remain selectable, but cannot invent a rate.
	rawOnly := &agentv1.MetricsSample{UnixMillis: base.UnixMilli(), PrometheusText: []byte("node_disk_read_bytes_total{device=\"old-disk\"} 25\n")}
	if e = metrics.Write(ctx, node, []*agentv1.MetricsSample{rawOnly}); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(20 * time.Second)
	var inventory consoleDeviceInventory
	for {
		inventory, e = metrics.consoleDeviceInventory(ctx, node, base, base.Add(420*time.Second))
		if e == nil && len(inventory.Items) == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual VM inventory missing", inventory, e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	ids := []string{consoleDeviceID("disk", "sda"), consoleDeviceID("network", "eth0"), consoleDeviceID("disk", "old-disk")}
	trend, e := metrics.consoleDeviceRange(ctx, node, base, base.Add(420*time.Second), ids)
	if e != nil {
		t.Fatal("actual fixed device query", e)
	}
	for _, point := range trend.Points {
		offset := point.Time - base.Unix()
		_, present := point.Values[consoleDeviceID("disk", "sda")+":disk_read"]
		want := offset == 30 || offset == 150 || offset == 180 || offset == 210 || offset == 270 || offset == 330 || offset == 360 || offset == 390
		if present != want {
			t.Fatal("actual VM filled missing/reset/reboot/gap or lost valid sample", offset, point.Values)
		}
		if _, present := point.Values[consoleDeviceID("disk", "old-disk")+":disk_read"]; present {
			t.Fatal("raw history was silently backfilled")
		}
	}
	for _, device := range inventory.Items {
		wantLast := base.Add(330 * time.Second).Unix()
		if device.Name == "old-disk" {
			wantLast = base.Unix()
		}
		if device.LastSeen == nil || *device.LastSeen != float64(wantLast) {
			t.Fatal("inventory fabricated last seen", device)
		}
	}
	other, e := metrics.consoleDeviceInventory(ctx, "different-"+token()[:12], base, base.Add(420*time.Second))
	if e != nil || len(other.Items) != 0 {
		t.Fatal("inventory escaped node scope", other, e)
	}
	old, e := metrics.consoleDeviceInventory(ctx, node, base.Add(-time.Hour), base.Add(-30*time.Second))
	if e != nil || len(old.Items) != 0 {
		t.Fatal("inventory ignored historical time window", old, e)
	}
}
