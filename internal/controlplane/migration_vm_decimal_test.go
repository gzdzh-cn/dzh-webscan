package controlplane

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMigrationVMDecimalFixedCodecAndConflictBoundary(t *testing.T) {
	cases := []struct{ input, want float64 }{{2.7993779160186625, 2.799377916018}, {-2.7993779160186625, -2.799377916018}, {0, 0}, {-0.0, 0}, {37, 37}, {1.000000000000001, 1}, {-1.000000000000001, -1}, {123456, 123456}}
	for _, tc := range cases {
		got, e := migrationVMDecimalSeries([]float64{tc.input})
		if e != nil || len(got) != 1 || got[0] != tc.want {
			t.Fatalf("codec %g actual %.17g wanted %.17g err %v", tc.input, got[0], tc.want, e)
		}
	}
	for _, bad := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		if _, e := migrationVMDecimalSeries([]float64{bad}); e == nil {
			t.Fatal("nonfinite input accepted")
		}
	}
	got, e := migrationVMDecimalSeries([]float64{math.MinInt64, math.MaxFloat64, math.SmallestNonzeroFloat64})
	if e != nil || len(got) != 3 {
		t.Fatal("mixed-scale finite input", e)
	}
	raw := []byte(`{"metric":{"__name__":"probe","node_id":"isolated"},"values":[2.7993779160186625],"timestamps":[1]}`)
	want, e := migrationRecoveryExpectedMetricMap(raw)
	if e != nil {
		t.Fatal(e)
	}
	actual, e := migrationRecoveryMetricMap([]byte(strings.ReplaceAll(string(raw), "2.7993779160186625", "2.799377916018")))
	if e != nil || !migrationRecoveryMetricContains(actual, want, true) {
		t.Fatal("legal VM scalar codec rejected", e)
	}
	wrong, _ := migrationRecoveryMetricMap([]byte(strings.ReplaceAll(string(raw), "2.7993779160186625", "2.799377916017")))
	if migrationRecoveryMetricContains(wrong, want, true) {
		t.Fatal("adjacent but distinct decimal value accepted")
	}
	// The full archive comparison intentionally keeps actual-to-actual exact.
	archive, _ := migrationRecoveryHostMetricMap([]migrationMetricLine{{Metric: map[string]string{"__name__": "probe"}, Values: []float64{2.7993779160186625}, Timestamps: []int64{1}}})
	changed, _ := migrationRecoveryHostMetricMap([]migrationMetricLine{{Metric: map[string]string{"__name__": "probe"}, Values: []float64{2.799377916018}, Timestamps: []int64{1}}})
	if migrationRecoveryMetricContains(changed, archive, true) {
		t.Fatal("archive comparison was relaxed")
	}
}

func TestMigrationVMDecimalActualEngineMixedScalesAndSignedValues(t *testing.T) {
	address := os.Getenv("WEBSCAN_V3_TEST_VM")
	if address == "" {
		t.Skip("isolated actual VM required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c := Config{}
	c.Metrics.QueryURL, c.Metrics.WriteURL = address, address
	m := migrationRecoveryHostMetrics(c)
	node := "codec-" + token()[:12]
	values := [][]float64{{2.7993779160186625, -2.7993779160186625, 0, 37, -37, 1.000000000000001, -1.000000000000001}, {1e20, 1e-16, -1e20, 1e8, -1e8, 0}, {math.Exp2(63), -math.Exp2(63), math.Exp2(64), 1234567890123456}, {math.MaxFloat64, math.SmallestNonzeroFloat64, -math.SmallestNonzeroFloat64}}
	at := time.Now().Add(-time.Minute).UnixMilli()
	for i, group := range values {
		times := make([]int64, len(group))
		for j := range times {
			times[j] = at + int64(j)
		}
		line := migrationMetricLine{Metric: map[string]string{"__name__": "codec_probe_" + string(rune('a'+i)), "node_id": node}, Values: group, Timestamps: times}
		raw, e := json.Marshal(line)
		if e != nil {
			t.Fatal(e)
		}
		if e = m.writeMetricPayload(ctx, address, raw); e != nil {
			t.Fatal(e)
		}
		if e = migrationRecoveryVerifyLayer(ctx, m, node, raw, times[0], times[len(times)-1], false); e != nil {
			probeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			actual, actualErr := migrationRecoveryMetricsExport(probeCtx, m, node, times[0], times[len(times)-1])
			stop()
			want, wantErr := migrationRecoveryExpectedMetricMap(raw)
			t.Logf("synthetic codec wanted=%v actual=%v expected_error=%v export_error=%v", want, actual, wantErr, actualErr)
			t.Fatalf("actual fixed-codec group %d rejected: %v", i, e)
		}
	}
}
