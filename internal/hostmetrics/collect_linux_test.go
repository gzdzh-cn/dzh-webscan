//go:build linux

package hostmetrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostNamespaceAndCounters(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "1/net"), 0700)
	os.MkdirAll(filepath.Join(dir, "net"), 0700)
	for name, raw := range map[string]string{"stat": "cpu0 100 0 30 500 2 0 0 0 0 0\nbtime 100\n", "meminfo": "MemTotal: 4096 kB\nMemAvailable: 1024 kB\n", "loadavg": "1 2 3 1/2 4", "diskstats": "8 0 sda 10 0 20 0 30 0 40 0 0 0 0\n", "net/dev": "container: 999 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0", "1/net/dev": "eth0: 100 0 2 3 0 0 0 0 200 0 4 5 0 0 0 0", "1/mountinfo": ""} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
	}
	out := Collect(Paths{Proc: dir})
	for _, want := range []string{`node_cpu_seconds_total{cpu="0",mode="user"} 1`, `node_memory_MemTotal_bytes 4.194304e+06`, `node_disk_read_bytes_total{device="sda"} 10240`, `node_network_receive_bytes_total{device="eth0"} 100`} {
		if !strings.Contains(out, want) {
			t.Fatal(want, out)
		}
	}
	if strings.Contains(out, "container") {
		t.Fatal(out)
	}
}
func TestMissingCollectorDoesNotInventZero(t *testing.T) {
	out := Collect(Paths{Proc: t.TempDir()})
	if !strings.Contains(out, `webscan_host_collector_error{collector="memory"} 1`) || strings.Contains(out, "node_memory_MemTotal") {
		t.Fatal(out)
	}
}
