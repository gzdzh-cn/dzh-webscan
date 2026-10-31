package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real immutable VictoriaMetrics executable, not an HTTP/storage mock. All
// storage and listeners belong to this test; no production database, network
// or notification service is used. tmpfs runs do not prove disk durability.
func TestMetricsSnapshotActualSingleServerLinux(t *testing.T) {
	binary := os.Getenv("WEBSCAN_V3_TEST_VM_EXECUTABLE")
	if binary == "" {
		t.Skip("explicit isolated VictoriaMetrics Linux executable required")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Fatal("requires isolated Linux amd64 root runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	parent := privateTestDir(t)
	start := func(directory string) string {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		listener.Close()
		log, err := os.OpenFile(directory+".test.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		child, stop := context.WithCancel(ctx)
		command := exec.CommandContext(child, binary, "-storageDataPath="+directory, "-httpListenAddr="+address, "-retentionPeriod=15d", "-search.latencyOffset=0s")
		command.Stdout, command.Stderr = log, log
		if err := command.Start(); err != nil {
			stop()
			log.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { stop(); _ = command.Wait(); log.Close() })
		endpoint := "http://" + address
		client := &http.Client{Timeout: time.Second}
		for attempt := 0; attempt < 150; attempt++ {
			response, err := client.Get(endpoint + "/health")
			if err == nil {
				response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return endpoint
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("isolated VM did not start")
			case <-time.After(100 * time.Millisecond):
			}
		}
		raw, _ := os.ReadFile(directory + ".test.log")
		t.Fatalf("isolated VM health failed: %s", raw)
		return ""
	}
	storage := filepath.Join(parent, "source")
	if err := os.Mkdir(storage, 0700); err != nil {
		t.Fatal(err)
	}
	endpoint := start(storage)
	client := &http.Client{Timeout: 5 * time.Second}
	stamp := time.Now().Add(-time.Minute).UnixMilli()
	write := func(name, value string) {
		t.Helper()
		response, err := client.Post(endpoint+"/api/v1/import/prometheus", "text/plain", strings.NewReader(fmt.Sprintf("%s{node_id=\"isolated-backup\"} %s %d\n", name, value, stamp)))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
			t.Fatal("isolated import failed", response.StatusCode)
		}
	}
	query := func(base, name string) []json.RawMessage {
		t.Helper()
		values := url.Values{"query": {name + `{node_id="isolated-backup"}`}, "time": {strconv.FormatInt(stamp/1000+1, 10)}, "nocache": {"1"}}
		response, err := client.Get(base + "/api/v1/query?" + values.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result struct {
			Status string `json:"status"`
			Data   struct {
				Result []json.RawMessage `json:"result"`
			} `json:"data"`
		}
		if json.NewDecoder(response.Body).Decode(&result) != nil || result.Status != "success" {
			t.Fatal("isolated query failed")
		}
		return result.Data.Result
	}
	write("webscan_backup_probe", "12.5")
	v := metricsSnapshotStore{URL: endpoint, Directory: storage, HTTP: client}
	// A pre-existing snapshot is outside the current operation's authority.
	raw, err := v.request(ctx, "create", "")
	var preserved struct{ Snapshot string }
	if err != nil || json.Unmarshal(raw, &preserved) != nil || !validMetricsSnapshotName(preserved.Snapshot) {
		t.Fatal("cannot create isolated preserved snapshot", err)
	}
	receipt, err := v.backup(ctx, filepath.Join(parent, "backup"))
	if err != nil || !receipt.SnapshotClean || receipt.Files < 1 || receipt.Bytes < 1 {
		t.Fatalf("actual snapshot backup failed: %+v %v", receipt, err)
	}
	var list struct {
		Snapshots []string `json:"snapshots"`
	}
	raw, err = v.request(ctx, "list", "")
	if err != nil || json.Unmarshal(raw, &list) != nil || len(list.Snapshots) != 1 || list.Snapshots[0] != preserved.Snapshot {
		t.Fatal("did not preserve unrelated snapshot or did not clean own snapshot", list, err)
	}
	// Concurrent callers may copy independently, but an atomic publication
	// race must produce one winner without replacing its verified archive.
	type outcome struct {
		receipt metricsSnapshotReceipt
		err     error
	}
	outcomes := make(chan outcome, 2)
	var entered atomic.Int32
	barrier := make(chan struct{})
	concurrent := v
	concurrentClient := *client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	concurrentClient.Transport = metricsSnapshotTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/snapshot/create" {
			if entered.Add(1) == 2 {
				close(barrier)
			}
			select {
			case <-barrier:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return transport.RoundTrip(r)
	})
	concurrent.HTTP = &concurrentClient
	raceContext, cancelRace := context.WithTimeout(ctx, 10*time.Second)
	defer cancelRace()
	for range 2 {
		go func() {
			r, e := concurrent.backup(raceContext, filepath.Join(parent, "competing"))
			outcomes <- outcome{r, e}
		}()
	}
	succeeded := 0
	for range 2 {
		result := <-outcomes
		if result.err == nil {
			succeeded++
			if !result.receipt.SnapshotClean {
				t.Fatal("concurrent winner did not clean its snapshot")
			}
			if _, err := verifyMetricsSnapshot(ctx, result.receipt.Directory, result.receipt.ManifestSHA256); err != nil {
				t.Fatal("concurrent publication corrupted winner", err)
			}
		}
	}
	if succeeded != 1 || entered.Load() != 2 {
		t.Fatal("concurrent backup publication did not have exactly one winner after both captures", succeeded, entered.Load())
	}
	raw, err = v.request(ctx, "list", "")
	if err != nil || json.Unmarshal(raw, &list) != nil || len(list.Snapshots) != 1 || list.Snapshots[0] != preserved.Snapshot {
		t.Fatal("concurrent cleanup affected unrelated snapshot", list, err)
	}
	// Querying the running source after the backup must not change the frozen
	// tree. The restored process must not see this later metric.
	write("webscan_after_backup_probe", "99")
	if raw, err := v.request(ctx, "create", ""); err != nil || len(raw) == 0 {
		t.Fatal("cannot flush post-backup source", err)
	}
	if result := query(endpoint, "webscan_after_backup_probe"); len(result) != 1 {
		t.Fatal("post-backup control metric absent on source", result)
	}
	if _, err := verifyMetricsSnapshot(ctx, receipt.Directory, receipt.ManifestSHA256); err != nil {
		t.Fatal("live writes changed archive", err)
	}
	restored := filepath.Join(parent, "restored")
	request, _ := json.Marshal(metricsSnapshotRestoreSpec{Format: 1, Directory: receipt.Directory, ManifestSHA256: receipt.ManifestSHA256})
	sourceFile := filepath.Join(parent, "restore-request.json")
	if err := os.WriteFile(sourceFile, request, 0600); err != nil {
		t.Fatal(err)
	}
	var commandOutput bytes.Buffer
	if err := Command(ctx, Options{Action: "verify-metrics-backup", Source: sourceFile}, nil, &commandOutput); err != nil || !bytes.Contains(commandOutput.Bytes(), []byte(`"state":"verified"`)) {
		t.Fatal("local verify command failed", err)
	}
	commandOutput.Reset()
	if err := Command(ctx, Options{Action: "restore-metrics-offline", Source: sourceFile, Output: restored}, nil, &commandOutput); err != nil || !bytes.Contains(commandOutput.Bytes(), []byte(`"runtime_started":false`)) {
		t.Fatal(err)
	}
	newEndpoint := start(restored)
	result := query(newEndpoint, "webscan_backup_probe")
	if len(result) != 1 || !bytes.Contains(result[0], []byte(`"12.5"`)) {
		t.Fatal("restored real server lost original metric", result)
	}
	if result := query(newEndpoint, "webscan_after_backup_probe"); len(result) != 0 {
		t.Fatal("restored checkpoint contains later live data", result)
	}
	t.Logf("actual VM snapshot, independent copy, exact cleanup and fresh offline restore passed: %d files, %d bytes", receipt.Files, receipt.Bytes)
}
