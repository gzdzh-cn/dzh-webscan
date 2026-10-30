package nodeops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequestDecodingBoundsAndWhitelistedFields(t *testing.T) {
	root := testRoot(t)
	r := testRequest(root)
	raw, _ := json.Marshal(r)
	if got, err := decodeRequest(strings.NewReader(string(raw))); err != nil || got.Job != r.Job {
		t.Fatal(err)
	}
	for _, input := range []string{string(raw) + "{}", string(raw) + strings.Repeat(" ", MaxRequestBytes), `{"command":"touch /tmp/forbidden"}`, strings.Replace(string(raw), `"protocol":1`, `"protocol":999`, 1), strings.Replace(string(raw), `"mode":"native"`, `"mode":"other"`, 1)} {
		if _, err := decodeRequest(strings.NewReader(input)); err == nil {
			t.Fatal("malformed or oversized request accepted")
		}
	}
	for _, change := range []func(*Request){func(r *Request) { r.Epoch = 0 }, func(r *Request) { r.Phase = "shell" }, func(r *Request) { r.Operation = "exec" }, func(r *Request) { r.Spec.MonitorDirectories = []string{"relative"} }, func(r *Request) { r.Spec.ArtifactBytes = 5 << 30 }} {
		bad := r
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid request accepted")
		}
	}
}
func TestLocalChecksReportMissingDirectoryWithoutChangingIt(t *testing.T) {
	root := testRoot(t)
	missing := filepath.Join(root, "not-created")
	spec := Spec{Mode: "native", MetricsPort: 19100, ArtifactBytes: 1024, MonitorDirectories: []string{root, missing}}
	out := localChecks(context.Background(), spec)
	foundGood, foundMissing := false, false
	for _, check := range out.Checks {
		if check.ID == "monitor-directory-1" && check.Status == "passed" {
			foundGood = true
		}
		if check.ID == "monitor-directory-2" && check.Status == "failed" {
			foundMissing = true
		}
		if check.ID == "disk" && check.Status != "unknown" && check.Required < 512<<20+2048 {
			t.Fatal("disk reservation not computed")
		}
	}
	if !foundGood || !foundMissing || !validOutcome(out) {
		t.Fatal("missing precise directory report")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("preflight created monitor directory", err)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), root) {
		t.Fatal("raw host path leaked through report")
	}
	// The shipped helper cannot pretend that a not-yet-implemented install phase
	// completed. It must not even create a task journal for an unsupported phase.
	j := openTestJournal(t, root, LocalPreflight{})
	r := testRequest(root)
	r.Phase = "activate"
	requireResult(t, j.Handle(r), "unknown", "executor-unavailable")
	if _, err := os.Stat(filepath.Join(root, "journal.sqlite3")); !os.IsNotExist(err) {
		t.Fatal("unsupported phase changed journal")
	}
}
func TestLocalPreflightFailureRetainsStructuredReasons(t *testing.T) {
	root := testRoot(t)
	j := openTestJournal(t, root, LocalPreflight{})
	r := testRequest(root)
	r.Spec.MonitorDirectories = []string{filepath.Join(root, "missing")}
	res := j.Handle(r)
	requireResult(t, res, "unknown", "preflight-failed")
	if len(res.Outcome.Checks) == 0 {
		t.Fatal("diagnostic report lost")
	}
	for _, c := range res.Outcome.Checks {
		if c.ID == "monitor-directory-1" && c.Status == "failed" {
			return
		}
	}
	t.Fatal("missing-directory reason not returned")
}
func TestOutputCaptureIsBounded(t *testing.T) {
	b := &boundedOutput{}
	data := []byte(strings.Repeat("a", 128<<10))
	n, err := b.Write(data)
	if err != nil || n != len(data) || len(b.raw) != 8192 {
		t.Fatal("unbounded diagnostic output")
	}
}

func TestListenerTablesDoNotTreatMissingEvidenceAsFreePort(t *testing.T) {
	root := testRoot(t)
	tcp, tcp6 := filepath.Join(root, "tcp"), filepath.Join(root, "tcp6")
	write := func(path, raw string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	header := "  sl  local_address rem_address   st\n"
	write(tcp, header)
	if occupied, known := listenerTables(19100, []string{tcp, tcp6}); occupied || !known {
		t.Fatal("disabled IPv6 should allow complete IPv4 evidence")
	}
	write(tcp6, header+" 0: 00000000000000000000000000000000:4A9C 00000000000000000000000000000000:0000 0A\n")
	if occupied, known := listenerTables(19100, []string{tcp, tcp6}); !occupied || !known {
		t.Fatal("IPv6 listener missed")
	}
	if occupied, known := listenerTables(19100, []string{filepath.Join(root, "missing"), tcp6}); !occupied || known {
		t.Fatal("missing IPv4 table presented as complete evidence")
	}
	if err := os.Remove(tcp6); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tcp6, 0700); err != nil {
		t.Fatal(err)
	}
	if _, known := listenerTables(19100, []string{tcp, tcp6}); known {
		t.Fatal("IPv6 read failure presented as free port")
	}
	write(tcp, "invalid table")
	if _, known := listenerTables(19100, []string{tcp}); known {
		t.Fatal("invalid table presented as free port")
	}
}
