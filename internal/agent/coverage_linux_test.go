//go:build linux

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
)

func TestCoverageRecoveryRefreshesStatusAndPreservesRejectedRules(t *testing.T) {
	a, ctx := testAgent(t)
	a.ready.Store(true)
	if err := a.status("applied", nil); err != nil {
		t.Fatal(err)
	}
	path := root(a)
	if err := os.Rename(path, path+".away"); err != nil {
		t.Fatal(err)
	}
	if err := a.refreshCoverage(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := common.ReadJSON(filepath.Join(a.Data, "rules-status.json"))
	if err != nil || common.I(status["coverage_ok"]) != 0 || common.S(common.M(status["coverage_error"])["code"]) != "watch_directory_missing" {
		t.Fatal("missing directory diagnosis not published", status, err)
	}
	if err := os.Rename(path+".away", path); err != nil {
		t.Fatal(err)
	}
	if err := a.refreshCoverage(ctx); err != nil {
		t.Fatal(err)
	}
	status, err = common.ReadJSON(filepath.Join(a.Data, "rules-status.json"))
	if err != nil || common.I(status["coverage_ok"]) != 1 || common.S(status["instance_id"]) != a.Instance || status["coverage_error"] != nil {
		t.Fatal("coverage recovered but status stayed stale", status, err)
	}
	b, err := os.ReadFile(common.S(a.C["metrics_file"]))
	if err != nil || !strings.Contains(string(b), "webscan_coverage_ok 1\n") {
		t.Fatal("live recovery metric missing", err)
	}
	if err := a.status("rejected", errors.New("invalid_yara_rules")); err != nil {
		t.Fatal(err)
	}
	if err := a.refreshCoverage(ctx); err != nil {
		t.Fatal(err)
	}
	status, _ = common.ReadJSON(filepath.Join(a.Data, "rules-status.json"))
	if common.S(status["state"]) != "rejected" || common.S(status["error"]) != "invalid_yara_rules" {
		t.Fatal("periodic coverage overwrote rejected rules", status)
	}
}

func TestWatchLimitFailureExplainsSharedHostQuota(t *testing.T) {
	a, _ := testAgent(t)
	a.recordWatchFailure(root(a), unix.ENOSPC)
	issue := a.watchFailure.Load()
	if issue.Code != "inotify_watch_limit" || !strings.Contains(issue.Message, "fs.inotify.max_user_watches") {
		t.Fatal("kernel watch quota failure not identified", issue)
	}
}
