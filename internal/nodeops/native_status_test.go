package nodeops

import (
	"strings"
	"testing"
)

// Actual systemctl 252 output captured in the isolated x86_64 guest. Job is
// present but empty when no job is queued, including for a missing unit.
const systemd252AbsentStatus = "MainPID=0\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\nUnitFileState=\nJob=\nNeedDaemonReload=no\n"

func TestNativeStatusAcceptsSystemctlUnsetJob(t *testing.T) {
	for _, job := range []string{"", "0"} {
		t.Run("absent-job-"+job, func(t *testing.T) {
			raw := strings.Replace(systemd252AbsentStatus, "Job=\n", "Job="+job+"\n", 1)
			if _, err := decodeNativeStatus(raw, false, true); err != nil {
				t.Fatal("absent unit with no queued job rejected", err)
			}
			if _, err := parseNativeStatus(raw); err == nil {
				t.Fatal("missing unit accepted as installed")
			}
		})
		t.Run("running-job-"+job, func(t *testing.T) {
			raw := "MainPID=123\nLoadState=loaded\nActiveState=active\nSubState=running\nFragmentPath=/etc/systemd/system/webscan-agent-native.service\nDropInPaths=\nUnitFileState=enabled\nJob=" + job + "\nNeedDaemonReload=no\n"
			status, err := parseNativeStatus(raw)
			if err != nil || status.MainPID != 123 || status.Job != job {
				t.Fatal("running unit with no queued job rejected", status, err)
			}
		})
	}
}

func TestNativeStatusStillRejectsMissingOrUnsafeJobs(t *testing.T) {
	for _, job := range []string{"12", "12 /org/freedesktop/systemd1/job/12", "00", "-1", " ", "unknown"} {
		t.Run("job-"+job, func(t *testing.T) {
			raw := strings.Replace(systemd252AbsentStatus, "Job=\n", "Job="+job+"\n", 1)
			if _, err := decodeNativeStatus(raw, true, true); err == nil {
				t.Fatal("queued or ambiguous job accepted")
			}
		})
	}
	for _, raw := range []string{strings.Replace(systemd252AbsentStatus, "Job=\n", "", 1), systemd252AbsentStatus + "Job=0\n"} {
		if _, err := decodeNativeStatus(raw, true, true); err == nil {
			t.Fatal("missing or duplicated Job property accepted")
		}
	}
}
