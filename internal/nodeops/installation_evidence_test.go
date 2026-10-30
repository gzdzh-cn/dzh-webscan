package nodeops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallationEvidenceBindsFinalReceiptAndReadOnlyReplay(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x, _, j := groupLifecycleFixture(t, "docker", mode)
			convertGroupToCompose(t, x)
			r := x.r
			finishThrough(t, j, r, "verify")
			r.Phase = "finalize"
			result := j.Handle(r)
			requireResult(t, result, "complete", "ok")
			if result.Installation == nil || !result.Installation.Valid() {
				t.Fatal("final receipt lacks installation evidence")
			}
			capture, err := readPrivate(filepath.Join(x.f.g.backup.directory(r), "capture/intent.json"), 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			active, err := readPrivate(filepath.Join(x.f.g.host.root, "active.json"), MaxRequestBytes)
			if err != nil {
				t.Fatal(err)
			}
			if result.Installation.CaptureSHA256 != sha(capture) || result.Installation.ActiveSHA256 != sha(active) {
				t.Fatal("receipt does not bind actual capture and active pointer")
			}
			before := len(x.f.mutations())
			r.Operation = "inspect"
			replay := j.Handle(r)
			requireResult(t, replay, "complete", "ok")
			if replay.Installation == nil || *replay.Installation != *result.Installation || len(x.f.mutations()) != before {
				t.Fatal("replay changed evidence or services")
			}
			if err := os.WriteFile(filepath.Join(x.f.g.backup.directory(r), "capture/intent.json"), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			rejected := j.Handle(r)
			if rejected.Code == "ok" || rejected.Installation != nil || len(x.f.mutations()) != before {
				t.Fatal("damaged capture produced valid evidence or changed services")
			}
		})
	}
}
