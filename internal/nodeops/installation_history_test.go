package nodeops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallationHistoryRequiresAnchoredRecoveryEvidence(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, damage := range []string{"missing-capture", "changed-capture", "missing-activation", "changed-snapshot", "wrong-target-anchor"} {
			t.Run(mode+"/"+damage, func(t *testing.T) {
				x, _, j := groupLifecycleFixture(t, "docker", mode)
				convertGroupToCompose(t, x)
				r := x.r
				finishThrough(t, j, r, "finalize")
				h := x.f.g.host
				if _, err := h.inventory(context.Background(), r.Node, mode); err != nil {
					t.Fatal("healthy installation", err)
				}
				var active ActiveInstallation
				if _, err := decodePrivateJSON(filepath.Join(h.root, "active.json"), &active, MaxRequestBytes); err != nil || !validDigest(active.CaptureSHA256) {
					t.Fatal("new pointer does not anchor capture", err)
				}
				root := filepath.Join(h.root, "transitions", r.Job)
				path := filepath.Join(root, "capture/intent.json")
				switch damage {
				case "missing-capture":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "changed-capture":
					var capture backupIntent
					if _, err := decodePrivateJSON(path, &capture, 4<<20); err != nil {
						t.Fatal(err)
					}
					capture.Installed.Sidecars = nil
					historyWriteJSON(t, path, capture)
				case "missing-activation":
					if err := os.Remove(filepath.Join(root, "activation/intent.json")); err != nil {
						t.Fatal(err)
					}
				case "changed-snapshot":
					path = filepath.Join(root, "snapshot/receipt.json")
					var snapshot backupSnapshot
					if _, err := decodePrivateJSON(path, &snapshot, 16<<20); err != nil {
						t.Fatal(err)
					}
					snapshot.IntentSHA256 = strings.Repeat("f", 64)
					historyWriteJSON(t, path, snapshot)
				case "wrong-target-anchor":
					active.CaptureSHA256 = strings.Repeat("f", 64)
					historyWriteJSON(t, filepath.Join(h.root, "active.json"), active)
				}
				before := len(x.f.mutations())
				if _, err := h.inventory(context.Background(), r.Node, mode); err == nil {
					t.Fatal("inventory accepted damaged history")
				}
				if len(x.f.mutations()) != before {
					t.Fatal("inspection changed services")
				}
			})
		}
	}
}

func TestInstallationHistoryRefusesRetiredAgentDrift(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, drift := range []string{"running", "restart", "retries", "name", "missing", "fingerprint"} {
			t.Run(mode+"/"+drift, func(t *testing.T) {
				x, _, j := groupLifecycleFixture(t, "docker", mode)
				convertGroupToCompose(t, x)
				r := x.r
				finishThrough(t, j, r, "finalize")
				h := x.f.g.host
				i, err := x.f.g.backup.readIntent(context.Background(), r)
				if err != nil {
					t.Fatal(err)
				}
				id := i.Installed.Services[0].ID
				c := x.f.m.containers[id]
				switch drift {
				case "running":
					c.Status = "running"
				case "restart":
					c.Restart = "always"
				case "retries":
					c.MaxRetries = 1
				case "name":
					c.Name = "/external-name"
				case "fingerprint":
					c.Image = "sha256:" + strings.Repeat("f", 64)
				}
				x.f.m.containers[id] = c
				if drift == "missing" {
					delete(x.f.m.containers, id)
				}
				before := len(x.f.mutations())
				if _, err := h.inventory(context.Background(), r.Node, mode); err == nil {
					t.Fatal("retired Agent drift accepted")
				}
				if len(x.f.mutations()) != before {
					t.Fatal("inspection changed services")
				}
			})
		}
	}
}

func TestActivationResumeRetainsUnanchoredPointer(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x, _, j := groupLifecycleFixture(t, "docker", mode)
			convertGroupToCompose(t, x)
			r := x.r
			finishThrough(t, j, r, "backup")
			r.Phase = "activate"
			if mode == "native" {
				a := *x.n
				b := *a.backup
				b.attachGroup(a.host, r)
				a.backup = &b
				p, err := a.plan(context.Background(), r)
				if err != nil {
					t.Fatal(err)
				}
				p.intent.Target.CaptureSHA256 = ""
				historyWriteJSON(t, x.n.intentPath(r), p.intent)
			} else {
				a := *x.d
				b := *a.backup
				b.attachGroup(a.host, r)
				a.backup = &b
				p, err := a.plan(context.Background(), r)
				if err != nil {
					t.Fatal(err)
				}
				p.intent.Target.CaptureSHA256 = ""
				historyWriteJSON(t, x.d.intentPath(r), p.intent)
			}
			finishThrough(t, j, r, "finalize")
			var active ActiveInstallation
			if _, err := decodePrivateJSON(filepath.Join(x.f.g.host.root, "active.json"), &active, MaxRequestBytes); err != nil || active.CaptureSHA256 != "" {
				t.Fatal("resume changed previously published pointer", err)
			}
			if _, err := x.f.g.host.inventory(context.Background(), r.Node, mode); err != nil {
				t.Fatal("legacy pointer rejected", err)
			}
		})
	}
}

func TestInstallationHistoryRejectsPredecessorCycle(t *testing.T) {
	x, _, j := groupLifecycleFixture(t, "docker", "native")
	convertGroupToCompose(t, x)
	r := x.r
	finishThrough(t, j, r, "finalize")
	h := x.f.g.host
	next := r
	next.Job, next.PlanDigest = "history-successor", strings.Repeat("e", 64)
	b := *x.f.g.backup
	b.host = h
	if _, err := b.prepareIntent(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(b.directory(next), "capture")
	var previous ActiveInstallation
	if _, err := decodePrivateJSON(filepath.Join(dir, "active.json"), &previous, MaxRequestBytes); err != nil {
		t.Fatal(err)
	}
	previous.Job, previous.PlanDigest, previous.CaptureSHA256 = next.Job, next.PlanDigest, ""
	historyWriteJSON(t, filepath.Join(dir, "active.json"), previous)
	raw, err := readPrivate(filepath.Join(dir, "active.json"), MaxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	var capture backupIntent
	if _, err := decodePrivateJSON(filepath.Join(dir, "intent.json"), &capture, 4<<20); err != nil {
		t.Fatal(err)
	}
	for index := range capture.Files {
		if capture.Files[index].Path == "active.json" {
			capture.Files[index].Bytes, capture.Files[index].SHA256 = int64(len(raw)), sha(raw)
		}
	}
	historyWriteJSON(t, filepath.Join(dir, "intent.json"), capture)
	raw, err = readPrivate(filepath.Join(dir, "intent.json"), 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	active := previous
	active.CaptureSHA256 = sha(raw)
	before := len(x.f.mutations())
	if _, err := h.installationHistory(context.Background(), &active); err == nil || err.Error() != "installation-history-invalid" {
		t.Fatal("predecessor cycle not rejected", err)
	}
	if len(x.f.mutations()) != before {
		t.Fatal("history traversal changed services")
	}
}

func TestRollbackRejectsContradictoryTargetCaptureAnchor(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			x, handler, j := groupLifecycleFixture(t, "docker", mode)
			convertGroupToCompose(t, x)
			r := x.r
			finishThrough(t, j, r, "finalize")
			path := filepath.Join(x.f.g.backup.directory(r), "activation/intent.json")
			if mode == "native" {
				var intent nativeActivationIntent
				if _, err := decodePrivateJSON(path, &intent, MaxRequestBytes); err != nil {
					t.Fatal(err)
				}
				intent.Target.CaptureSHA256 = strings.Repeat("f", 64)
				historyWriteJSON(t, path, intent)
			} else {
				var intent dockerActivationIntent
				if _, err := decodePrivateJSON(path, &intent, MaxRequestBytes); err != nil {
					t.Fatal(err)
				}
				intent.Target.CaptureSHA256 = strings.Repeat("f", 64)
				historyWriteJSON(t, path, intent)
			}
			before := len(x.f.mutations())
			r.Phase, r.Operation = "restore", "apply"
			if _, err := handler.Apply(r); err == nil {
				t.Fatal("rollback accepted contradictory capture anchor")
			}
			if len(x.f.mutations()) != before {
				t.Fatal("rollback changed services before proving capture")
			}
		})
	}
}

func historyWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
