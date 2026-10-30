package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nextWrapperRequest(r Request) Request {
	r.Job += "-next"
	r.PlanDigest = strings.Repeat("7", 64)
	r.Spec.MetricsPort++
	r.Epoch++
	r.Phase = "backup"
	return r
}

func TestRetainedWrapperFreshTasksKeepOriginalAuthorityAndObject(t *testing.T) {
	for _, role := range []string{"vector", "exporter"} {
		for _, tls := range []bool{false, true} {
			t.Run(role+map[bool]string{false: "-http", true: "-https"}[tls], func(t *testing.T) {
				m := wrapperFixture(t, role, tls, true, true)
				originalID := m.o.Identity.ID
				if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
					t.Fatal(err)
				}
				pointer, _ := m.w.authorityPath(m.name)
				originRaw, err := readPrivate(pointer, MaxRequestBytes)
				if err != nil {
					t.Fatal(err)
				}
				originalIntent, _, err := m.w.read(m.r, m.name)
				if err != nil {
					t.Fatal(err)
				}
				r := m.r
				r.Phase = "restore"
				if err := m.w.restore(context.Background(), r, m.name); err != nil {
					t.Fatal(err)
				}
				for j := 0; j < 3; j++ {
					r = nextWrapperRequest(r)
					before := len(m.mutations())
					callsBefore := len(m.calls)
					i, err := m.w.capture(context.Background(), r, m.name)
					if err != nil {
						t.Fatal(err)
					}
					if len(m.mutations()) != before || i.RetainedSHA256 != sha(originRaw) || i.Binding != binding(r) || !bytes.Equal(i.Unit, originalIntent.Unit) || i.Object.Identity.ID != originalID || !i.Running || !i.Enabled {
						t.Fatal("fresh capture lost origin/current state")
					}
					immutableLookup := false
					for _, call := range m.calls[callsBefore:] {
						if strings.Contains(call, " image inspect "+m.image.ID+" ") {
							immutableLookup = true
						}
						if m.u.SourceImage != m.image.ID && strings.Contains(call, " image inspect "+m.u.SourceImage+" ") {
							t.Fatal("fresh task depends on mutable source alias")
						}
					}
					if !immutableLookup {
						t.Fatal("did not recheck immutable image")
					}
					if err := m.w.quiesce(context.Background(), r, m.name); err != nil {
						t.Fatal(err)
					}
					r.Phase = "restore"
					if err := m.w.restore(context.Background(), r, m.name); err != nil {
						t.Fatal(err)
					}
					if err := m.w.restored(context.Background(), r, m.name); err != nil {
						t.Fatal(err)
					}
					got, _ := readPrivate(pointer, MaxRequestBytes)
					if !bytes.Equal(got, originRaw) || m.o.Identity.ID != originalID {
						t.Fatal("rewrote root provenance or recreated object")
					}
				}
			})
		}
	}
}

func TestRetainedWrapperFreshCaptureRestoresObservedState(t *testing.T) {
	for _, role := range []string{"vector", "exporter"} {
		for _, running := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				t.Run(role+map[bool]string{false: "-stopped", true: "-running"}[running]+map[bool]string{false: "-disabled", true: "-enabled"}[enabled], func(t *testing.T) {
					m := wrapperFixture(t, role, false, true, true)
					if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
						t.Fatal(err)
					}
					r := m.r
					r.Phase = "restore"
					if err := m.w.restore(context.Background(), r, m.name); err != nil {
						t.Fatal(err)
					}
					m.running, m.enabled = running, enabled
					m.o.Identity.Status = "exited"
					if running {
						m.o.Identity.Status = "running"
					}
					r = nextWrapperRequest(r)
					i, err := m.w.capture(context.Background(), r, m.name)
					if err != nil || i.Running != running || i.Enabled != enabled {
						t.Fatal("used first task's old state", err)
					}
					// No quiesce in this task: aborting capture must retain the safe
					// unit, not write back the original destructive template.
					r.Phase = "restore"
					before := len(m.mutations())
					if err := m.w.restore(context.Background(), r, m.name); err != nil {
						t.Fatal(err)
					}
					if len(m.mutations()) != before || m.running != running || m.enabled != enabled {
						t.Fatal("capture-only abort changed observed state")
					}
				})
			}
		}
	}
}

func TestRetainedWrapperRejectsUnprovenHistoryAndExternalChanges(t *testing.T) {
	for _, change := range []string{"missing-pointer", "wrong-node", "wrong-name", "wrong-spec", "wrong-hash", "format", "unknown-field", "duplicate-field", "chain", "missing-origin", "changed-origin", "missing-quiesce", "changed-quiesce", "symlink", "hardlink", "mode", "directory-mode", "source-directory-mode", "owner", "pending-original", "missing-unit", "unit-other-id", "unit-hook", "object-id", "object-mount", "engine-policy", "runtime", "orphan-object", "pending-reload", "foreign-process"} {
		t.Run(change, func(t *testing.T) {
			m := wrapperFixture(t, "vector", true, true, true)
			if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
				t.Fatal(err)
			}
			pointer, _ := m.w.authorityPath(m.name)
			var p retainedWrapperAuthority
			raw, err := decodePrivateJSON(pointer, &p, MaxRequestBytes)
			if err != nil {
				t.Fatal(err)
			}
			dir, _ := m.w.directory(m.r, m.name)
			modified := false
			switch change {
			case "missing-pointer":
				os.Remove(pointer)
			case "wrong-node":
				p.Binding.Node = "other-node"
				modified = true
			case "wrong-name":
				p.Name = "webscan-exporter-v1.service"
				modified = true
			case "wrong-spec":
				p.Spec.MetricsPort++
				modified = true
			case "wrong-hash":
				p.IntentSHA256 = strings.Repeat("0", 64)
				modified = true
			case "format":
				p.Format = 2
				modified = true
			case "unknown-field":
				os.WriteFile(pointer, append(raw[:len(raw)-1], []byte(`,"extra":true}`)...), 0600)
			case "duplicate-field":
				os.WriteFile(pointer, append(raw[:len(raw)-1], []byte(`,"format":1}`)...), 0600)
			case "chain":
				i, _, err := m.w.read(m.r, m.name)
				if err != nil {
					t.Fatal(err)
				}
				i.RetainedSHA256 = strings.Repeat("1", 64)
				b, _ := json.Marshal(i)
				os.WriteFile(filepath.Join(dir, "intent.json"), b, 0600)
				p.IntentSHA256 = sha(b)
				modified = true
			case "missing-origin":
				os.Remove(filepath.Join(dir, "intent.json"))
			case "changed-origin":
				os.WriteFile(filepath.Join(dir, "intent.json"), []byte(`{}`), 0600)
			case "missing-quiesce":
				os.Remove(filepath.Join(dir, "quiesce.json"))
			case "changed-quiesce":
				os.WriteFile(filepath.Join(dir, "quiesce.json"), []byte(`{}`), 0600)
			case "symlink", "hardlink":
				other := filepath.Join(m.w.host.root, "pointer-copy")
				if err := os.WriteFile(other, raw, 0600); err != nil {
					t.Fatal(err)
				}
				os.Remove(pointer)
				if change == "symlink" {
					err = os.Symlink(other, pointer)
				} else {
					err = os.Link(other, pointer)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "mode":
				os.Chmod(pointer, 0644)
			case "directory-mode":
				os.Chmod(filepath.Dir(pointer), 0755)
			case "source-directory-mode":
				os.Chmod(dir, 0755)
			case "owner":
				if os.Geteuid() != 0 {
					t.Skip("requires root ownership test in isolated Linux verifier")
				}
				if err := os.Chown(pointer, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "pending-original":
				os.WriteFile(m.unit, m.u.definition(), 0644)
			case "missing-unit":
				os.Remove(m.unit)
			case "unit-other-id":
				os.WriteFile(m.unit, retainedWrapperUnit(m.u, strings.Repeat("2", 64)), 0600)
			case "unit-hook":
				b, _ := os.ReadFile(m.unit)
				os.WriteFile(m.unit, append(b, []byte("ExecStartPost=/bin/true\n")...), 0600)
			case "object-id":
				m.o.Identity.ID = strings.Repeat("2", 64)
			case "object-mount":
				m.o.Identity.Mounts[0].RW = true
			case "engine-policy":
				m.o.Identity.Restart = "always"
			case "runtime":
				b, _ := os.ReadFile(filepath.Join(m.w.host.configRoot, "runtime.json"))
				os.WriteFile(filepath.Join(m.w.host.configRoot, "runtime.json"), append(b, ' '), 0600)
			case "orphan-object":
				m.o.Identity.Status = "running"
			case "pending-reload":
				m.loaded = m.u.definition()
			case "foreign-process":
				m.running = true
				m.o.Identity.Status = "running"
				m.unknownProcess = true
			}
			if modified {
				b, _ := json.Marshal(p)
				if err := os.WriteFile(pointer, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := len(m.mutations())
			if _, _, err := m.w.retainedState(context.Background(), m.r.Node, m.name); err == nil {
				t.Fatal("accepted changed retained state")
			}
			if _, err := m.w.capture(context.Background(), nextWrapperRequest(m.r), m.name); err == nil {
				t.Fatal("new task adopted unproven history")
			}
			if len(m.mutations()) != before {
				t.Fatal("read-only checks changed service")
			}
		})
	}
}

func TestRetainedWrapperProvenancePublicationPrecedesUnitChange(t *testing.T) {
	m := wrapperFixture(t, "vector", false, true, true)
	i, err := m.w.capture(context.Background(), m.r, m.name)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := m.w.read(m.r, m.name)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.w.mark(m.r, m.name, "quiesce.json", i, raw, true); err != nil {
		t.Fatal(err)
	}
	if err := m.w.publishAuthority(m.r, i); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(m.unit)
	if !bytes.Equal(unit, i.Unit) || len(m.mutations()) != 0 {
		t.Fatal("publication changed effective unit")
	}
	if _, err := m.w.capture(context.Background(), nextWrapperRequest(m.r), m.name); err == nil {
		t.Fatal("new task ignored interrupted original owner")
	}
	if err := m.w.quiesce(context.Background(), m.r, m.name); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.w.retainedState(context.Background(), m.r.Node, m.name); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedWrapperPublicationFailureCannotChangeServices(t *testing.T) {
	for _, kind := range []string{"file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			m := wrapperFixture(t, "exporter", true, true, true)
			p, _ := m.w.authorityPath(m.name)
			if kind == "file" {
				if err := os.WriteFile(filepath.Dir(p), []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Symlink(m.w.host.configRoot, filepath.Dir(p)); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.w.quiesce(context.Background(), m.r, m.name); err == nil {
				t.Fatal("accepted unsafe provenance directory")
			}
			unit, _ := os.ReadFile(m.unit)
			if !bytes.Equal(unit, m.u.definition()) || !m.running || !m.enabled || len(m.mutations()) != 0 {
				t.Fatal("stopped service without durable provenance")
			}
		})
	}
}

func TestRetainedWrapperGroupNextTaskReusesOriginalProofAndNewData(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			f, r, db := wrapperGroupFixture(t, mode)
			if _, err := f.g.backup.run(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			// A quiescent retained sidecar is proven separately, even when the
			// legacy Compose file never described that wrapper-managed object.
			inventory, err := f.g.host.inventory(context.Background(), r.Node, mode)
			if err != nil || len(inventory.Services) != 1 || len(inventory.Wrappers) != 0 {
				t.Fatal("parked wrapper inventory", err)
			}
			r.Phase = "restore"
			if err := f.g.restoreBeforeActivation(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			if _, err := f.g.host.inventory(context.Background(), r.Node, mode); err == nil {
				t.Fatal("ordinary inventory adopted active wrappers")
			}
			if _, err := db.Exec(`INSERT INTO events VALUES('later-task-event','{}',NULL)`); err != nil {
				t.Fatal(err)
			}
			r = nextWrapperRequest(r)
			next := newLegacyWrapperGroup(f.g.host, r, f.g.backup.data, f.g.backup.logs)
			if _, err := next.backup.run(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			i, err := next.backup.readIntent(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			for _, member := range i.Installed.Wrappers {
				intent, _, err := (legacyWrapperTransition{next.host}).read(r, member.Name)
				if err != nil || intent.RetainedSHA256 == "" {
					t.Fatal("new group lost root proof", err)
				}
			}
			assertBackupRows(t, filepath.Join(next.backup.directory(r), "snapshot", "agent.sqlite3"), 2)
			r.Phase = "restore"
			if err := next.restoreBeforeActivation(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			assertBackupRows(t, filepath.Join(next.backup.data, "agent.sqlite3"), 2)
		})
	}
}

func TestRetainedWrapperInventoryRejectsMissingProofAndActiveServices(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, change := range []string{"unit-missing", "pointer-missing", "unexpected-enable", "unexpected-running", "reverted-unit", "object-changed", "directory-mode"} {
			t.Run(mode+"-"+change, func(t *testing.T) {
				f, r, _ := wrapperGroupFixture(t, mode)
				if _, err := f.g.backup.run(context.Background(), r); err != nil {
					t.Fatal(err)
				}
				w := f.wrappers[1]
				pointer, err := w.w.authorityPath(w.name)
				if err != nil {
					t.Fatal(err)
				}
				switch change {
				case "unit-missing":
					err = os.Remove(w.unit)
				case "pointer-missing":
					err = os.Remove(pointer)
				case "unexpected-enable":
					w.enabled = true
				case "unexpected-running":
					w.running = true
					w.o.Identity.Status = "running"
				case "reverted-unit":
					err = os.WriteFile(w.unit, w.u.definition(), 0644)
				case "object-changed":
					w.o.User = "1000"
				case "directory-mode":
					err = os.Chmod(filepath.Dir(pointer), 0755)
				}
				if err != nil {
					t.Fatal(err)
				}
				before := len(f.mutations())
				if _, err := f.g.host.inventory(context.Background(), r.Node, mode); err == nil {
					t.Fatal("inventory adopted unproven or active retained component")
				}
				if len(f.mutations()) != before {
					t.Fatal("inventory changed services")
				}
			})
		}
	}
}

func TestRetainedWrapperInventoryRechecksAfterAgentInspection(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, change := range []string{"enable", "remove-pointer", "start-object"} {
			t.Run(mode+"-"+change, func(t *testing.T) {
				f, r, _ := wrapperGroupFixture(t, mode)
				if _, err := f.g.backup.run(context.Background(), r); err != nil {
					t.Fatal(err)
				}
				h := f.g.host
				interrupted := false
				h.command = func(ctx context.Context, p string, a ...string) (string, error) {
					raw, err := f.command(ctx, p, a...)
					agent := mode == "native" && p == "systemctl" && len(a) > 1 && a[0] == "show" && a[1] == nativeServiceName || mode == "docker" && p == "docker" && len(a) > 4 && a[2] == "container" && a[4] == strings.Repeat("1", 64)
					if agent && !interrupted {
						interrupted = true
						switch change {
						case "enable":
							f.wrappers[1].enabled = true
						case "remove-pointer":
							pointer, _ := f.wrappers[1].w.authorityPath(f.wrappers[1].name)
							if e := os.Remove(pointer); e != nil {
								t.Fatal(e)
							}
						case "start-object":
							f.wrappers[1].o.Identity.Status = "running"
							f.wrappers[1].running = true
						}
					}
					return raw, err
				}
				before := len(f.mutations())
				if _, err := h.inventory(context.Background(), r.Node, mode); err == nil || !interrupted {
					t.Fatal("inventory published stale parked proof", err)
				}
				if len(f.mutations()) != before {
					t.Fatal("read-only recheck changed services")
				}
			})
		}
	}
}
