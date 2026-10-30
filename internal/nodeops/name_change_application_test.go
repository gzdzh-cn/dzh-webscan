package nodeops

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

// Real private artifacts, SQLite state and production phase handlers; only the
// service managers, processes and cgroup evidence are fixtures. Keep this
// distinct from the opted-in actual Linux kernel lifecycle acceptance.
func TestNameChangeConfigurationLifecycleRetainsIdentityAndNewEventsOnRollback(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			var w *LocalRuntime
			var r Request
			var handler Handler
			var db *sql.DB
			var data string
			var updateTarget func(Request)
			var checkOriginal func(Request) error
			var starts func() int
			if mode == "native" {
				n, a, _, _ := nativeJournalFixture(t, false)
				w, r, handler, data = n.runtime, a.request, n, n.activation.backup.data
				db = restorationData(t, a)
				base := a.activation.host.command
				a.activation.host.command = func(ctx context.Context, program string, args ...string) (string, error) {
					out, err := base(ctx, program, args...)
					if err == nil && program == "systemctl" && len(args) > 0 && args[0] == "start" {
						var active ActiveInstallation
						if _, err := decodePrivateJSON(filepath.Join(w.root, "active.json"), &active, MaxRequestBytes); err == nil {
							a.program = filepath.Join(w.releaseDir(active.Spec), "webscan")
							a.configuration = filepath.Join(w.configurationDir(active.Spec), "runtime.json")
						}
					}
					return out, err
				}
				a.activation.backup.host = a.activation.host
				updateTarget = func(next Request) { a.request = next }
				starts = func() int { return a.starts }
			} else {
				d, a, _, _ := dockerJournalFixture(t, false)
				w, r, handler, data = d.runtime, a.request, d, d.activation.backup.data
				db = dockerRestorationData(t, a)
				// Observe the running object, rather than the not-yet-created
				// target. They have different configurations during an upgrade.
				d.activation.host.processExecutable = func(int) (string, error) {
					for _, c := range a.machine.containers {
						if c.Status == "running" && len(c.Entrypoint) > 0 {
							return c.Entrypoint[0], nil
						}
					}
					return "", os.ErrNotExist
				}
				d.activation.host.processArguments = func(int) ([]string, error) {
					for _, c := range a.machine.containers {
						if c.Status == "running" && len(c.Entrypoint) > 0 {
							return append(append([]string{}, c.Entrypoint...), c.Command...), nil
						}
					}
					return nil, os.ErrNotExist
				}
				d.activation.backup.host = d.activation.host
				checkOriginal = func(next Request) error {
					if _, err := d.activation.host.inventory(ctx, next.Node, next.Spec.Mode); err != nil {
						t.Log("direct original inventory", err)
					}
					return d.originalDocker(ctx, next)
				}
				updateTarget = func(next Request) {
					previous := a.request
					// Model exactly the generated command, mounts and project of
					// the new immutable configuration, without mutating old objects.
					raw, _ := json.Marshal(a.target)
					raw = bytes.ReplaceAll(raw, []byte(previous.Spec.RuntimeSHA256), []byte(next.Spec.RuntimeSHA256))
					var target containerIdentity
					if err := json.Unmarshal(raw, &target); err != nil {
						t.Fatal(err)
					}
					a.target = target
					if previous.Job != next.Job {
						a.target.ID = strings.Repeat("7", 64)
					}
					a.target.Project = dockerProject(ActiveInstallation{Node: next.Node, Job: next.Job, PlanDigest: next.PlanDigest})
					a.runtime.ID, a.request = a.target.ID, next
				}
				starts = func() int { return a.starts }
			}
			now := time.Now().UTC().Truncate(time.Second)
			ca, err := nodepki.NewAuthority(now, 365*24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			live, err := ca.Issue(nodepki.Node, r.Node, []string{"node.test"}, now, 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(live.Key)
			crl, err := ca.Revoke(nil, nil, now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			attachConfiguration(t, w, &r, func(m *nodeconfig.Material) {
				m.Format, m.CA, m.CRL, m.Certificate, m.Key = 2, live.CA, crl, live.Certificate, live.Key
			})
			r, identity := managedLifecycleRequest(t, w, r, data)
			updateTarget(r)
			j := openTestJournal(t, filepath.Join(w.root, "node"), handler)
			finishThrough(t, j, r, "finalize")
			previousPointer, err := os.ReadFile(filepath.Join(w.root, "active.json"))
			if err != nil {
				t.Fatal(err)
			}
			intent, err := nodepki.NewNodeNameChangeIntent(r.Node, sha(recoveryTestCertificate(t, live.CA).Raw), sha(recoveryTestCertificate(t, live.Certificate).Raw), "next-node.test", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			in := NameChangeInput{Format: 1, Operation: "prepare", Intent: intent, CRL: crl}
			prepared, err := w.nameChange(ctx, in)
			if err != nil {
				t.Fatal("name preparation from finalized installation", err)
			}
			certificate := signHelperNameChange(t, helperNameChangeFixture{w: w, r: r, ca: ca, live: live, in: in}, prepared.Request)
			in.Operation, in.Request, in.Certificate = "activate", prepared.Request, certificate
			beforeStarts := starts()
			if _, err := w.nameChange(ctx, in); err != nil {
				t.Fatal(err)
			}
			identityBefore, err := os.ReadFile(identity)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(identityBefore)
			if starts() != beforeStarts {
				t.Fatal("certificate activation restarted the service")
			}
			if err := w.verifyConfiguration(ctx, r); err != nil {
				t.Fatal("overlap invalidated old configuration", err)
			}
			oldSpec := r.Spec
			raw, err := os.ReadFile(filepath.Join(w.root, "configs", r.Spec.RuntimeSHA256, "node.json"))
			if err != nil {
				t.Fatal(err)
			}
			m, err := nodeconfig.Decode(raw, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			m.Version++
			m.ServerName = intent.ServerName
			m.SourceSHA256 = strings.Repeat("e", 64)
			raw, err = json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			r.Job, r.PlanDigest, r.Epoch = "job-name-target", strings.Repeat("d", 64), 1
			r.Spec.RuntimeSHA256, r.Spec.RuntimeBytes = sha(raw), uint64(len(raw))
			r.Spec.ServerName, r.Spec.ConfigVersion, r.Spec.ConfigSourceSHA256 = m.ServerName, m.Version, m.SourceSHA256
			if err := os.Mkdir(filepath.Join(w.root, "configs", r.Spec.RuntimeSHA256), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(w.root, "configs", r.Spec.RuntimeSHA256, "node.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			// The isolated Docker stage checks prepared files and image proof;
			// exercise the real configuration preparation explicitly here.
			if err := w.prepareConfiguration(ctx, r); err != nil {
				t.Fatal(err)
			}
			updateTarget(r)
			if checkOriginal != nil {
				preflight := r
				preflight.Phase = "preflight"
				if err := checkOriginal(preflight); err != nil {
					t.Fatal("saved original before target application", err)
				}
			}
			finishThrough(t, j, r, "activate")
			var target ActiveInstallation
			if _, err := decodePrivateJSON(filepath.Join(w.root, "active.json"), &target, MaxRequestBytes); err != nil || target.Spec.ServerName != intent.ServerName || target.Spec.RuntimeSHA256 == oldSpec.RuntimeSHA256 {
				t.Fatal("new name runtime not activated", err)
			}
			// A genuine write after the new backup and target activation must
			// survive restoration of the old configuration and retain its ID.
			if _, err := db.Exec(`INSERT INTO events VALUES('after-name-activation','{"event_id":"after-name-activation","node_id":"node-one"}',2,NULL,NULL)`); err != nil {
				t.Fatal(err)
			}
			r.Phase, r.Epoch = "restore", 2
			requireResult(t, j.Handle(r), "complete", "ok")
			r.Phase = "verify-rollback"
			requireResult(t, j.Handle(r), "complete", "ok")
			afterStarts := starts()
			requireResult(t, j.Handle(r), "complete", "ok")
			if starts() != afterStarts {
				t.Fatal("rollback receipt replay restarted a writer")
			}
			pointer, err := os.ReadFile(filepath.Join(w.root, "active.json"))
			if err != nil || !bytes.Equal(pointer, previousPointer) {
				t.Fatal("rollback lost exact original installation", err)
			}
			identityAfter, err := os.ReadFile(identity)
			defer clear(identityAfter)
			if err != nil || !bytes.Equal(identityAfter, identityBefore) {
				t.Fatal("rollback replaced node-local name identity", err)
			}
			old := r
			old.Spec = oldSpec
			if err := w.verifyConfiguration(ctx, old); err != nil {
				t.Fatal("restored old name cannot use retained successor", err)
			}
			var pending int
			if err := db.QueryRow(`SELECT count(*) FROM events WHERE id='after-name-activation' AND accepted IS NULL AND exported IS NOT NULL`).Scan(&pending); err != nil || pending != 1 {
				t.Fatal("new event lost or not reexported for rollback", err)
			}
			assertBackupRows(t, filepath.Join(data, "agent.sqlite3"), 3)
			r.Phase = "activate"
			requireResult(t, j.Handle(r), "unknown", "phase-order")
		})
	}
}
