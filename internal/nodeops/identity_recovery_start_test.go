package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

// These tests use real private configuration, keys and Journal; the service
// manager is an explicit fixture. Kernel acceptance is separate.
func signedHelperRecovery(t *testing.T, mode string, activate bool) helperRecoveryFixture {
	t.Helper()
	f := newHelperRecoveryFixture(t, mode)
	prepared, err := f.w.identityRecovery(context.Background(), f.in)
	if err != nil {
		t.Fatal(err)
	}
	r, err := nodepki.ParseNodeRecoveryRequest(prepared.Request)
	if err != nil {
		t.Fatal(err)
	}
	dir := testRoot(t)
	b, err := f.ca.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	if err := os.Mkdir(filepath.Join(dir, "crls"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"ca.crt": b.CA, "ca.key": b.Key, "ca.crl": f.in.CRL, "crls/1.pem": f.in.CRL} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	err = nodepki.SignNodeRecoveryRegistered(context.Background(), dir, r, f.in.Intent, time.Now(), 72*time.Hour, func(b nodepki.Bundle, crl []byte) error {
		f.in.Certificate, f.in.CRL = b.Certificate, crl
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f.in.Operation, f.in.Request = "activate", prepared.Request
	if activate {
		if _, err := f.w.identityRecovery(context.Background(), f.in); err != nil {
			t.Fatal(err)
		}
	}
	f.in.Operation = "start"
	return f
}

func recoveryServiceMachine(t *testing.T, f helperRecoveryFixture) *installationMachine {
	t.Helper()
	w, r := f.w, f.r
	m := &installationMachine{containers: map[string]containerIdentity{}, nativeEnabled: true}
	m.host = newInstallationHost(w.root)
	m.host.configRoot, m.host.unitPath = filepath.Join(w.root, "legacy"), filepath.Join(w.root, nativeServiceName)
	m.host.command = m.command
	m.host.processExecutable = func(int) (string, error) { return filepath.Join(w.releaseDir(r.Spec), "webscan"), nil }
	m.host.processArguments = func(int) ([]string, error) {
		return []string{filepath.Join(w.releaseDir(r.Spec), "webscan"), "agent", "--config", filepath.Join(w.configurationDir(r.Spec), "runtime.json")}, nil
	}
	if r.Spec.Mode == "native" {
		raw, err := os.ReadFile(filepath.Join(w.configurationDir(r.Spec), nativeServiceName))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(m.host.unitPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		var a ActiveInstallation
		if _, err := decodePrivateJSON(filepath.Join(w.root, "active.json"), &a, MaxRequestBytes); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(w.configurationDir(r.Spec), "compose.json"))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Services map[string]struct {
				Volumes []serviceMount `json:"volumes"`
			} `json:"services"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		c := containerIdentity{ID: strings.Repeat("1", 64), Name: "/" + agentContainerName, Managed: "v3", Node: r.Node, Configuration: r.Spec.RuntimeSHA256, Project: dockerProject(a), Service: "agent", Image: r.Spec.AgentImage, ImageID: "sha256:" + strings.Repeat("2", 64), Entrypoint: []string{filepath.Join(w.releaseDir(r.Spec), "webscan")}, Command: []string{"agent", "--config", filepath.Join(w.configurationDir(r.Spec), "runtime.json")}, Status: "exited", Restart: "unless-stopped"}
		for _, v := range doc.Services["agent"].Volumes {
			c.Mounts = append(c.Mounts, struct {
				Type                string
				Source, Destination string
				RW                  bool
			}{"bind", strings.ReplaceAll(v.Source, "$$", "$"), strings.ReplaceAll(v.Target, "$$", "$"), !v.ReadOnly})
		}
		m.containers[c.ID] = c
	}
	return m
}

func TestIdentityRecoveryStartOwnedServiceAndLostResponse(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			f := signedHelperRecovery(t, mode, true)
			m := recoveryServiceMachine(t, f)
			starts := 0
			base := m.host.command
			m.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
				if serviceMutation(p, args) {
					starts++
					if _, ok := ctx.Value(serviceOperationKey{}).(serviceOperation); !ok {
						t.Fatal("start without service lock")
					}
					want := "systemctl start " + nativeServiceName
					if mode == "docker" {
						want = "docker --host unix:///var/run/docker.sock start " + strings.Repeat("1", 64)
					}
					if p+" "+strings.Join(args, " ") != want {
						t.Fatal("unexpected mutation", p, args)
					}
				}
				return base(ctx, p, args...)
			}
			for attempt := 0; attempt < 2; attempt++ {
				out, err := f.w.identityRecoveryWithHost(context.Background(), f.in, m.host)
				if err != nil || out.Operation != "start" || out.CertificateSHA256 != sha(recoveryTestCertificate(t, f.in.Certificate).Raw) || len(out.Request) != 0 {
					t.Fatal("owned-service start/reconciliation", err)
				}
			}
			if starts != 1 {
				t.Fatal("lost response restarted service", starts)
			}
			if mode == "native" {
				for _, call := range m.calls {
					if strings.HasPrefix(call, "docker ") {
						t.Fatal("native start called Docker")
					}
				}
			}
		})
	}
}

func TestIdentityRecoveryStartRefusesUnsafeState(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, scenario := range []string{"not-activated", "disabled", "missing-service", "foreign-service", "binary-tamper", "post-start-drift", "start-failed", "not-running", "revoked-parent", "revoked-leaf", "changed-challenge", "operation-lock", "deleted-process"} {
			if mode == "docker" && scenario == "deleted-process" {
				continue
			}
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := signedHelperRecovery(t, mode, scenario != "not-activated")
				m := recoveryServiceMachine(t, f)
				starts := 0
				base := m.host.command
				m.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
					if serviceMutation(p, args) {
						starts++
						if scenario == "start-failed" {
							return "", errors.New("fixture failure")
						}
						if scenario == "not-running" {
							return "", nil
						}
						if scenario == "post-start-drift" {
							if mode == "native" {
								m.nativeEnabled = false
							} else {
								for id, c := range m.containers {
									c.Restart = "no"
									m.containers[id] = c
								}
							}
						}
					}
					return base(ctx, p, args...)
				}
				switch scenario {
				case "disabled":
					m.nativeEnabled = false
					for id, c := range m.containers {
						c.Restart = "no"
						m.containers[id] = c
					}
				case "missing-service":
					if mode == "native" {
						os.Remove(m.host.unitPath)
					} else {
						clear(m.containers)
					}
				case "foreign-service":
					if mode == "native" {
						os.WriteFile(m.host.unitPath, []byte("foreign service"), 0600)
					} else {
						for id, c := range m.containers {
							c.Node = "other-node"
							m.containers[id] = c
						}
					}
				case "binary-tamper":
					os.WriteFile(filepath.Join(f.w.releaseDir(f.r.Spec), "webscan"), []byte("not the installed executable"), 0700)
				case "deleted-process":
					m.host.processExecutable = func(int) (string, error) {
						return filepath.Join(f.w.releaseDir(f.r.Spec), "webscan") + " (deleted)", nil
					}
				case "changed-challenge":
					f.in.Intent.Challenge = strings.Repeat("a", 64)
				case "operation-lock":
					_, release, err := acquireServiceOperation(context.Background(), f.w.root)
					if err != nil {
						t.Fatal(err)
					}
					defer release()
				case "revoked-parent", "revoked-leaf":
					cert := f.expired.Certificate
					if scenario == "revoked-leaf" {
						cert = f.in.Certificate
					}
					var err error
					f.in.CRL, err = f.ca.Revoke(f.in.CRL, [][]byte{cert}, time.Now(), time.Hour)
					if err != nil {
						t.Fatal(err)
					}
				}
				if _, err := f.w.identityRecoveryWithHost(context.Background(), f.in, m.host); err == nil {
					t.Fatal("unsafe state returned start success")
				}
				mayStart := scenario == "post-start-drift" || scenario == "start-failed" || scenario == "not-running" || scenario == "deleted-process"
				if !mayStart && starts != 0 {
					t.Fatal("unsafe state reached mutation", starts)
				}
			})
		}
	}
}
