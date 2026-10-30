package nodeops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func legacyWrapperFixture(t *testing.T, role string, tls bool) []byte {
	t.Helper()
	transport := "http"
	if tls {
		transport = "https"
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "legacy-"+role+"-"+transport+".service"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLegacyWrapperExactProducerTemplates(t *testing.T) {
	for _, role := range []string{"vector", "exporter"} {
		for _, tls := range []bool{false, true} {
			t.Run(fmt.Sprint(role, tls), func(t *testing.T) {
				raw := legacyWrapperFixture(t, role, tls)
				u, err := parseLegacySidecarUnit("webscan-"+role+"-v1.service", raw)
				if err != nil || u.Role != role || u.TLS != tls {
					t.Fatal("exact preserved producer template not recognized", u, err)
				}
				if role == "exporter" && (u.MetricsPort != 19100 || u.SourceImage != "sha256:"+strings.Repeat("d", 64)) || role == "vector" && (u.MetricsPort != 0 || u.SourceImage != "mirror.example.test/timberio/vector:0.45.0-alpine") {
					t.Fatal("wrong variable evidence", u)
				}
				if !bytes.Equal(raw, u.definition()) {
					t.Fatal("template bytes not preserved")
				}
			})
		}
	}
}

func TestLegacyWrapperRejectsUnknownTemplates(t *testing.T) {
	base := string(legacyWrapperFixture(t, "exporter", true))
	for kind, raw := range map[string]string{
		"hook":                 base + "ExecStartPost=/bin/true\n",
		"duplicate-section":    base + "[Service]\nExecStop=/bin/false\n",
		"duplicate-prestart":   strings.Replace(base, "ExecStart=", "ExecStartPre=/bin/true\nExecStart=", 1),
		"command-reset":        base + "ExecStart=\n",
		"different-name":       strings.ReplaceAll(base, "webscan-exporter-v1", "webscan-foreign-v1"),
		"different-alias":      strings.ReplaceAll(base, "docker.io/prom/node-exporter:v1.9.1", "foreign.example/image:latest"),
		"different-program":    strings.ReplaceAll(base, "/usr/bin/docker", "/usr/local/bin/docker"),
		"extra-mount":          strings.Replace(base, " --user ", " -v /secret:/secret --user ", 1),
		"writable-proc":        strings.Replace(base, "/proc:/host/proc:ro", "/proc:/host/proc:rw", 1),
		"restart-modified":     strings.Replace(base, "Restart=always", "Restart=on-failure", 1),
		"no-docker-partof":     strings.Replace(base, "PartOf=docker.service\n", "", 1),
		"source-environment":   strings.Replace(base, "sha256:"+strings.Repeat("d", 64), "$IMAGE", 1),
		"source-specifier":     strings.Replace(base, "sha256:"+strings.Repeat("d", 64), "%i", 1),
		"source-options":       strings.Replace(base, "sha256:"+strings.Repeat("d", 64), "--help", 1),
		"source-shell":         strings.Replace(base, "sha256:"+strings.Repeat("d", 64), "image;touch /tmp/marker", 1),
		"source-newline":       strings.Replace(base, "sha256:"+strings.Repeat("d", 64), "image\nEnvironment=SECRET=x", 1),
		"zero-port":            strings.Replace(base, ":19100 ", ":0 ", 1),
		"negative-port":        strings.Replace(base, ":19100 ", ":-1 ", 1),
		"overflow-port":        strings.Replace(base, ":19100 ", ":65536 ", 1),
		"noncanonical-port":    strings.Replace(base, ":19100 ", ":019100 ", 1),
		"malformed-port":       strings.Replace(base, ":19100 ", ":19100x ", 1),
		"null":                 base + "\x00",
		"crlf":                 strings.ReplaceAll(base, "\n", "\r\n"),
		"comment":              base + "# local change\n",
		"empty":                "",
		"oversized":            strings.Repeat("x", (64<<10)+1),
		"duplicate-port":       strings.Replace(base, " --web.config.file=", " --web.listen-address=:19100 --web.config.file=", 1),
		"missing-final-line":   strings.TrimSuffix(base, "\n"),
		"systemd-continuation": strings.Replace(base, " --user", " \\\n--user", 1),
	} {
		t.Run(kind, func(t *testing.T) {
			if _, err := parseLegacySidecarUnit("webscan-exporter-v1.service", []byte(raw)); err == nil || err.Error() != "legacy-wrapper-not-owned" {
				t.Fatal("unknown template accepted", err)
			}
		})
	}
	for _, name := range []string{"webscan-agent-v1.service", "foreign.service", "../webscan-exporter-v1.service", "webscan-exporter-v1"} {
		if _, err := parseLegacySidecarUnit(name, []byte(base)); err == nil {
			t.Fatal("name alone accepted", name)
		}
	}
}

func TestLegacyWrapperReaderSeparateFromPrivateMaterial(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0644} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			path := filepath.Join(testRoot(t), "webscan-vector-v1.service")
			raw := legacyWrapperFixture(t, "vector", false)
			if err := os.WriteFile(path, raw, mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			before, _ := os.Stat(path)
			got, err := readLegacyWrapperUnit(path)
			if err != nil || !bytes.Equal(raw, got) {
				t.Fatal("genuine unit rejected", err)
			}
			after, _ := os.Stat(path)
			if before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
				t.Fatal("read changed unit")
			}
			if _, err := readPrivate(path, 64<<10); mode == 0644 && err == nil {
				t.Fatal("private credential reader weakened")
			}
		})
	}
}

func TestLegacyWrapperReaderRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "symlink-parent", "writable-parent", "group-write", "world-write", "executable", "setuid", "directory", "fifo", "empty", "oversized", "unknown-name", "wrong-owner"} {
		t.Run(kind, func(t *testing.T) {
			root := testRoot(t)
			parent := filepath.Join(root, "units")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "webscan-vector-v1.service")
			if err := os.WriteFile(path, legacyWrapperFixture(t, "vector", true), 0644); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Rename(path, path+".original")
				if err == nil {
					err = os.Symlink(path+".original", path)
				}
			case "hardlink":
				err = os.Link(path, path+".link")
			case "symlink-parent":
				err = os.Symlink(parent, filepath.Join(root, "alias"))
				path = filepath.Join(root, "alias", filepath.Base(path))
			case "writable-parent":
				err = os.Chmod(parent, 0777)
			case "group-write":
				err = os.Chmod(path, 0664)
			case "world-write":
				err = os.Chmod(path, 0666)
			case "executable":
				err = os.Chmod(path, 0755)
			case "setuid":
				err = unix.Chmod(path, 04644)
			case "directory", "fifo":
				err = os.Remove(path)
				if err == nil && kind == "directory" {
					err = os.Mkdir(path, 0700)
				} else if err == nil {
					err = unix.Mkfifo(path, 0600)
				}
			case "empty":
				err = os.Truncate(path, 0)
			case "oversized":
				err = os.Truncate(path, (64<<10)+1)
			case "unknown-name":
				other := filepath.Join(parent, "unrelated.service")
				err = os.Rename(path, other)
				path = other
			case "wrong-owner":
				if os.Geteuid() != 0 {
					t.Skip("chown rejection requires isolated root Linux verification")
				}
				err = os.Chown(path, 65534, 65534)
			}
			if err != nil {
				t.Fatal("fixture", err)
			}
			if _, err := readLegacyWrapperUnit(path); err == nil {
				t.Fatal("unsafe file accepted")
			}
		})
	}
}

func TestLegacyWrapperInventoryIsReadOnlyAndKeepsActiveGate(t *testing.T) {
	for _, role := range []string{"vector", "exporter"} {
		for _, state := range []string{"disabled", "active", "enabled", "failed", "reload", "dropin", "foreign-path", "job", "unknown", "unit-changed", "malformed", "agent-wrapper"} {
			t.Run(role+"/"+state, func(t *testing.T) {
				m := installationFixture(t, "native")
				m.addNative(t)
				name := "webscan-" + role + "-v1.service"
				unit := legacyWrapperFixture(t, role, true)
				if state == "malformed" {
					unit = append(unit, []byte("ExecStopPost=/bin/false\n")...)
				}
				if state == "agent-wrapper" {
					name = "webscan-agent-v1.service"
				}
				path := filepath.Join(filepath.Dir(m.host.unitPath), name)
				if err := os.WriteFile(path, unit, 0644); err != nil {
					t.Fatal(err)
				}
				base := m.host.command
				var calls []string
				m.host.command = func(ctx context.Context, p string, a ...string) (string, error) {
					calls = append(calls, p+" "+strings.Join(a, " "))
					if p != "systemctl" || len(a) != 3 || a[0] != "show" || a[1] != name {
						return base(ctx, p, a...)
					}
					status := fmt.Sprintf("LoadState=loaded\nActiveState=inactive\nSubState=dead\nFragmentPath=%s\nDropInPaths=\nNeedDaemonReload=no\nUnitFileState=disabled\nJob=0\nMainPID=0\n", path)
					switch state {
					case "active":
						status = strings.ReplaceAll(status, "inactive", "active")
						status = strings.ReplaceAll(status, "SubState=dead", "SubState=running")
						status = strings.ReplaceAll(status, "MainPID=0", "MainPID=1234")
					case "enabled":
						status = strings.ReplaceAll(status, "UnitFileState=disabled", "UnitFileState=enabled")
					case "failed":
						status = strings.ReplaceAll(status, "inactive", "failed")
					case "reload":
						status = strings.ReplaceAll(status, "NeedDaemonReload=no", "NeedDaemonReload=yes")
					case "dropin":
						status = strings.ReplaceAll(status, "DropInPaths=", "DropInPaths=/etc/override.conf")
					case "foreign-path":
						status = strings.ReplaceAll(status, path, path+".foreign")
					case "job":
						status = strings.ReplaceAll(status, "Job=0", "Job=7")
					case "unknown":
						return "", errors.New("private upstream failure")
					case "unit-changed":
						if err := os.WriteFile(path, append(unit, '#'), 0644); err != nil {
							t.Fatal(err)
						}
					}
					return status, nil
				}
				_, err := m.host.inventory(context.Background(), "node-one", "native")
				if (state == "disabled" || state == "failed") != (err == nil) {
					t.Fatal("wrong eligibility", err)
				}
				for _, call := range calls {
					if !strings.HasPrefix(call, "systemctl show ") {
						t.Fatal("read-only native inventory changed services or used Docker", call)
					}
				}
				if !m.nativeRunning || !m.nativeEnabled {
					t.Fatal("original Agent changed")
				}
				if state != "unit-changed" {
					got, e := os.ReadFile(path)
					if e != nil || !bytes.Equal(got, unit) {
						t.Fatal("unit modified", e)
					}
				}
			})
		}
	}
}

func FuzzLegacyWrapperTemplate(f *testing.F) {
	for _, role := range []string{"vector", "exporter"} {
		for _, tls := range []bool{false, true} {
			port := 0
			if role == "exporter" {
				port = 19100
			}
			u := legacySidecarUnit{role, "sha256:" + strings.Repeat("a", 64), tls, port}
			f.Add("webscan-"+role+"-v1.service", u.definition())
		}
	}
	f.Fuzz(func(t *testing.T, name string, raw []byte) {
		u, err := parseLegacySidecarUnit(name, raw)
		if err != nil {
			return
		}
		if !u.valid() || !bytes.Equal(raw, u.definition()) || name != "webscan-"+u.Role+"-v1.service" {
			t.Fatal("noncanonical unit accepted")
		}
		v, err := parseLegacySidecarUnit(name, u.definition())
		if err != nil || !reflect.DeepEqual(u, v) {
			t.Fatal("unstable parsing", err)
		}
	})
}
