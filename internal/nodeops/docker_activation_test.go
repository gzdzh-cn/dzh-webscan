package nodeops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/nodeconfig"
)

type dockerActivationMachine struct {
	machine               *installationMachine
	activation            *dockerActivation
	request               Request
	material              nodeconfig.Material
	target                containerIdentity
	runtime               dockerRuntimeState
	creates, starts       int
	failAfter, failBefore string
}

func dockerActivationFixture(t *testing.T, fresh bool, beforeBackup ...func(*transitionBackup)) *dockerActivationMachine {
	t.Helper()
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	r.Spec.Mode = "docker"
	r.Spec.AgentImage, _ = imageFixture()
	// The container's /tmp is intentionally reserved. Use a separate disposable
	// monitor tree, never the deployment/configuration tree or a business path.
	monitor, err := os.MkdirTemp("/var/tmp", "webscan-v3-monitor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(monitor) })
	monitor, err = filepath.EvalSymlinks(monitor)
	if err != nil {
		t.Fatal(err)
	}
	r.Spec.MonitorDirectories = []string{monitor}
	m := attachConfiguration(t, w, &r, nil)
	ctx := context.Background()
	if err := w.prepare(ctx, r.Spec); err != nil {
		t.Fatal(err)
	}
	if err := w.prepareConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	machine := installationFixture(t, "docker")
	machine.host.root = w.root
	if fresh {
		if err := os.Remove(filepath.Join(machine.host.configRoot, "runtime.json")); err != nil {
			t.Fatal(err)
		}
	} else {
		machine.addDocker(t)
	}
	a := &dockerActivationMachine{machine: machine, request: r, material: m}
	a.target = containerIdentity{ID: strings.Repeat("9", 64), Name: "/" + agentContainerName, Image: r.Spec.AgentImage, ImageID: "sha256:" + strings.Repeat("8", 64), Project: dockerProject(ActiveInstallation{Node: r.Node, Job: r.Job, PlanDigest: r.PlanDigest}), Service: "agent", Managed: "v3", Node: r.Node, Configuration: r.Spec.RuntimeSHA256, Entrypoint: []string{filepath.Join(w.releaseDir(r.Spec), "webscan")}, Command: []string{"agent", "--config", filepath.Join(w.configurationDir(r.Spec), "runtime.json")}, Status: "created", Restart: "unless-stopped"}
	raw, err := readPrivate(filepath.Join(w.configurationDir(r.Spec), "compose.json"), 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	var definition struct {
		Services map[string]struct {
			Volumes []serviceMount `json:"volumes"`
		} `json:"services"`
	}
	if json.Unmarshal(raw, &definition) != nil {
		t.Fatal("invalid definition")
	}
	for _, v := range definition.Services["agent"].Volumes {
		a.target.Mounts = append(a.target.Mounts, struct {
			Type                string
			Source, Destination string
			RW                  bool
		}{"bind", strings.ReplaceAll(v.Source, "$$", "$"), strings.ReplaceAll(v.Target, "$$", "$"), !v.ReadOnly})
	}
	a.runtime = dockerStateFixture(t, m.Settings.Resources)
	a.runtime.ID = a.target.ID
	machine.host.command = a.command
	b := &transitionBackup{root: w.root, data: filepath.Join(w.root, "data"), logs: filepath.Join(w.root, "logs"), unit: machine.host.unitPath, host: machine.host}
	for _, setup := range beforeBackup {
		setup(b)
	}
	r.Phase = "backup"
	if _, err := b.run(ctx, r); err != nil {
		t.Fatal(err)
	}
	a.activation = &dockerActivation{runtime: w, backup: b, host: machine.host}
	r.Phase = "activate"
	a.request = r
	return a
}

func (m *dockerActivationMachine) command(ctx context.Context, p string, args ...string) (string, error) {
	if p != "docker" || len(args) < 3 {
		return m.machine.command(ctx, p, args...)
	}
	verb := args[2]
	if verb == m.failBefore {
		return "", errors.New("injected-before-operation")
	}
	var out string
	var err error
	switch verb {
	case "ps":
		if len(args) > 6 && strings.HasPrefix(args[6], "label=com.docker.compose.project=") {
			project := strings.TrimPrefix(args[6], "label=com.docker.compose.project=")
			for _, c := range m.machine.containers {
				if c.Project == project {
					out += c.ID + "\n"
				}
			}
		} else {
			out, err = m.machine.command(ctx, p, args...)
		}
	case "image":
		raw, _ := json.Marshal(map[string]any{"id": m.target.ImageID, "os": "linux", "arch": "amd64", "repo_digests": []string{m.request.Spec.AgentImage}})
		out = string(raw)
	case "compose":
		m.creates++
		if len(args) < 11 || args[5] != "-p" || args[6] != m.target.Project || args[7] != "-f" || args[9] != "create" {
			return "", errors.New("unexpected compose arguments")
		}
		for _, c := range m.machine.containers {
			if c.Name == m.target.Name {
				return "", errors.New("name in use")
			}
		}
		m.machine.containers[m.target.ID] = m.target
		out = m.target.ID
	case "rename":
		id, name := args[3], args[4]
		c, ok := m.machine.containers[id]
		if !ok {
			return "", errors.New("no such id")
		}
		for _, existing := range m.machine.containers {
			if existing.Name == "/"+name {
				return "", errors.New("name in use")
			}
		}
		c.Name = "/" + name
		m.machine.containers[id] = c
	case "container":
		if len(args) == 7 && args[6] == dockerRuntimeFormat {
			c, ok := m.machine.containers[args[4]]
			if !ok {
				return "", errors.New("no such id")
			}
			s := m.runtime
			s.State.Status = c.Status
			s.State.Running = c.Status == "running"
			if !s.State.Running {
				s.State.Pid = 0
			}
			s.Host.RestartPolicy.Name = c.Restart
			raw, _ := json.Marshal(s)
			out = string(raw)
		} else {
			out, err = m.machine.command(ctx, p, args...)
		}
	case "start":
		if c := m.machine.containers[args[len(args)-1]]; c.Status != "running" {
			m.starts++
		}
		out, err = m.machine.command(ctx, p, args...)
	default:
		out, err = m.machine.command(ctx, p, args...)
	}
	if err == nil && verb == m.failAfter {
		return out, errors.New("injected-response-loss")
	}
	return out, err
}

func TestDockerActivationRetainsOriginalAndUsesOneTarget(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing", true: "fresh"}[fresh], func(t *testing.T) {
			a := dockerActivationFixture(t, fresh)
			if err := a.activation.run(context.Background(), a.request); err != nil {
				t.Fatal(err)
			}
			if a.creates != 1 || a.starts != 1 || a.machine.containers[a.target.ID].Status != "running" {
				t.Fatal("target not activated", a.creates, a.starts)
			}
			if !fresh {
				old := a.machine.containers[strings.Repeat("1", 64)]
				if old.Status == "running" || old.Restart != "no" || !strings.HasPrefix(old.Name, "/webscan-retired-") {
					t.Fatal("original lost or still enabled")
				}
			}
			if err := a.activation.run(context.Background(), a.request); err != nil || a.creates != 1 || a.starts != 1 {
				t.Fatal("replay created or started another writer", err, a.creates, a.starts)
			}
			current, err := a.activation.host.inventory(context.Background(), a.request.Node, "docker")
			if err != nil || current.Generation != "v3" || len(current.Services) != 1 || current.Services[0].ID != a.target.ID {
				t.Fatal(current, err)
			}
		})
	}
}

func TestDockerActivationReconcilesLostCreateRenameAndStartResponses(t *testing.T) {
	for _, operation := range []string{"rename", "compose", "update", "start"} {
		t.Run(operation, func(t *testing.T) {
			a := dockerActivationFixture(t, false)
			a.failAfter = operation
			if err := a.activation.run(context.Background(), a.request); err == nil {
				t.Fatal("response loss reported success")
			}
			a.failAfter = ""
			a.request.Epoch++
			if err := a.activation.run(context.Background(), a.request); err != nil {
				t.Fatal("cannot continue", err)
			}
			if a.creates != 1 || a.starts != 1 {
				t.Fatal("repeated create/start", a.creates, a.starts)
			}
		})
	}
}

func TestDockerActivationRefusesForeignState(t *testing.T) {
	for _, kind := range []string{"old-running", "old-enabled", "foreign-name", "foreign-pointer", "missing-recorded-target", "changed-recorded-target", "wrong-policy", "unrecorded-running"} {
		t.Run(kind, func(t *testing.T) {
			a := dockerActivationFixture(t, false)
			switch kind {
			case "old-running", "old-enabled":
				c := a.machine.containers[strings.Repeat("1", 64)]
				if kind == "old-running" {
					c.Status = "running"
				} else {
					c.Restart = "always"
				}
				a.machine.containers[c.ID] = c
			case "foreign-name":
				c := a.target
				c.Project = "foreign"
				a.machine.containers[c.ID] = c
				old := a.machine.containers[strings.Repeat("1", 64)]
				old.Name = "/retained-elsewhere"
				a.machine.containers[old.ID] = old
			case "foreign-pointer":
				os.WriteFile(filepath.Join(a.activation.runtime.root, "active.json"), []byte("foreign"), 0600)
			case "missing-recorded-target", "changed-recorded-target":
				if err := a.activation.run(context.Background(), a.request); err != nil {
					t.Fatal(err)
				}
				if kind == "missing-recorded-target" {
					delete(a.machine.containers, a.target.ID)
				} else {
					c := a.machine.containers[a.target.ID]
					c.Command = []string{"other"}
					a.machine.containers[c.ID] = c
				}
			case "wrong-policy":
				a.runtime.Host.Memory = 0
			case "unrecorded-running":
				a.failAfter = "compose"
				if err := a.activation.run(context.Background(), a.request); err == nil {
					t.Fatal("injection failed")
				}
				a.failAfter = ""
				c := a.machine.containers[a.target.ID]
				c.Status = "running"
				a.machine.containers[c.ID] = c
			}
			before := a.starts
			if err := a.activation.run(context.Background(), a.request); err == nil {
				t.Fatal("foreign or missing evidence accepted")
			}
			if a.starts != before {
				t.Fatal("started before proving state")
			}
		})
	}
}

func TestDockerLostCreateCannotIgnoreRenamedOrDuplicateTaskObject(t *testing.T) {
	for _, kind := range []string{"renamed", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			a := dockerActivationFixture(t, false)
			a.failAfter = "compose"
			if err := a.activation.run(context.Background(), a.request); err == nil {
				t.Fatal("create response loss injection failed")
			}
			a.failAfter = ""
			c := a.machine.containers[a.target.ID]
			if kind == "renamed" {
				c.Name = "/unrecorded-rename"
				a.machine.containers[c.ID] = c
			} else {
				c.ID = strings.Repeat("7", 64)
				c.Name = "/duplicate-project"
				a.machine.containers[c.ID] = c
			}
			if err := a.activation.run(context.Background(), a.request); err == nil {
				t.Fatal("orphan task object ignored during activation")
			}
			r := a.request
			r.Phase = "restore"
			if err := a.activation.restore(context.Background(), r); err == nil {
				t.Fatal("orphan task object ignored during restoration")
			}
			if a.starts != 0 || a.creates != 1 {
				t.Fatal("another writer created or started", a.starts, a.creates)
			}
		})
	}
}
