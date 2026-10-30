package nodeops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionedImageReferencesKeepDigestAndBindRelease(t *testing.T) {
	for _, repository := range []string{"docker.io/gzdzh/webscan-agent", "registry.example.test:5000/team/agent", "webscan-agent"} {
		ref := repository + ":v3.0.0@sha256:" + strings.Repeat("a", 64)
		if !AgentImageMatchesRelease(ref, "v3.0.0") || AgentImageMatchesRelease(ref, "v3.0.1") || AgentImageMatchesRelease(ref, "") {
			t.Fatal("version is not bound to release", ref)
		}
		if got, version := agentImageName(ref); got != repository || version != "v3.0.0" {
			t.Fatal(got, version)
		}
		if ValidAgentImage(repository+":v3.0.0") || ValidAgentImage(repository+":latest@sha256:"+strings.Repeat("a", 64)) {
			t.Fatal("mutable or misleading version accepted")
		}
	}
	if !AgentImageMatchesRelease("gzdzh/webscan-agent@sha256:"+strings.Repeat("b", 64), "v3.0.0") {
		t.Fatal("existing signed releases must remain readable")
	}
}

func TestVersionedOfflineImageAliasesAreProvedAndNeverRebound(t *testing.T) {
	for _, containerd := range []bool{false, true} {
		t.Run(map[bool]string{false: "classic", true: "containerd"}[containerd], func(t *testing.T) {
			root, s, _ := imageArchiveFixture(t, true, nil)
			s.Release = "v3.0.0"
			s.AgentImage = strings.Replace(s.AgentImage, "@", ":"+s.Release+"@", 1)
			id := "sha256:" + s.ImageConfigSHA256
			if containerd {
				f, manifest, err := verifiedImageArchiveManifest(context.Background(), root, s)
				if err != nil {
					t.Fatal(err)
				}
				f.Close()
				id = manifest
			}
			state, bin := testRoot(t), testRoot(t)
			raw, _ := json.Marshal(map[string]any{"id": id, "repo_digests": []string{s.AgentImage}, "os": "linux", "arch": "amd64"})
			if err := os.WriteFile(filepath.Join(state, "source"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			alias := strings.SplitN(s.AgentImage, "@", 2)[0]
			script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$WEBSCAN_VERSION_TEST_STATE/commands"
case " $* " in
  *" image inspect $WEBSCAN_VERSION_TEST_ALIAS "*) cat "$WEBSCAN_VERSION_TEST_STATE/alias" ;;
  *' image inspect '*) cat "$WEBSCAN_VERSION_TEST_STATE/source" ;;
  *' tag '*) cp "$WEBSCAN_VERSION_TEST_STATE/source" "$WEBSCAN_VERSION_TEST_STATE/alias" ;;
  *) exit 99 ;;
esac
`
			if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("WEBSCAN_VERSION_TEST_STATE", state)
			t.Setenv("WEBSCAN_VERSION_TEST_ALIAS", alias)
			ctx := context.Background()
			if err := prepareDockerImage(ctx, root, s); err != nil {
				t.Fatal(err)
			}
			if got, err := dockerLaunchReference(root, s); err != nil || got != alias {
				t.Fatal("unreadable launch name", got, err)
			}
			if got, err := dockerLaunchIdentity(root, s); err != nil || got != id {
				t.Fatal("underlying identity changed", got, err)
			}
			if err := inspectDockerImage(ctx, root, s); err != nil {
				t.Fatal("valid alias failed replay", err)
			}
			commands, _ := os.ReadFile(filepath.Join(state, "commands"))
			if strings.Count(string(commands), " tag ") != 1 || strings.Contains(string(commands), " pull ") {
				t.Fatal("expected one local alias, without downloading", string(commands))
			}
			// Changing the name must not authorize different bytes, even on replay.
			bad := `{"id":"sha256:` + strings.Repeat("f", 64) + `","os":"linux","arch":"amd64"}`
			if err := os.WriteFile(filepath.Join(state, "alias"), []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
			if inspectDockerImage(ctx, root, s) == nil || prepareDockerImage(ctx, root, s) == nil {
				t.Fatal("rebound version alias accepted")
			}
			after, _ := os.ReadFile(filepath.Join(state, "commands"))
			if strings.Count(string(after), " tag ") != 1 {
				t.Fatal("conflicting version alias overwritten")
			}
		})
	}
}

func TestVersionedArchiveRejectsOtherReleaseTag(t *testing.T) {
	root, s, _ := imageArchiveFixture(t, true, nil)
	s.AgentImage = strings.Replace(s.AgentImage, "@", ":v3.0.1@", 1)
	if _, err := verifiedImageArchive(context.Background(), root, s); err == nil {
		t.Fatal("archive named v3.0.0 accepted as v3.0.1")
	}
}

func TestVersionedContainerOwnershipStillBindsActualImageID(t *testing.T) {
	w, r, m := serviceFixture(t, "docker")
	r.Spec.AgentImage = strings.Replace(r.Spec.AgentImage, "@", ":"+r.Spec.Release+"@", 1)
	r.Spec.ImageArchiveSHA256, r.Spec.ImageArchiveBytes, r.Spec.ImageConfigSHA256 = strings.Repeat("d", 64), 1024, strings.Repeat("e", 64)
	_, raw, err := w.serviceDefinition(m, r.Spec)
	if err != nil {
		t.Fatal(err)
	}
	dir := w.configurationDir(r.Spec)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Image   string
			Volumes []serviceMount
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	service := doc.Services["agent"]
	if service.Image != strings.SplitN(r.Spec.AgentImage, "@", 2)[0] {
		t.Fatal("container image name has no version", service.Image)
	}
	a := ActiveInstallation{Node: r.Node, Spec: r.Spec, DefinitionSHA256: sha(raw)}
	c := containerIdentity{ID: strings.Repeat("1", 64), Managed: "v3", Node: r.Node, Configuration: r.Spec.RuntimeSHA256, Project: dockerProject(a), Service: "agent", Status: "created", Restart: "no", Image: service.Image, ImageID: "sha256:" + r.Spec.ImageConfigSHA256, Entrypoint: []string{filepath.Join(w.releaseDir(r.Spec), "webscan")}, Command: []string{"agent", "--config", filepath.Join(dir, "runtime.json")}}
	for _, mount := range service.Volumes {
		c.Mounts = append(c.Mounts, struct {
			Type                string
			Source, Destination string
			RW                  bool
		}{mount.Type, strings.ReplaceAll(mount.Source, "$$", "$"), strings.ReplaceAll(mount.Target, "$$", "$"), !mount.ReadOnly})
	}
	h := newInstallationHost(w.root)
	if err := h.verifyV3Container(c, a); err != nil {
		t.Fatal("correct versioned container rejected", err)
	}
	c.ImageID = "sha256:" + strings.Repeat("f", 64)
	if h.verifyV3Container(c, a) == nil {
		t.Fatal("version name authorized a different actual image")
	}
}
