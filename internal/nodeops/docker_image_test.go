package nodeops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func imageFixture() (string, map[string]any) {
	ref := "docker.io/gzdzh/webscan-agent@sha256:" + strings.Repeat("a", 64)
	return ref, map[string]any{"id": "sha256:" + strings.Repeat("b", 64), "repo_digests": []string{"gzdzh/webscan-agent@sha256:" + strings.Repeat("a", 64)}, "os": "linux", "arch": "amd64"}
}

func TestDockerIdentityRequiresPlatformAndRepositoryDigest(t *testing.T) {
	ref, image := imageFixture()
	raw, _ := json.Marshal(image)
	if err := verifyDockerImageIdentity(string(raw), ref); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]any){
		func(m map[string]any) { m["repo_digests"] = nil },
		func(m map[string]any) { m["repo_digests"] = []string{"gzdzh/webscan-agent:latest"} },
		func(m map[string]any) {
			m["repo_digests"] = []string{"gzdzh/webscan-agent@sha256:" + strings.Repeat("c", 64)}
		},
		func(m map[string]any) { m["os"] = "windows" }, func(m map[string]any) { m["arch"] = "arm64" },
		func(m map[string]any) { m["id"] = "sha256:invalid" },
	} {
		_, bad := imageFixture()
		change(bad)
		raw, _ := json.Marshal(bad)
		if err := verifyDockerImageIdentity(string(raw), ref); err == nil {
			t.Fatal("unproven image identity accepted", bad)
		}
	}
	for _, bad := range []string{"webscan:latest", ref + ";id", "--privileged", "x@sha256:invalid"} {
		if ValidAgentImage(bad) || verifyDockerImageIdentity(string(raw), bad) == nil {
			t.Fatal("unsafe image reference accepted", bad)
		}
	}
}

func TestDockerIdentityAlsoBindsLaunchConfigWhenArchiveIsSigned(t *testing.T) {
	ref, image := imageFixture()
	s := Spec{Mode: "docker", AgentImage: ref, ImageArchiveSHA256: strings.Repeat("c", 64), ImageArchiveBytes: 1024, ImageConfigSHA256: strings.Repeat("b", 64)}
	raw, _ := json.Marshal(image)
	if err := verifyDockerImageForSpec(string(raw), s); err != nil {
		t.Fatal(err)
	}
	image["id"] = "sha256:" + strings.Repeat("e", 64)
	raw, _ = json.Marshal(image)
	if verifyDockerImageForSpec(string(raw), s) == nil {
		t.Fatal("repository digest was accepted for a different signed launch config")
	}
	// Without a signed archive/config binding, repository identity remains the
	// required proof and launch continues to use the immutable registry digest.
	s.ImageArchiveSHA256, s.ImageArchiveBytes, s.ImageConfigSHA256 = "", 0, ""
	if err := verifyDockerImageForSpec(string(raw), s); err != nil {
		t.Fatal("registry-only release rejected", err)
	}
}

// Docker's containerd image store can report the manifest digest as Id,
// rather than the signed archive's config digest. Until the complete load,
// launch and ownership path supports that identity, fail closed.
func TestDockerContainerdManifestIDIsNotTreatedAsSignedConfig(t *testing.T) {
	ref, image := imageFixture()
	s := Spec{Mode: "docker", AgentImage: ref, ImageArchiveSHA256: strings.Repeat("c", 64), ImageArchiveBytes: 1024, ImageConfigSHA256: strings.Repeat("b", 64)}
	image["id"] = "sha256:" + strings.Repeat("a", 64)
	raw, err := json.Marshal(image)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDockerImageForSpec(string(raw), s); err == nil {
		t.Fatal("manifest digest must not be accepted as a verified config digest")
	}
}

func TestDockerStagePullsPinnedImageAndRechecksOnReplay(t *testing.T) {
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	state := testRoot(t)
	ref, expected := imageFixture()
	r.Spec.Mode, r.Spec.AgentImage = "docker", ref
	raw, _ := json.Marshal(expected)
	if err := os.WriteFile(filepath.Join(state, "expected.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$WEBSCAN_NODE_TEST_STATE/commands"
case " $* " in
  *' image inspect '*) cat "$WEBSCAN_NODE_TEST_STATE/image.json" ;;
  *' pull '*) cp "$WEBSCAN_NODE_TEST_STATE/expected.json" "$WEBSCAN_NODE_TEST_STATE/image.json" ;;
  *) exit 99 ;;
esac
`
	bin := testRoot(t)
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("WEBSCAN_NODE_TEST_STATE", state)
	t.Setenv("DOCKER_HOST", "tcp://must-never-use-remote-engine:2375")
	if _, err := w.Apply(r); err != nil {
		t.Fatal("Docker preparation failed", err)
	}
	commands, _ := os.ReadFile(filepath.Join(state, "commands"))
	if !strings.Contains(string(commands), "pull --platform linux/amd64 "+ref) || !strings.Contains(string(commands), "--host unix:///var/run/docker.sock --config ") || strings.Contains(string(commands), "remote-engine") || strings.Contains(string(commands), "run ") || strings.Contains(string(commands), "stop ") {
		t.Fatal("unexpected engine operations", string(commands))
	}
	if err := w.VerifyCompleted(r, stageOutcome(r.Spec)); err != nil {
		t.Fatal("verified image not replayable", err)
	}
	if err := os.WriteFile(filepath.Join(state, "image.json"), []byte(`{"id":"wrong"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := w.VerifyCompleted(r, stageOutcome(r.Spec)); err == nil {
		t.Fatal("stale receipt accepted replaced image")
	}
	stateName, _, err := w.Reconcile(r)
	if stateName != "absent" || err != nil {
		t.Fatal("interrupted immutable download cannot retry", stateName, err)
	}
	if err := prepareDockerImage(context.Background(), w.root, r.Spec); err != nil {
		t.Fatal("immutable pull did not recover", err)
	}
}

func TestContainerdLaunchReceiptRequiresVerifiedArchiveManifest(t *testing.T) {
	root, s, _ := imageArchiveFixture(t, true, nil)
	f, manifest, err := verifiedImageArchiveManifest(context.Background(), root, s)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if manifest == "" {
		t.Fatal("missing OCI manifest")
	}
	if err = recordDockerLaunchReference(root, s, manifest, manifest); err != nil {
		t.Fatal(err)
	}
	got, err := dockerLaunchReference(root, s)
	if err != nil || got != manifest {
		t.Fatal(got, err)
	}
	if err = recordDockerLaunchReference(root, s, "sha256:"+strings.Repeat("f", 64), manifest); err == nil {
		t.Fatal("unrelated image accepted")
	}
	file := filepath.Join(root, "images", s.ImageArchiveSHA256, "launch-image")
	if err = os.WriteFile(file, []byte("sha256:"+strings.Repeat("f", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = dockerLaunchReference(root, s); err == nil {
		t.Fatal("forged launch receipt accepted")
	}
}
