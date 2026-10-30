package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceDigestIncludesUntrackedAPIAndProtocol(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := exec.Command("git", "init", "-q").Run(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"api/control/v3/models.go", "sdk/agent/v1/agent.proto", "web/v3.html"} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before, err := currentSourceDigest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"api/control/v3/models.go", "sdk/agent/v1/agent.proto", "web/v3.html"} {
		if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
			t.Fatal(err)
		}
		after, err := currentSourceDigest(context.Background())
		if err != nil || after == before {
			t.Fatal("source changed without digest changing", path, err)
		}
		before = after
	}
}

func TestFormalPublicationBindsEvidenceAndEveryRequiredGate(t *testing.T) {
	dir := t.TempDir()
	evidence := filepath.Join(dir, "acceptance.log")
	if err := os.WriteFile(evidence, []byte("actual isolated result\n"), 0600); err != nil {
		t.Fatal(err)
	}
	hash, _ := fileSHA(evidence)
	b := buildRecord{Release: "v3.0.0", Commit: strings.Repeat("a", 40), Source: strings.Repeat("b", 64)}
	r := verificationRecord{Release: b.Release, Commit: b.Commit, Source: b.Source}
	r.Gates = make(map[string]struct {
		Passed   bool   `json:"passed"`
		Evidence string `json:"evidence"`
		SHA256   string `json:"sha256"`
	})
	for _, name := range formalGates {
		r.Gates[name] = struct {
			Passed   bool   `json:"passed"`
			Evidence string `json:"evidence"`
			SHA256   string `json:"sha256"`
		}{true, "acceptance.log", hash}
	}
	path := filepath.Join(dir, "verification.json")
	write := func() {
		raw, _ := json.Marshal(r)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := checkVerification(path, b); err != nil {
		t.Fatal(err)
	}
	r.Commit = strings.Repeat("c", 40)
	write()
	if checkVerification(path, b) == nil {
		t.Fatal("different source accepted")
	}
	r.Commit = b.Commit
	delete(r.Gates, "docker29-lifecycle")
	write()
	if checkVerification(path, b) == nil {
		t.Fatal("missing Docker 29 acceptance accepted")
	}
	r.Gates["docker29-lifecycle"] = r.Gates["native-lifecycle"]
	delete(r.Gates, "web-deployment-docker29")
	write()
	if checkVerification(path, b) == nil {
		t.Fatal("separate lifecycle proof substituted for full web deployment")
	}
	r.Gates["web-deployment-docker29"] = r.Gates["native-lifecycle"]
	write()
	if err := os.WriteFile(evidence, []byte("replaced result"), 0600); err != nil {
		t.Fatal(err)
	}
	if checkVerification(path, b) == nil {
		t.Fatal("replaced evidence accepted")
	}
}

func TestFormalPublicationRejectsDirtyBuildAndReplacedArtifacts(t *testing.T) {
	dir := t.TempDir()
	b := buildRecord{Release: "v3.0.0", Commit: strings.Repeat("a", 40), Source: strings.Repeat("b", 64)}
	write := func() { raw, _ := json.Marshal(b); os.WriteFile(filepath.Join(dir, "build-info.json"), raw, 0600) }
	write()
	for _, name := range releaseArtifacts[:3] {
		os.WriteFile(filepath.Join(dir, name), []byte(name), 0600)
	}
	if err := writeBuildReceipt(dir, map[string]string{"central": "sha256:one", "agent": "sha256:two"}); err != nil {
		t.Fatal(err)
	}
	if _, err := readBuildReceipt(dir, b.Release); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "webscan"), []byte("replaced"), 0600)
	if _, err := readBuildReceipt(dir, b.Release); err == nil {
		t.Fatal("replaced binary accepted")
	}
	b.Commit += "-dirty"
	write()
	if err := writeBuildReceipt(dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := readBuildReceipt(dir, b.Release); err == nil {
		t.Fatal("dirty build accepted")
	}
}
