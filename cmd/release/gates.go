package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"webscan/internal/common"
	"webscan/internal/controlplane"
)

type buildRecord struct {
	Release string `json:"release"`
	Commit  string `json:"commit"`
	Source  string `json:"source_digest"`
	BuiltAt string `json:"built_at"`
}
type imageBuildReceipt struct {
	Build     buildRecord       `json:"build"`
	Artifacts map[string]string `json:"artifacts"`
	Images    map[string]string `json:"images"`
}
type verificationRecord struct {
	Release string `json:"release"`
	Commit  string `json:"commit"`
	Source  string `json:"source_digest"`
	Gates   map[string]struct {
		Passed   bool   `json:"passed"`
		Evidence string `json:"evidence"`
		SHA256   string `json:"sha256"`
	} `json:"gates"`
}

var formalGates = []string{"settings", "security", "native-lifecycle", "docker29-lifecycle", "web-deployment-native", "web-deployment-docker29", "collection", "unchanged-central", "frontend", "go-race", "browser", "single-install", "single-upgrade"}
var releaseArtifacts = []string{"webscan", "agent-native.tar.gz", "install.sh", "build-info.json"}
var errPublicationGate = errors.New("正式发布门禁未通过：需要已推送且干净的真实源码提交、匹配的构建产物、签名清单及全部隔离验收记录；未更新 latest")

func fileSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func readReleaseJSON(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 1<<20 {
		return errPublicationGate
	}
	if json.Unmarshal(raw, out) != nil {
		return errPublicationGate
	}
	return nil
}
func readBuildReceipt(root, version string) (imageBuildReceipt, error) {
	var r imageBuildReceipt
	if readReleaseJSON(filepath.Join(root, "image-build.json"), &r) != nil || r.Build.Release != version || len(r.Build.Commit) != 40 || strings.Contains(r.Build.Commit, "dirty") || len(r.Build.Source) != 64 {
		return r, errPublicationGate
	}
	for _, name := range releaseArtifacts {
		got, err := fileSHA(filepath.Join(root, name))
		if err != nil || got != r.Artifacts[name] {
			return r, errPublicationGate
		}
	}
	var b buildRecord
	if readReleaseJSON(filepath.Join(root, "build-info.json"), &b) != nil || b != r.Build {
		return r, errPublicationGate
	}
	return r, nil
}
func checkVerification(path string, b buildRecord) error {
	var r verificationRecord
	if readReleaseJSON(path, &r) != nil || r.Release != b.Release || r.Commit != b.Commit || r.Source != b.Source {
		return errPublicationGate
	}
	for _, name := range formalGates {
		g, ok := r.Gates[name]
		if !ok || !g.Passed || g.Evidence == "" || len(g.SHA256) != 64 {
			return errPublicationGate
		}
		p := g.Evidence
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(path), p)
		}
		got, err := fileSHA(p)
		if err != nil || got != g.SHA256 {
			return errPublicationGate
		}
	}
	return nil
}
func checkPublicationSource(ctx context.Context, b buildRecord) error {
	git := func(args ...string) (string, error) {
		raw, err := exec.CommandContext(ctx, "git", args...).Output()
		return strings.TrimSpace(string(raw)), err
	}
	head, err := git("rev-parse", "HEAD")
	if err != nil || head != b.Commit {
		return errPublicationGate
	}
	source, err := currentSourceDigest(ctx)
	if err != nil || source != b.Source {
		return errPublicationGate
	}
	// Generated frontend files are part of the committed source too. A rebuild
	// with different output needs another reviewed commit and build.
	status, err := git("status", "--porcelain", "--untracked-files=all")
	if err != nil || status != "" {
		return errPublicationGate
	}
	remote, err := git("config", "--get", "branch.main.remote")
	if err != nil || remote == "" {
		return errPublicationGate
	}
	ref, err := git("config", "--get", "branch.main.merge")
	if err != nil || ref == "" {
		return errPublicationGate
	}
	advertised, err := git("ls-remote", "--exit-code", remote, ref)
	if err != nil || len(strings.Fields(advertised)) != 2 || strings.Fields(advertised)[0] != head {
		return errPublicationGate
	}
	return nil
}

var sourcePaths = []string{"internal", "cmd", "api", "sdk", "scripts", "web/src", "web/index.html", "web/v3.html", "web/package.json", "web/package-lock.json", "web/vite.config.ts", "web/tsconfig.json", "web/tsconfig.node.json", "go.mod", "go.sum", "Dockerfile", "Dockerfile.release", "config", "install.sh"}

// Matches package.sh's SHA256 of `shasum -a 256` output, including filenames.
func currentSourceDigest(ctx context.Context) (string, error) {
	args := append([]string{"ls-files", "-z", "--cached", "--others", "--exclude-standard", "--"}, sourcePaths...)
	raw, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, path := range strings.Split(string(raw), "\x00") {
		if path == "" {
			continue
		}
		if strings.ContainsAny(path, "\r\n\\") {
			return "", errPublicationGate
		}
		sum, err := fileSHA(path)
		if err != nil {
			return "", err
		}
		h.Write([]byte(sum + "  " + path + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func checkSignedArtifacts(root, manifest, signature, key, version string) (controlplane.ReleaseManifest, error) {
	var m controlplane.ReleaseManifest
	t, _, err := controlplane.LoadTrustedRelease(manifest, signature, key)
	if err != nil {
		return m, errPublicationGate
	}
	raw, err := os.ReadFile(manifest)
	h := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(h[:]) != t.SHA256() || json.Unmarshal(raw, &m) != nil || m.Release != version {
		return m, errPublicationGate
	}
	for name, want := range map[string]controlplane.ReleaseArtifact{"webscan": m.Helper, "agent-native.tar.gz": m.Native} {
		got, err := fileSHA(filepath.Join(root, name))
		stat, e := os.Stat(filepath.Join(root, name))
		if err != nil || e != nil || got != want.SHA256 || uint64(stat.Size()) != want.Bytes {
			return m, errPublicationGate
		}
	}
	return m, nil
}
func writeBuildReceipt(root string, images map[string]string) error {
	var b buildRecord
	if err := readReleaseJSON(filepath.Join(root, "build-info.json"), &b); err != nil {
		return err
	}
	r := imageBuildReceipt{Build: b, Images: images, Artifacts: map[string]string{}}
	for _, name := range releaseArtifacts {
		got, err := fileSHA(filepath.Join(root, name))
		if err != nil {
			return err
		}
		r.Artifacts[name] = got
	}
	return common.AtomicJSON(filepath.Join(root, "image-build.json"), r)
}
