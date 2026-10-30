package nodeops

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func imageArchiveFixture(t *testing.T, oci bool, change func(map[string]any, *savedImage)) (string, Spec, []byte) {
	t.Helper()
	layer := []byte("immutable layer bytes")
	cfg := map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + sha(layer)}}}
	m := savedImage{RepoTags: []string{"gzdzh/webscan-agent:v3.0.0"}}
	if change != nil {
		change(cfg, &m)
	}
	config, _ := json.Marshal(cfg)
	configSHA := sha(config)
	m.Config, m.Layers = configSHA+".json", []string{sha(layer) + "/layer.tar"}
	if oci {
		m.Config, m.Layers = "blobs/sha256/"+configSHA, []string{"blobs/sha256/" + sha(layer)}
	}
	files := map[string][]byte{m.Config: config, m.Layers[0]: layer}
	manifest, _ := json.Marshal([]savedImage{m})
	files["manifest.json"] = manifest
	if oci {
		blob, _ := json.Marshal(map[string]any{"schemaVersion": 2, "config": map[string]string{"digest": "sha256:" + configSHA}, "layers": []map[string]string{{"digest": "sha256:" + sha(layer)}}})
		files["blobs/sha256/"+sha(blob)] = blob
		index, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []map[string]any{{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + sha(blob)}}})
		files["index.json"] = index
	}
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	var names []string
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if err := tw.WriteHeader(&tar.Header{Name: k, Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(files[k]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[k]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	root := testRoot(t)
	s := Spec{Mode: "docker", AgentImage: "docker.io/gzdzh/webscan-agent@sha256:" + strings.Repeat("a", 64), ImageArchiveSHA256: sha(raw), ImageArchiveBytes: uint64(len(raw)), ImageConfigSHA256: configSHA}
	dir := filepath.Join(root, "images", s.ImageArchiveSHA256)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-image.tar"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return root, s, raw
}

func TestImageArchiveProvesLegacyAndOCIConfigIdentity(t *testing.T) {
	for _, oci := range []bool{false, true} {
		root, s, raw := imageArchiveFixture(t, oci, nil)
		f, err := verifiedImageArchive(context.Background(), root, s)
		if err != nil {
			t.Fatal("valid image proof rejected", oci, err)
		}
		got, err := io.ReadAll(f)
		f.Close()
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatal("verified archive not rewound", err)
		}
	}
	for _, kind := range []string{"arch", "repo", "config", "digest", "size", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root, s, raw := imageArchiveFixture(t, true, func(cfg map[string]any, m *savedImage) {
				if kind == "arch" {
					cfg["architecture"] = "arm64"
				}
				if kind == "repo" {
					m.RepoTags = []string{"other/project:latest"}
				}
			})
			file := filepath.Join(root, "images", s.ImageArchiveSHA256, "docker-image.tar")
			switch kind {
			case "config":
				s.ImageConfigSHA256 = strings.Repeat("f", 64)
			case "digest":
				raw[len(raw)/2] ^= 1
				os.WriteFile(file, raw, 0600)
			case "size":
				s.ImageArchiveBytes++
			case "symlink":
				outside := filepath.Join(testRoot(t), "archive")
				os.WriteFile(outside, raw, 0600)
				os.Remove(file)
				if err := os.Symlink(outside, file); err != nil {
					t.Fatal(err)
				}
			}
			if f, err := verifiedImageArchive(context.Background(), root, s); err == nil {
				f.Close()
				t.Fatal("invalid image proof accepted")
			}
		})
	}
}

func TestImageArchiveAuthenticatesLayerPayloadAndPadding(t *testing.T) {
	for _, kind := range []string{"layer", "padding", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			root, s, raw := imageArchiveFixture(t, true, nil)
			ctx := context.Background()
			switch kind {
			case "layer":
				// Preserve valid tar/JSON metadata while changing only a layer.
				i := bytes.Index(raw, []byte("immutable layer bytes"))
				if i < 0 {
					t.Fatal("missing layer fixture")
				}
				raw[i] ^= 1
			case "padding":
				// Zero padding is legal tar content, but still signed content.
				raw = append(raw, make([]byte, 512)...)
				s.ImageArchiveBytes = uint64(len(raw))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := os.WriteFile(filepath.Join(root, "images", s.ImageArchiveSHA256, "docker-image.tar"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if f, err := verifiedImageArchive(ctx, root, s); err == nil {
				f.Close()
				t.Fatal("unauthenticated archive accepted")
			}
		})
	}
}

func TestDockerPullFailureUsesVerifiedArchiveAndIgnoresLoadMessage(t *testing.T) {
	root, s, raw := imageArchiveFixture(t, true, nil)
	state, bin := testRoot(t), testRoot(t)
	identity, _ := json.Marshal(map[string]any{"id": "sha256:" + s.ImageConfigSHA256, "os": "linux", "arch": "amd64", "repo_digests": nil})
	os.WriteFile(filepath.Join(state, "expected.json"), identity, 0600)
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$WEBSCAN_NODE_TEST_STATE/commands"
case " $* " in
 *' image inspect '*) cat "$WEBSCAN_NODE_TEST_STATE/image.json" ;;
 *' pull '*) exit 17 ;;
 *' load '*) cat > "$WEBSCAN_NODE_TEST_STATE/loaded.tar"; cp "$WEBSCAN_NODE_TEST_STATE/expected.json" "$WEBSCAN_NODE_TEST_STATE/image.json"; echo 'untrusted load message' ;;
 *) exit 99 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("WEBSCAN_NODE_TEST_STATE", state)
	if err := prepareDockerImage(context.Background(), root, s); err != nil {
		t.Fatal("verified fallback failed", err)
	}
	loaded, _ := os.ReadFile(filepath.Join(state, "loaded.tar"))
	if !bytes.Equal(loaded, raw) {
		t.Fatal("different archive sent to engine")
	}
	if err := inspectDockerImage(context.Background(), root, s); err != nil {
		t.Fatal("missing RepoDigests was not resolved by archive proof", err)
	}
	if err := prepareDockerImage(context.Background(), root, s); err != nil {
		t.Fatal("verified loaded image not reusable", err)
	}
	commands, _ := os.ReadFile(filepath.Join(state, "commands"))
	if strings.Count(string(commands), " load\n") != 1 {
		t.Fatal("reloaded cached image", string(commands))
	}
	archive := filepath.Join(root, "images", s.ImageArchiveSHA256, "docker-image.tar")
	if err := os.WriteFile(archive, bytes.Repeat([]byte("x"), len(raw)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := inspectDockerImage(context.Background(), root, s); err == nil {
		t.Fatal("cached image accepted after provenance changed")
	}
	if err := prepareDockerImage(context.Background(), root, s); err == nil {
		t.Fatal("corrupt archive fallback accepted")
	}
	commands, _ = os.ReadFile(filepath.Join(state, "commands"))
	if strings.Count(string(commands), " load\n") != 1 {
		t.Fatal("corrupt archive reached Docker engine")
	}
}

func TestImageArchiveRejectsDirectoryAsLayerAndTrailingData(t *testing.T) {
	for _, kind := range []string{"directory", "duplicate", "trailer"} {
		t.Run(kind, func(t *testing.T) {
			_, s, raw := imageArchiveFixture(t, false, nil)
			var b bytes.Buffer
			tr, tw := tar.NewReader(bytes.NewReader(raw)), tar.NewWriter(&b)
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(tr)
				if err != nil {
					t.Fatal(err)
				}
				layer := strings.HasSuffix(h.Name, "/layer.tar")
				if layer && kind == "directory" {
					h.Typeflag, h.Size = tar.TypeDir, 0
					body = nil
				}
				if err := tw.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
				tw.Write(body)
				if layer && kind == "duplicate" {
					tw.WriteHeader(h)
					tw.Write(body)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if kind == "trailer" {
				b.WriteString("unexpected data")
			}
			s.ImageArchiveBytes = uint64(b.Len())
			if err := inspectSavedImage(context.Background(), bytes.NewReader(b.Bytes()), s); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	if sameImageRepository("gzdzh/webscan-agent:v3.0.0", "invalid") {
		t.Fatal("invalid expected image accepted")
	}
}

func TestImageArchiveManifestIdentityRequiresCompleteValidation(t *testing.T) {
	for _, oci := range []bool{false, true} {
		root, spec, raw := imageArchiveFixture(t, oci, nil)
		f, digest, err := verifiedImageArchiveManifest(context.Background(), root, spec)
		if err != nil {
			t.Fatal(err)
		}
		head := make([]byte, 16)
		if _, err := io.ReadFull(f, head); err != nil {
			t.Fatal("verified archive not rewound", err)
		}
		f.Close()
		if oci && (!strings.HasPrefix(digest, "sha256:") || !validDigest(strings.TrimPrefix(digest, "sha256:"))) {
			t.Fatal("missing verified OCI manifest digest", digest)
		}
		if !oci && digest != "" {
			t.Fatal("legacy archive must not invent manifest identity", digest)
		}
		if oci {
			tr := tar.NewReader(bytes.NewReader(raw))
			var expected string
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if h.Name == "index.json" {
					var index struct {
						Manifests []struct {
							Digest string `json:"digest"`
						} `json:"manifests"`
					}
					if err := json.NewDecoder(tr).Decode(&index); err != nil || len(index.Manifests) != 1 {
						t.Fatal("invalid test index", err)
					}
					expected = index.Manifests[0].Digest
				}
			}
			if digest != expected {
				t.Fatal("returned identity differs from verified index", digest, expected)
			}
		}
	}
	root, spec, raw := imageArchiveFixture(t, true, nil)
	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)/2] ^= 1
	if err := os.WriteFile(filepath.Join(root, "images", spec.ImageArchiveSHA256, "docker-image.tar"), corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if f, digest, err := verifiedImageArchiveManifest(context.Background(), root, spec); err == nil || f != nil || digest != "" {
		if f != nil {
			f.Close()
		}
		t.Fatal("tampered signed archive exposed manifest identity", err, digest)
	}
	// The digest must never escape if later validation fails.
	raw = append(raw, 'x')
	digest := "old value"
	if err := inspectSavedImageManifest(context.Background(), bytes.NewReader(raw), spec, &digest); err == nil || digest != "" {
		t.Fatal("invalid trailer exposed manifest identity", err, digest)
	}
}

func TestImageRepositoryDockerHubDefaultNamespace(t *testing.T) {
	expected := "docker.io/library/webscan-agent@sha256:" + strings.Repeat("a", 64)
	for _, tag := range []string{"webscan-agent:pilot", "library/webscan-agent:pilot", "docker.io/webscan-agent:pilot", "docker.io/library/webscan-agent:pilot"} {
		if !sameImageRepository(tag, expected) {
			t.Fatalf("same Docker Hub repository rejected: %s", tag)
		}
	}
	for _, tag := range []string{"other/webscan-agent:pilot", "example.com/library/webscan-agent:pilot", "localhost:5000/library/webscan-agent:pilot", "docker.io/library/other:pilot", "webscan-agent@sha256:" + strings.Repeat("a", 64)} {
		if sameImageRepository(tag, expected) {
			t.Fatalf("different repository accepted: %s", tag)
		}
	}
	if !sameImageRepository("gzdzh/webscan-agent:pilot", "docker.io/gzdzh/webscan-agent@sha256:"+strings.Repeat("a", 64)) {
		t.Fatal("explicit owner rejected")
	}
}

func TestImageArchiveMixedShortTagAndFullOCIName(t *testing.T) {
	_, s, raw := imageArchiveFixture(t, true, func(_ map[string]any, m *savedImage) { m.RepoTags = []string{"webscan-agent:pilot"} })
	s.AgentImage = "docker.io/library/webscan-agent@sha256:" + strings.Repeat("a", 64)
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(tr)
		if e != nil {
			t.Fatal(e)
		}
		if h.Name == "index.json" {
			var index map[string]any
			json.Unmarshal(body, &index)
			m := index["manifests"].([]any)[0].(map[string]any)
			m["annotations"] = map[string]string{"io.containerd.image.name": "docker.io/library/webscan-agent:pilot", "org.opencontainers.image.ref.name": "pilot"}
			body, _ = json.Marshal(index)
			h.Size = int64(len(body))
		}
		if e = tw.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if _, e = tw.Write(body); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	s.ImageArchiveBytes = uint64(b.Len())
	if e := inspectSavedImage(context.Background(), bytes.NewReader(b.Bytes()), s); e != nil {
		t.Fatal("Docker 29 archive alias mismatch", e)
	}
	s.AgentImage = "docker.io/other/webscan-agent@sha256:" + strings.Repeat("a", 64)
	if e := inspectSavedImage(context.Background(), bytes.NewReader(b.Bytes()), s); e == nil {
		t.Fatal("unrelated owner accepted")
	}
}
