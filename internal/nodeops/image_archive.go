package nodeops

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type savedImage struct {
	Config   string
	RepoTags []string
	Layers   []string
}

// The signed release manifest supplies both the archive SHA256 and config ID.
// Neither a tag in manifest.json nor the load command's output establishes
// identity. This handles Docker-save and the OCI-backed Docker-save format.
func verifiedImageArchive(ctx context.Context, root string, s Spec) (*os.File, error) {
	f, _, err := verifiedImageArchiveManifest(ctx, root, s)
	return f, err
}

// Return the digest from the same authenticated parse. Parsing the archive
// again duplicates every layer read and can exhaust a bounded SSH phase on
// slow storage, although none of the trust decisions has changed.
func verifiedImageArchiveManifest(ctx context.Context, root string, s Spec) (*os.File, string, error) {
	if !s.imageArchiveValid() {
		return nil, "", errors.New("missing-image-archive-proof")
	}
	dir := filepath.Join(root, "images", s.ImageArchiveSHA256)
	for _, d := range []string{root, filepath.Join(root, "images"), dir} {
		if err := privateDirectoryTree(d); err != nil {
			return nil, "", err
		}
	}
	f, err := openPrivateFile(filepath.Join(dir, "docker-image.tar"))
	if err != nil {
		return nil, "", err
	}
	valid := false
	defer func() {
		if !valid {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil || st.Size() < 1 || uint64(st.Size()) != s.ImageArchiveBytes {
		return nil, "", errors.New("image-archive-size-mismatch")
	}
	// Authenticate exactly the bytes being parsed, including layer payloads and
	// tar padding. The parser consumes the complete bounded stream; hashing a
	// separate pass both doubles disk IO and can authenticate a different read.
	hash := sha256.New()
	stream := &io.LimitedReader{R: &contextReader{ctx, f}, N: int64(s.ImageArchiveBytes) + 1}
	var manifest string
	if err := inspectSavedImageManifest(ctx, io.TeeReader(stream, hash), s, &manifest); err != nil {
		return nil, "", err
	}
	if stream.N != 1 || hex.EncodeToString(hash.Sum(nil)) != s.ImageArchiveSHA256 {
		return nil, "", errors.New("image-archive-digest-mismatch")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, "", err
	}
	valid = true
	return f, manifest, nil
}

func inspectSavedImage(ctx context.Context, source io.Reader, s Spec) error {
	return inspectSavedImageManifest(ctx, source, s, nil)
}

// inspectSavedImageManifest returns an OCI manifest digest only after the
// complete archive, platform, config and layer metadata checks succeed. The
// archive itself must also be authenticated with verifiedImageArchive before
// using this value for a runtime decision. A legacy Docker-save has no OCI
// manifest and returns an empty digest.
func inspectSavedImageManifest(ctx context.Context, source io.Reader, s Spec, manifestDigest *string) error {
	if manifestDigest != nil {
		*manifestDigest = ""
	}
	var verifiedManifest string
	tr := tar.NewReader(&contextReader{ctx, source})
	files := map[string]byte{}
	metadata := map[string][]byte{}
	metadataBytes := 0
	for i := 0; ; i++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || i >= 4096 || h.Size < 0 || uint64(h.Size) > s.ImageArchiveBytes {
			return errors.New("invalid-image-archive")
		}
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		_, duplicate := files[name]
		if name == "" || strings.HasPrefix(h.Name, "/") || path.Clean(name) != name || strings.Contains(name, "\\") || duplicate || h.Linkname != "" || h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return errors.New("unsafe-image-archive-entry")
		}
		for _, part := range strings.Split(name, "/") {
			if !bundleName.MatchString(part) {
				return errors.New("unsafe-image-archive-entry")
			}
		}
		files[name] = h.Typeflag
		if h.Typeflag == tar.TypeDir {
			continue
		}
		// Large layer blobs are never buffered. Small JSON blobs are retained
		// only to resolve an OCI index encountered after its referenced manifest.
		if h.Size <= 1<<20 {
			raw, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			if json.Valid(raw) {
				metadataBytes += len(raw)
				if metadataBytes > 8<<20 {
					return errors.New("image-metadata-too-large")
				}
				metadata[name] = raw
			}
		}
	}
	var manifests []savedImage
	if json.Unmarshal(metadata["manifest.json"], &manifests) != nil || len(manifests) != 1 {
		return errors.New("image-archive-requires-one-image")
	}
	m := manifests[0]
	if m.Config != s.ImageConfigSHA256+".json" && m.Config != "blobs/sha256/"+s.ImageConfigSHA256 {
		return errors.New("image-archive-config-mismatch")
	}
	config, ok := metadata[m.Config]
	if !ok || sha(config) != s.ImageConfigSHA256 {
		return errors.New("image-archive-config-mismatch")
	}
	var cfg struct {
		OS     string `json:"os"`
		Arch   string `json:"architecture"`
		RootFS struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if json.Unmarshal(config, &cfg) != nil || cfg.OS != "linux" || cfg.Arch != "amd64" || cfg.RootFS.Type != "layers" || len(cfg.RootFS.DiffIDs) != len(m.Layers) || len(m.Layers) > 512 {
		return errors.New("image-archive-platform-or-layers-invalid")
	}
	for i, layer := range m.Layers {
		if files[layer] != tar.TypeReg || !strings.HasPrefix(cfg.RootFS.DiffIDs[i], "sha256:") || !validDigest(strings.TrimPrefix(cfg.RootFS.DiffIDs[i], "sha256:")) {
			return errors.New("image-archive-layer-missing")
		}
	}
	for _, tag := range m.RepoTags {
		if !sameImageRepository(tag, s.AgentImage) {
			return errors.New("image-archive-unrelated-tag")
		}
	}
	if raw := metadata["index.json"]; raw != nil {
		var err error
		verifiedManifest, err = verifySavedOCIIndex(metadata, raw, s, m)
		if err != nil {
			return err
		}
	}
	// Legacy and OCI Docker-save archives pad the outer tar with zero blocks.
	padding, err := io.ReadAll(io.LimitReader(&contextReader{ctx, source}, 1<<20+1))
	if err != nil || len(padding) > 1<<20 || bytes.Count(padding, []byte{0}) != len(padding) {
		return errors.New("image-archive-invalid-trailer")
	}
	if manifestDigest != nil {
		*manifestDigest = verifiedManifest
	}
	return nil
}

func sameImageRepository(tag, expected string) bool {
	if !ValidAgentImage(expected) || strings.ContainsAny(tag, "\x00\r\n ") || strings.Contains(tag, "@") {
		return false
	}
	colon := strings.LastIndex(tag, ":")
	if colon <= strings.LastIndex(tag, "/") || colon == len(tag)-1 {
		return false
	}
	repository := tag[:colon]
	want, version := agentImageName(expected)
	if version != "" && tag[colon+1:] != version {
		return false
	}
	return canonicalImageRepository(repository) == canonicalImageRepository(want)
}

// Docker-save may use a short RepoTag while its OCI index expands the same
// Docker Hub repository to docker.io/library/name. Normalize only the default
// registry and namespace; a different registry or owner remains different.
func canonicalImageRepository(repository string) string {
	registry, name := "docker.io", repository
	if first, rest, ok := strings.Cut(repository, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		registry, name = first, rest
	}
	if registry == "docker.io" && !strings.Contains(name, "/") {
		name = "library/" + name
	}
	return registry + "/" + name
}
