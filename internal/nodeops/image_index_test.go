package nodeops

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"
)

func TestSavedOCIIndexRequiresOneSignedPlatformManifest(t *testing.T) {
	for _, kind := range []string{"valid-attestation", "wrong-config", "wrong-layer", "wrong-platform", "duplicate-runtime", "attestation-only", "unknown-unmarked", "broken-blob", "depth-limit"} {
		t.Run(kind, func(t *testing.T) {
			_, spec, raw := imageArchiveFixture(t, true, nil)
			metadata := map[string][]byte{}
			tr := tar.NewReader(bytes.NewReader(raw))
			for {
				h, e := tr.Next()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
				metadata[h.Name], e = io.ReadAll(tr)
				if e != nil {
					t.Fatal(e)
				}
			}
			var top savedOCIIndex
			if e := json.Unmarshal(metadata["index.json"], &top); e != nil {
				t.Fatal(e)
			}
			runnable := top.Manifests[0]
			runnable.Platform = &struct {
				OS   string `json:"os"`
				Arch string `json:"architecture"`
			}{"linux", "amd64"}
			attRaw := []byte(`{"schemaVersion":2,"artifactType":"application/vnd.in-toto+json"}`)
			att := savedOCIDescriptor{Digest: "sha256:" + sha(attRaw), Media: "application/vnd.oci.image.manifest.v1+json", Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"}, Platform: &struct {
				OS   string `json:"os"`
				Arch string `json:"architecture"`
			}{"unknown", "unknown"}}
			metadata["blobs/sha256/"+sha(attRaw)] = attRaw
			children := []savedOCIDescriptor{runnable, att}
			switch kind {
			case "wrong-config":
				spec.ImageConfigSHA256 = sha([]byte("other config"))
			case "wrong-layer":
				// Config identity alone cannot prove the selected layer metadata.
				var manifest map[string]any
				_ = json.Unmarshal(metadata["blobs/sha256/"+runnable.Digest[7:]], &manifest)
				manifest["layers"] = []map[string]string{{"digest": "sha256:" + sha([]byte("other layer"))}}
				blob, _ := json.Marshal(manifest)
				metadata["blobs/sha256/"+sha(blob)] = blob
				children[0].Digest = "sha256:" + sha(blob)
			case "wrong-platform":
				children[0].Platform.Arch = "arm64"
			case "duplicate-runtime":
				children = append(children, runnable)
			case "attestation-only":
				children = []savedOCIDescriptor{att}
			case "unknown-unmarked":
				children[1].Annotations = nil
			case "broken-blob":
				metadata["blobs/sha256/"+runnable.Digest[7:]] = []byte(`{"schemaVersion":2}`)
			}
			// A real Docker-save index names another index containing the platform
			// image and an attestation, rather than naming the runnable image directly.
			blob, _ := json.Marshal(savedOCIIndex{Schema: 2, Manifests: children})
			metadata["blobs/sha256/"+sha(blob)] = blob
			root := savedOCIDescriptor{Media: "application/vnd.oci.image.index.v1+json", Digest: "sha256:" + sha(blob)}
			if kind == "depth-limit" {
				for i := 0; i < 5; i++ {
					blob, _ = json.Marshal(savedOCIIndex{Schema: 2, Manifests: []savedOCIDescriptor{root}})
					metadata["blobs/sha256/"+sha(blob)] = blob
					root.Digest = "sha256:" + sha(blob)
				}
			}
			index, _ := json.Marshal(savedOCIIndex{Schema: 2, Manifests: []savedOCIDescriptor{root}})
			var saved []savedImage
			_ = json.Unmarshal(metadata["manifest.json"], &saved)
			id, e := verifySavedOCIIndex(metadata, index, spec, saved[0])
			if kind == "valid-attestation" {
				if e != nil || id != root.Digest {
					t.Fatal("valid nested index rejected", e)
				}
			} else if e == nil || id != "" {
				t.Fatal("unproved nested image accepted", kind)
			}
		})
	}
}

// Opt-in read-only validation of a real locally exported containerd archive.
func TestSavedOCIRealArchive(t *testing.T) {
	path := os.Getenv("WEBSCAN_V3_TEST_SAVED_ARCHIVE")
	if path == "" {
		t.Skip("explicit local test archive required")
	}
	proof, e := os.ReadFile(os.Getenv("WEBSCAN_V3_TEST_SAVED_PROOF"))
	if e != nil {
		t.Fatal(e)
	}
	var spec Spec
	if json.Unmarshal(proof, &spec) != nil || !spec.imageArchiveValid() {
		t.Fatal("invalid archive proof")
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	var id string
	if e = inspectSavedImageManifest(context.Background(), f, spec, &id); e != nil || id == "" {
		t.Fatal("real archive validation failed", e)
	}
	t.Log("real signed-config/OCI-index proof verified", id)
}
