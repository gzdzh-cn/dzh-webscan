package deploy

import (
	"archive/tar"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/common"
)

func imageArchiveFixture(t *testing.T, oci bool, change func(map[string][]byte)) (string, string, string) {
	t.Helper()
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	configID := "sha256:" + common.Hash(config)
	manifest := []byte(`{"schemaVersion":2,"config":{"digest":"` + configID + `"},"layers":[]}`)
	manifestID := "sha256:" + common.Hash(manifest)
	files := map[string][]byte{"blobs/sha256/" + common.Hash(config): config}
	files["manifest.json"], _ = json.Marshal([]any{common.Map{"Config": "blobs/sha256/" + common.Hash(config), "RepoTags": nil, "Layers": []string{}}})
	if oci {
		files["blobs/sha256/"+common.Hash(manifest)] = manifest
		files["index.json"], _ = json.Marshal(common.Map{"schemaVersion": 2, "manifests": []any{common.Map{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestID, "size": len(manifest)}}})
	}
	if change != nil {
		change(files)
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := tar.NewWriter(f)
	for name, data := range files {
		if err = w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return path, configID, manifestID
}

func TestArchiveImageIdentitiesBindOCIManifestToConfig(t *testing.T) {
	for _, oci := range []bool{false, true} {
		path, config, manifest := imageArchiveFixture(t, oci, nil)
		ids, err := archiveImageIdentities(path)
		want := []string{config}
		if oci {
			want = append(want, manifest)
		}
		if err != nil || strings.Join(ids, ",") != strings.Join(want, ",") {
			t.Fatal(oci, ids, err)
		}
	}
	for _, bad := range []string{"changed-blob", "different-config", "multiple-manifests", "invalid-digest"} {
		t.Run(bad, func(t *testing.T) {
			path, _, _ := imageArchiveFixture(t, true, func(files map[string][]byte) {
				var index common.Map
				json.Unmarshal(files["index.json"], &index)
				d := common.M(common.A(index["manifests"])[0])
				name := "blobs/sha256/" + strings.TrimPrefix(common.S(d["digest"]), "sha256:")
				switch bad {
				case "changed-blob":
					files[name] = append(files[name], ' ')
				case "different-config":
					b := []byte(`{"config":{"digest":"sha256:unrelated"}}`)
					d["digest"], d["size"] = "sha256:"+common.Hash(b), len(b)
					files["blobs/sha256/"+common.Hash(b)] = b
				case "multiple-manifests":
					index["manifests"] = []any{d, d}
				case "invalid-digest":
					d["digest"] = "../../image"
				}
				files["index.json"], _ = json.Marshal(index)
			})
			if _, err := archiveImageIdentities(path); err == nil {
				t.Fatal("unverified manifest identity accepted")
			}
		})
	}
}

func TestTransferImageSupportsConfigAndManifestIDsAndRequiresSuccessfulLoad(t *testing.T) {
	for _, mode := range []string{"legacy-config", "oci-config", "oci-manifest", "repository-digest", "wrong-image", "load-failed", "resume-cache"} {
		t.Run(mode, func(t *testing.T) {
			path, config, manifest := imageArchiveFixture(t, mode != "legacy-config", nil)
			bin := t.TempDir()
			script := "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\nif [ \"$1\" = --output ]; then cp -- " + Q(path) + " \"$2\"; exit; fi\nshift\ndone\nexit 1\n"
			if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			image := "example.test/webscan-agent@sha256:" + strings.Repeat("b", 64)
			inspected := 0
			loaded := 0
			r := testRemoteCommand(t, func(cmd string) (string, bool) {
				if strings.Contains(cmd, "docker load --input") {
					loaded++
					return "Loaded image ID: sha256:untrusted-output\n", mode == "load-failed"
				}
				inspected++
				id := config
				if mode == "oci-manifest" || mode == "resume-cache" {
					id = manifest
				}
				if mode == "wrong-image" {
					id = "sha256:" + strings.Repeat("a", 64)
				}
				if strings.HasSuffix(cmd, Q(id)) || mode == "repository-digest" && strings.HasSuffix(cmd, Q(image)) {
					b, _ := json.Marshal([]any{common.Map{"Id": id, "RepoDigests": []string{image}}})
					return string(b), false
				}
				return "", true
			})
			d := &Deploy{Docker: &Docker{Dir: bin, Host: "unused"}, O: Options{Resume: mode == "resume-cache"}}
			ref, err := d.TransferImage(context.Background(), r, image)
			if mode == "load-failed" || mode == "wrong-image" {
				if err == nil || ref != "" {
					t.Fatal("failed import or wrong identity accepted", ref, err)
				}
				if mode == "load-failed" && inspected != 0 {
					t.Fatal("failed import accepted cached image fallback")
				}
				return
			}
			want := config
			if mode == "oci-manifest" || mode == "resume-cache" {
				want = manifest
			} else if mode == "repository-digest" {
				want = image
			}
			if err != nil || ref != want {
				t.Fatal(mode, ref, err)
			}
			if mode == "resume-cache" && loaded != 0 {
				t.Fatal("verified resume cache retransmitted or reloaded")
			}
		})
	}
}
