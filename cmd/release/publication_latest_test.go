package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/common"
	"webscan/internal/controlplane"
	"webscan/internal/deploy"
)

type publicationFixtureRegistry struct {
	receipt     imageBuildReceipt
	prefix      string
	remote      map[string]string
	ids         map[string]string
	tagged      map[string]string
	calls       []string
	lookupError error
}

func (f *publicationFixtureRegistry) Close() { f.calls = append(f.calls, "close") }

func (f *publicationFixtureRegistry) Lookup(_ context.Context, ref string) (string, bool, error) {
	f.calls = append(f.calls, "lookup "+ref)
	if f.lookupError != nil {
		return "", false, f.lookupError
	}
	image, ok := f.remote[ref]
	return image, ok, nil
}

func (f *publicationFixtureRegistry) Exec(_ context.Context, _ io.Reader, args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	ref := args[len(args)-1]
	role := "agent"
	if strings.Contains(ref, "webscan-central") {
		role = "central"
	}
	switch args[0] {
	case "image":
		id := f.receipt.Images[role]
		if other, ok := f.ids[ref]; ok {
			id = other
		}
		return []byte(id + "/" + f.receipt.Build.Release + "/" + f.receipt.Build.Commit + "/" + f.receipt.Build.Source), nil
	case "pull":
		return nil, nil
	case "tag":
		f.tagged[ref] = args[1]
		return nil, nil
	case "push":
		if strings.HasSuffix(ref, ":latest") {
			f.remote[ref] = f.tagged[ref]
		} else {
			f.remote[ref] = f.prefix + "/webscan-" + role + "@sha256:" + strings.Repeat(map[string]string{"central": "c", "agent": "d"}[role], 64)
		}
		return nil, nil
	default:
		return nil, errors.New("unexpected_fixture_command")
	}
}

func publicationFixture(t *testing.T) (publicationOptions, *deploy.Config, publicationChecks, *publicationFixtureRegistry, publicationRegistryFactory) {
	t.Helper()
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := os.Mkdir("config", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("config/base-images.lock", []byte("RUNTIME_IMAGE=fixture@sha256:"+strings.Repeat("e", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "release")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	b := buildRecord{Release: "v3.0.4", Commit: strings.Repeat("a", 40), Source: strings.Repeat("b", 64)}
	write := func(path string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "build-info.json"), b)
	for _, name := range releaseArtifacts[:3] {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeBuildReceipt(root, map[string]string{"central": "sha256:" + strings.Repeat("1", 64), "agent": "sha256:" + strings.Repeat("2", 64)}); err != nil {
		t.Fatal(err)
	}
	r, err := readBuildReceipt(root, b.Release)
	if err != nil {
		t.Fatal(err)
	}
	o := publicationOptions{Action: "stage", Root: root, Version: b.Release,
		Verification: filepath.Join(dir, "verification.json"), Manifest: filepath.Join(dir, "manifest.json"),
		Signature: filepath.Join(dir, "manifest.sig"), PublicKey: filepath.Join(dir, "signing.pub"), ProductionVerification: filepath.Join(dir, "production.json")}
	evidence := filepath.Join(dir, "gate.log")
	if err = os.WriteFile(evidence, []byte("synthetic gate fixture; not acceptance evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	hash, _ := fileSHA(evidence)
	v := verificationRecord{Release: b.Release, Commit: b.Commit, Source: b.Source}
	if err = json.Unmarshal([]byte(`{"gates":{}}`), &v); err != nil {
		t.Fatal(err)
	}
	required, err := requiredFormalGates(b.Release)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range required {
		v.Gates[name] = struct {
			Passed   bool   `json:"passed"`
			Evidence string `json:"evidence"`
			SHA256   string `json:"sha256"`
		}{true, evidence, hash}
	}
	write(o.Verification, v)
	prefix := "docker.io/example"
	m := controlplane.ReleaseManifest{Format: 1, Release: b.Release, Platform: "linux/amd64", Protocol: 1,
		Image:  prefix + "/webscan-agent:" + b.Release + "@sha256:" + strings.Repeat("d", 64),
		Helper: controlplane.ReleaseArtifact{SHA256: r.Artifacts["webscan"], Bytes: uint64(len("webscan"))},
		Native: controlplane.ReleaseArtifact{SHA256: r.Artifacts["agent-native.tar.gz"], Bytes: uint64(len("agent-native.tar.gz"))}}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	for path, data := range map[string][]byte{o.Manifest: raw, o.Signature: ed25519.Sign(priv, raw), o.PublicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	clear(priv)
	if _, err := checkSignedArtifacts(root, o.Manifest, o.Signature, o.PublicKey, o.Version); err != nil {
		t.Fatalf("signed fixture invalid: %v", err)
	}
	f := &publicationFixtureRegistry{receipt: r, prefix: prefix, remote: map[string]string{}, ids: map[string]string{}, tagged: map[string]string{}}
	checks := publicationChecks{Source: func(context.Context, buildRecord) error { f.calls = append(f.calls, "source"); return nil },
		Verification: checkVerification, Signed: checkSignedArtifacts}
	factory := func(context.Context, *deploy.Config) (publicationRegistry, error) {
		f.calls = append(f.calls, "factory")
		return f, nil
	}
	return o, &deploy.Config{Raw: common.Map{"registry": common.Map{"prefix": prefix}}}, checks, f, factory
}

func assertNoRegistryMutation(t *testing.T, calls []string) {
	t.Helper()
	for _, call := range calls {
		if strings.HasPrefix(call, "tag ") || strings.HasPrefix(call, "push ") {
			t.Fatalf("unexpected registry mutation: %v", calls)
		}
	}
}

func assertNoLatestMutation(t *testing.T, calls []string) {
	t.Helper()
	for _, call := range calls {
		if (strings.HasPrefix(call, "tag ") || strings.HasPrefix(call, "push ")) && strings.Contains(call, ":latest") {
			t.Fatalf("unexpected latest mutation: %v", calls)
		}
	}
}

func TestPublicationStageVersionedAndExplicitLatestPromotion(t *testing.T) {
	o, c, checks, f, factory := publicationFixture(t)
	if err := runPublication(context.Background(), c, o, checks, factory); err != nil {
		t.Fatal(err)
	}
	assertNoLatestMutation(t, f.calls)
	firstPush := -1
	for i, call := range f.calls {
		if strings.HasPrefix(call, "push ") {
			firstPush = i
			break
		}
	}
	if firstPush < 0 || !strings.Contains(strings.Join(f.calls[:firstPush], "\n"), "lookup "+publicationTarget(f.prefix, "agent", o.Version)) {
		t.Fatalf("both roles must be checked before first push: %v", f.calls)
	}
	f.calls = nil
	o.Action = "publish-versioned"
	if err := runPublication(context.Background(), c, o, checks, factory); err != nil {
		t.Fatal(err)
	}
	assertNoRegistryMutation(t, f.calls)
	var report map[string]json.RawMessage
	if err := readReleaseJSON(filepath.Join(o.Root, "release.json"), &report); err != nil || string(report["latest"]) != "{}" {
		t.Fatalf("versioned publication reported latest: %s %v", report["latest"], err)
	}
	o.Action = "promote-latest"
	f.calls = nil
	if runPublication(context.Background(), c, o, checks, factory) == nil {
		t.Fatal("missing production acceptance allowed latest")
	}
	assertNoRegistryMutation(t, f.calls)
	s, err := readStagedPublication(o.Root, f.prefix, f.receipt.Build)
	if err != nil {
		t.Fatal(err)
	}
	if err = common.AtomicJSON(o.ProductionVerification, productionPublicationAcceptance{Release: s.Release, Commit: s.Commit, Source: s.Source, Images: s.Images, Accepted: true}); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err = runPublication(context.Background(), c, o, checks, factory); err != nil {
		t.Fatal(err)
	}
	for _, role := range publicationRoles {
		if f.remote[publicationTarget(f.prefix, role, "latest")] != s.Images[role] {
			t.Fatal("latest is not the accepted pinned image")
		}
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "tag ") && !strings.Contains(call, "@sha256:") {
			t.Fatalf("latest uses a mutable local tag: %s", call)
		}
	}
}

func TestPublicationFailureNeverWritesLatest(t *testing.T) {
	for _, failure := range []string{"source", "gate", "missing-signature", "invalid-signature", "remote-central", "remote-agent", "lookup", "production-image"} {
		t.Run(failure, func(t *testing.T) {
			o, c, checks, f, factory := publicationFixture(t)
			if err := runPublication(context.Background(), c, o, checks, factory); err != nil {
				t.Fatal(err)
			}
			s, err := readStagedPublication(o.Root, f.prefix, f.receipt.Build)
			if err != nil {
				t.Fatal(err)
			}
			accepted := productionPublicationAcceptance{Release: s.Release, Commit: s.Commit, Source: s.Source, Images: s.Images, Accepted: true}
			o.Action = "promote-latest"
			switch failure {
			case "source":
				checks.Source = func(context.Context, buildRecord) error { return errPublicationGate }
			case "gate":
				var v verificationRecord
				if err := readReleaseJSON(o.Verification, &v); err != nil {
					t.Fatal(err)
				}
				delete(v.Gates, "full-backup-restore")
				if err := common.AtomicJSON(o.Verification, v); err != nil {
					t.Fatal(err)
				}
			case "missing-signature":
				o.Signature = ""
			case "invalid-signature":
				if err := os.WriteFile(o.Signature, make([]byte, ed25519.SignatureSize), 0600); err != nil {
					t.Fatal(err)
				}
			case "remote-central", "remote-agent":
				role := strings.TrimPrefix(failure, "remote-")
				f.remote[publicationTarget(f.prefix, role, o.Version)] = f.prefix + "/webscan-" + role + "@sha256:" + strings.Repeat("f", 64)
			case "lookup":
				f.lookupError = errors.New("registry unavailable")
			case "production-image":
				accepted.Images = map[string]string{"central": s.Images["agent"], "agent": s.Images["agent"]}
			}
			if err := common.AtomicJSON(o.ProductionVerification, accepted); err != nil {
				t.Fatal(err)
			}
			f.calls = nil
			if runPublication(context.Background(), c, o, checks, factory) == nil {
				t.Fatal("failure accepted")
			}
			assertNoRegistryMutation(t, f.calls)
		})
	}
}

func TestPublicationStageRejectsExistingVersionBeforeAnyPush(t *testing.T) {
	for _, role := range publicationRoles {
		t.Run(role, func(t *testing.T) {
			o, c, checks, f, factory := publicationFixture(t)
			fixed := f.prefix + "/webscan-" + role + "@sha256:" + strings.Repeat("f", 64)
			f.remote[publicationTarget(f.prefix, role, o.Version)] = fixed
			f.ids[fixed] = "sha256:" + strings.Repeat("9", 64)
			if runPublication(context.Background(), c, o, checks, factory) == nil {
				t.Fatal("existing different image accepted")
			}
			assertNoRegistryMutation(t, f.calls)
		})
	}
}

func TestPublicationStageReusesExistingMatchingVersion(t *testing.T) {
	o, c, checks, f, factory := publicationFixture(t)
	if err := runPublication(context.Background(), c, o, checks, factory); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := runPublication(context.Background(), c, o, checks, factory); err != nil {
		t.Fatal(err)
	}
	assertNoRegistryMutation(t, f.calls)
}

func TestPublicationUnsignedBootstrapAndLegacyPublishCompatibility(t *testing.T) {
	t.Run("unsigned-bootstrap", func(t *testing.T) {
		o, c, checks, f, factory := publicationFixture(t)
		o.Manifest, o.Signature, o.PublicKey = "", "", ""
		if err := runPublication(context.Background(), c, o, checks, factory); err != nil {
			t.Fatal(err)
		}
		assertNoLatestMutation(t, f.calls)
	})
	t.Run("legacy-publish-updates-latest", func(t *testing.T) {
		o, c, checks, f, factory := publicationFixture(t)
		o.Action = "publish"
		if err := runPublication(context.Background(), c, o, checks, factory); err != nil {
			t.Fatal(err)
		}
		for _, role := range publicationRoles {
			if f.remote[publicationTarget(f.prefix, role, "latest")] == "" {
				t.Fatal("legacy publish silently stopped updating latest")
			}
		}
	})
}

func TestPublicationStageRetainsPreviouslyRecordedDigest(t *testing.T) {
	o, c, checks, f, factory := publicationFixture(t)
	if err := runPublication(context.Background(), c, o, checks, factory); err != nil {
		t.Fatal(err)
	}
	// Even an image with the same config and OCI labels cannot silently replace
	// a manifest digest already recorded by this build's bootstrap operation.
	f.remote[publicationTarget(f.prefix, "central", o.Version)] = f.prefix + "/webscan-central@sha256:" + strings.Repeat("f", 64)
	f.calls = nil
	if runPublication(context.Background(), c, o, checks, factory) == nil {
		t.Fatal("stage replaced its previously recorded digest")
	}
	assertNoRegistryMutation(t, f.calls)
}

func TestPublicationRegistryLookupUsesRemoteDescriptorAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
for ref do :; done
case "$ref" in
  */missing:v3.0.4) echo 'ERROR: manifest unknown' >&2; exit 1 ;;
  */denied:v3.0.4) echo 'ERROR: denied: manifest unknown' >&2; exit 1 ;;
  */offline:v3.0.4) echo 'ERROR: TLS handshake timeout' >&2; exit 1 ;;
  */invalid:v3.0.4) echo '{"digest":"not-a-digest"}'; exit 0 ;;
esac
echo '{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}'
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	d := &dockerPublicationRegistry{&deploy.Docker{Host: "fixture-only", Dir: dir}}
	for _, tc := range []struct {
		name   string
		exists bool
		fails  bool
	}{
		{"existing", true, false}, {"missing", false, false}, {"denied", false, true},
		{"offline", false, true}, {"invalid", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := "docker.io/example/" + tc.name + ":v3.0.4"
			locked, exists, err := d.Lookup(context.Background(), ref)
			if exists != tc.exists || (err != nil) != tc.fails {
				t.Fatalf("unexpected lookup state: %q %v %v", locked, exists, err)
			}
			if exists && locked != "docker.io/example/existing@sha256:"+strings.Repeat("c", 64) {
				t.Fatal("remote descriptor not used")
			}
		})
	}
}
