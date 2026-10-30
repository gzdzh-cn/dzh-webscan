package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func releaseFixture() ReleaseManifest {
	return ReleaseManifest{Format: 1, Release: "v3.0.0", Platform: "linux/amd64", Protocol: 1,
		Helper: ReleaseArtifact{SHA256: strings.Repeat("b", 64), Bytes: 1024},
		Native: ReleaseArtifact{SHA256: strings.Repeat("a", 64), Bytes: 2048},
		Image:  "docker.io/gzdzh/webscan-agent@sha256:" + strings.Repeat("c", 64)}
}

func signedRelease(t *testing.T, m ReleaseManifest) *TrustedRelease {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	r, err := VerifyReleaseManifest(raw, ed25519.Sign(key, raw), pub)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSignedReleaseRejectsTamperingAndInvalidContracts(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(releaseFixture())
	sig := ed25519.Sign(key, raw)
	verified, err := VerifyReleaseManifest(raw, sig, pub)
	if err != nil || verified.SHA256() != digest(raw) {
		t.Fatal("valid release rejected", err)
	}
	for _, v := range []struct{ raw, sig, key []byte }{
		{raw, sig[:63], pub}, {raw, sig, pub[:31]}, {raw, nil, pub}, {nil, sig, pub},
		{bytes.Replace(raw, []byte("v3.0.0"), []byte("v3.0.1"), 1), sig, pub},
		{raw, bytes.Repeat([]byte{1}, 64), pub}, {bytes.Repeat([]byte("x"), 64<<10+1), sig, pub},
	} {
		if _, err := VerifyReleaseManifest(v.raw, v.sig, v.key); err == nil {
			t.Fatal("invalid signature accepted")
		}
	}
	changes := []func(*ReleaseManifest){
		func(m *ReleaseManifest) { m.Format = 2 }, func(m *ReleaseManifest) { m.Protocol = 2 },
		func(m *ReleaseManifest) { m.Platform = "linux/arm64" }, func(m *ReleaseManifest) { m.Release = "latest" },
		func(m *ReleaseManifest) { m.Helper.SHA256 = strings.Repeat("B", 64) }, func(m *ReleaseManifest) { m.Helper.Bytes = 0 },
		func(m *ReleaseManifest) { m.Helper.Bytes = 256<<20 + 1 }, func(m *ReleaseManifest) { m.Native.Bytes = 4<<30 + 1 },
		func(m *ReleaseManifest) { m.Native.SHA256 = "invalid" }, func(m *ReleaseManifest) { m.Image = "gzdzh/webscan-agent:latest" },
		func(m *ReleaseManifest) { m.Image = "x@sha256:" + strings.Repeat("z", 64) },
		func(m *ReleaseManifest) { m.Image = "x@sha256:" + strings.Repeat("c", 64) + ";id" },
		func(m *ReleaseManifest) { m.Image = "gzdzh/webscan-agent:v3.0.1@sha256:" + strings.Repeat("c", 64) },
	}
	for _, change := range changes {
		m := releaseFixture()
		change(&m)
		raw, _ := json.Marshal(m)
		if _, err := VerifyReleaseManifest(raw, ed25519.Sign(key, raw), pub); err == nil {
			t.Fatal("unsupported signed contract accepted", string(raw))
		}
	}
	for _, raw := range [][]byte{
		[]byte(`{"format":1,"format":1,` + string(raw[1:])),
		append(append([]byte{}, raw...), []byte(`{}`)...),
		[]byte(strings.Replace(string(raw), `"format":1`, `"command":"id","format":1`, 1)),
	} {
		if _, err := VerifyReleaseManifest(raw, ed25519.Sign(key, raw), pub); err == nil {
			t.Fatal("ambiguous manifest accepted")
		}
	}
}

func TestSignedReleaseAllowsVersionedDigestReference(t *testing.T) {
	m := releaseFixture()
	m.Image = strings.Replace(m.Image, "@", ":"+m.Release+"@", 1)
	r := signedRelease(t, m)
	if r.manifest.Image != m.Image {
		t.Fatal("versioned image was not preserved in signed release")
	}
}

func TestDeploymentManifestBindsHelperTargetAndMode(t *testing.T) {
	r := signedRelease(t, releaseFixture())
	j := DeploymentJob{Plan: DeploymentPlan{Request: DeploymentRequest{Release: "v3.0.0", SHA256: strings.Repeat("a", 64), ManifestSHA256: r.SHA256()}, Node: Node{Mode: "native"}}}
	if !r.matches(j) {
		t.Fatal("native plan rejected")
	}
	j.Plan.Node.Mode = "docker"
	if r.matches(j) {
		t.Fatal("native checksum accepted for image")
	}
	j.Plan.Request.SHA256 = strings.Repeat("c", 64)
	if !r.matches(j) {
		t.Fatal("immutable image digest rejected")
	}
	for _, change := range []func(*DeploymentJob){
		func(j *DeploymentJob) { j.Plan.Request.Release = "v3.0.1" },
		func(j *DeploymentJob) { j.Plan.Request.ManifestSHA256 = "" },
		func(j *DeploymentJob) { j.Plan.Request.ManifestSHA256 = strings.Repeat("f", 64) },
	} {
		bad := j
		change(&bad)
		if r.matches(bad) {
			t.Fatal("different or unbound release accepted")
		}
	}
	m := releaseFixture()
	m.Helper.SHA256 = strings.Repeat("d", 64)
	if signedRelease(t, m).matches(j) {
		t.Fatal("replaced helper accepted for existing plan")
	}
	if (&TrustedRelease{}).matches(j) || (*TrustedRelease)(nil).matches(j) {
		t.Fatal("unverified release accepted")
	}
}

func TestSignedReleaseBindsImageArchiveProvenance(t *testing.T) {
	m := releaseFixture()
	m.ImageArchive = &ReleaseArtifact{SHA256: strings.Repeat("d", 64), Bytes: 4096}
	m.ImageConfigSHA256 = strings.Repeat("e", 64)
	trusted := signedRelease(t, m)
	j := DeploymentJob{Plan: DeploymentPlan{Request: DeploymentRequest{Release: m.Release, SHA256: strings.Repeat("c", 64), ManifestSHA256: trusted.SHA256()}, Node: Node{Mode: "docker"}}}
	if !trusted.matches(j) {
		t.Fatal("signed archive plan rejected")
	}
	changed := m
	changed.ImageConfigSHA256 = strings.Repeat("f", 64)
	if signedRelease(t, changed).matches(j) {
		t.Fatal("substituted image config accepted")
	}
	changed = m
	changed.ImageArchive = &ReleaseArtifact{SHA256: strings.Repeat("f", 64), Bytes: 4096}
	if signedRelease(t, changed).matches(j) {
		t.Fatal("substituted archive accepted")
	}
	for _, change := range []func(*ReleaseManifest){
		func(m *ReleaseManifest) { m.ImageArchive = nil },
		func(m *ReleaseManifest) { m.ImageConfigSHA256 = "" },
		func(m *ReleaseManifest) { m.ImageConfigSHA256 = strings.Repeat("E", 64) },
		func(m *ReleaseManifest) { m.ImageArchive = &ReleaseArtifact{SHA256: strings.Repeat("d", 64), Bytes: 0} },
		func(m *ReleaseManifest) {
			m.ImageArchive = &ReleaseArtifact{SHA256: strings.Repeat("d", 64), Bytes: 4<<30 + 1}
		},
	} {
		bad := m
		change(&bad)
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(bad)
		if _, err := VerifyReleaseManifest(raw, ed25519.Sign(key, raw), pub); err == nil {
			t.Fatal("invalid archive contract accepted")
		}
	}
}
