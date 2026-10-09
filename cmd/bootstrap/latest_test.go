package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
	"webscan/internal/deploy"
)

func TestLatestAllowsNewToolWhilePinnedReferenceStaysStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webscan")
	os.WriteFile(path, []byte("#!/bin/sh\nprintf 'v2.0.99\\n'\n"), 0700)
	if err := validateToolVersionForImage(context.Background(), path, "test/central:latest"); err != nil {
		t.Fatal(err)
	}
	if err := validateToolVersionForImage(context.Background(), path, "test/central:v2.0.99"); err == nil {
		t.Fatal("explicit release lost strict validation")
	}
	if err := validateToolVersionForImage(context.Background(), path, "test/central:latest@sha256:"+strings.Repeat("a", 64)); err == nil {
		t.Fatal("explicit digest lost strict validation")
	}
	os.WriteFile(path, []byte("#!/bin/sh\nprintf 'v3.0.0\\n'\n"), 0700)
	if err := validateToolVersionForImage(context.Background(), path, "test/central:latest"); err == nil {
		t.Fatal("incompatible major version accepted")
	}
}

func TestResumeAndRollbackPreferSavedToolImageOverMovedLatest(t *testing.T) {
	before := deploy.StateRoot
	deploy.StateRoot = t.TempDir()
	t.Cleanup(func() { deploy.StateRoot = before })
	latest := "docker.io/gzdzh/webscan-central:latest"
	locked := "gzdzh/webscan-central@sha256:" + strings.Repeat("a", 64)
	common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), common.Map{"target_release": "v2.0.19", "target_tool_image": locked})
	for _, flag := range []string{"--resume", "--rollback"} {
		if got := bootstrapImageForOperation(latest, []string{flag}); got != locked {
			t.Fatal("moved latest used for recovery", got)
		}
	}
	if got := bootstrapImageForOperation(latest, []string{"--upgrade"}); got != latest {
		t.Fatal("normal upgrade stopped following latest")
	}
	common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), common.Map{"target_release": "v2.0.18"})
	if got := bootstrapImageForOperation(latest, []string{"--resume"}); got != "docker.io/gzdzh/webscan-central:v2.0.18" {
		t.Fatal("legacy run did not select its original tool", got)
	}
}

func TestToolDigestSelectsRequestedRegistry(t *testing.T) {
	a := "private.example.test/team/central@sha256:" + strings.Repeat("a", 64)
	b := "gzdzh/webscan-central@sha256:" + strings.Repeat("b", 64)
	if got := matchingToolDigest("docker.io/gzdzh/webscan-central:latest", []string{a, b}); got != b {
		t.Fatal("wrong registry selected", got)
	}
}

func TestStaleLatestCannotRunNewBootstrapConfiguration(t *testing.T) {
	before := Release
	Release = "v2.0.21"
	t.Cleanup(func() { Release = before })
	file := filepath.Join(t.TempDir(), "webscan")
	for _, tc := range []struct {
		version string
		old     bool
	}{{"v2.0.20", true}, {"v2.0.21", false}, {"v2.0.22", false}, {"v2.1.0", false}} {
		os.WriteFile(file, []byte("#!/bin/sh\nprintf '"+tc.version+"\\n'\n"), 0700)
		if toolOlderThanBootstrap(context.Background(), file) != tc.old {
			t.Fatal(tc)
		}
	}
}

func TestOfficialDockerHubDigestAlias(t *testing.T) {
	digest := "gzdzh/webscan-central@sha256:" + strings.Repeat("a", 64)
	if matchingToolDigest("registry-1.docker.io/gzdzh/webscan-central:latest", []string{digest}) != digest {
		t.Fatal("official fallback digest not recognized")
	}
}
