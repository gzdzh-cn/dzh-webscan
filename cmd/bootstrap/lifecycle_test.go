package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractToolCleansBeforeReturningAndOnCancelledCopy(t *testing.T) {
	for _, cancelCopy := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "cancelled"}[cancelCopy], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dir := t.TempDir()
			calls := []string{}
			fake := func(c context.Context, _ io.Reader, args ...string) ([]byte, error) {
				calls = append(calls, strings.Join(args, " "))
				switch args[0] {
				case "create":
					if !strings.Contains(strings.Join(args, " "), "--pull never --label io.webscan.bootstrap=true") {
						t.Fatal("unowned or implicit-pull container")
					}
				case "cp":
					if cancelCopy {
						cancel()
						return nil, context.Canceled
					}
					return nil, os.WriteFile(args[2], []byte("fixture-binary"), 0600)
				case "rm":
					if c.Err() != nil {
						t.Fatal("cleanup inherited cancelled context")
					}
				default:
					t.Fatal(args)
				}
				return nil, nil
			}
			_, err := extractTool(ctx, fake, dir, "test/central@sha256:locked")
			if cancelCopy && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if !cancelCopy && err != nil {
				t.Fatal(err)
			}
			if len(calls) != 3 || !strings.HasPrefix(calls[2], "rm -f webscan-bootstrap-") {
				t.Fatal("container survived extraction", calls)
			}
		})
	}
}

func TestExtractedToolVersionMustMatchBootstrap(t *testing.T) {
	for _, version := range []string{Release, "older-release"} {
		path := filepath.Join(t.TempDir(), "webscan")
		os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' '"+version+"'\n"), 0700)
		err := validateToolVersion(context.Background(), path)
		if (err == nil) != (version == Release) {
			t.Fatal("incorrect tool version validation", err)
		}
	}
}

func TestStaleCleanupOnlyQueriesOwnedCreatedContainers(t *testing.T) {
	calls := []string{}
	fake := func(_ context.Context, _ io.Reader, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "ps" {
			if strings.Join(args, " ") != "ps -aq --filter label=io.webscan.bootstrap=true --filter status=created" {
				t.Fatal("cleanup is too broad", args)
			}
			return []byte("owned-created-id\n"), nil
		}
		if strings.Join(args, " ") != "rm owned-created-id" {
			t.Fatal("unexpected removal", args)
		}
		return nil, nil
	}
	if err := cleanStaleBootstrap(context.Background(), fake); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatal(calls)
	}
}

func TestDeploymentChildReceivesCancellationAndFinishesCleanup(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "tool")
	marker := filepath.Join(dir, "cleaned")
	started := filepath.Join(dir, "started")
	os.WriteFile(script, []byte("#!/bin/sh\ntrap 'touch \"$WEBSCAN_TEST_CLEANED\"; exit 0' TERM\nprintf ready > \"$WEBSCAN_TEST_STARTED\"\nwhile :; do sleep 0.05; done\n"), 0700)
	t.Setenv("WEBSCAN_TEST_CLEANED", marker)
	t.Setenv("WEBSCAN_TEST_STARTED", started)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runDeploymentTool(ctx, script, nil) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("child was killed without its cleanup", err)
	}
}
