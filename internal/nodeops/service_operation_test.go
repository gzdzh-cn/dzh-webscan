package nodeops

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestServiceOperationChildKeepsLockAfterParentExit(t *testing.T) {
	if root := os.Getenv("WEBSCAN_V3_OPERATION_CHILD"); root != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ctx, _, err := acquireServiceOperation(ctx, root)
		if err != nil {
			os.Exit(21)
		}
		// Cancel only after the real child has started. A fixed startup timeout
		// races Rosetta/cold exec and can expire before the shell writes entered.
		go func() {
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				if _, e := os.Stat(filepath.Join(root, "entered")); e == nil {
					cancel()
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
			}
		}()
		_, err = executeServiceCommand(ctx, "/bin/sh", []string{"-c", `touch "$1"; attempts=0; while [ ! -f "$2" ]; do attempts=$((attempts+1)); if [ "$attempts" -ge 1000 ]; then exit 77; fi; sleep 0.02; done; touch "$3"`, "worker", filepath.Join(root, "entered"), filepath.Join(root, "release"), filepath.Join(root, "finished")}, true)
		if err == nil {
			os.Exit(22)
		}
		os.Exit(19)
	}
	root := testRoot(t)
	// Keep the child alive until the parent has actually checked the lock;
	// release it on test failure too, rather than leaving an orphaned shell.
	releaseChild := func() { _ = os.WriteFile(filepath.Join(root, "release"), []byte("release"), 0600) }
	t.Cleanup(releaseChild)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServiceOperationChildKeepsLockAfterParentExit$")
	cmd.Env = append(os.Environ(), "WEBSCAN_V3_OPERATION_CHILD="+root)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 19 {
		t.Fatal("helper did not exit after response timeout", err)
	}
	if _, err := os.Stat(filepath.Join(root, "entered")); err != nil {
		t.Fatal("child did not begin", err)
	}
	if _, release, err := acquireServiceOperation(context.Background(), root); err == nil {
		release()
		t.Fatal("parent exit unlocked still-running mutation")
	}
	releaseChild()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, release, err := acquireServiceOperation(context.Background(), root); err == nil {
			release()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("finished child did not release operation lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(root, "finished")); err != nil {
		t.Fatal("mutating child was killed on caller timeout", err)
	}
}
func TestServiceMutationRequiresOperationLock(t *testing.T) {
	if _, err := executeServiceCommand(context.Background(), "/bin/sh", []string{"-c", "exit 0"}, true); err == nil {
		t.Fatal("mutation without persistent operation scope")
	}
	root := testRoot(t)
	ctx, release, err := acquireServiceOperation(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := executeServiceCommand(ctx, "/bin/sh", []string{"-c", "exit 0"}, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := acquireServiceOperation(ctx, testRoot(t)); err == nil {
		t.Fatal("lock reused for different host scope")
	}
}
