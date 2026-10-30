package nodeops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeVerificationRequiresActivatedIdentityAndActualLimits(t *testing.T) {
	a := nativeActivationFixture(t, false)
	ctx := context.Background()
	r := a.request
	r.Phase = "verify"
	f := resourceFixture(t, 2)
	f.resources.CPUs = 1
	writeResourceFixture(t, f.cpu, "100000 100000\n")
	f.properties = strings.ReplaceAll(f.properties, "1s 250ms", "1s")
	if _, err := a.activation.verifyNativeWithResources(ctx, r, f.fs); err == nil {
		t.Fatal("unactivated service accepted")
	}
	if err := a.activation.run(ctx, a.request); err != nil {
		t.Fatal(err)
	}
	base := a.activation.host.command
	a.activation.host.command = func(ctx context.Context, program string, args ...string) (string, error) {
		if program == "systemctl" && len(args) == 3 && strings.Contains(args[2], "ControlGroup") {
			return f.properties, nil
		}
		return base(ctx, program, args...)
	}
	// The service fixture has PID 123, the kernel fixture has the same identity.
	out, err := a.activation.verifyNativeWithResources(ctx, r, f.fs)
	if err != nil || len(out.Checks) != 4 {
		t.Fatal("native verification failed", out, err)
	}
	writeResourceFixture(t, f.memory, "max\n")
	if _, err := a.activation.verifyNativeWithResources(ctx, r, f.fs); err == nil {
		t.Fatal("successful unit start hid missing kernel limit")
	}
	writeResourceFixture(t, f.memory, "268435456\n")
	if err := os.WriteFile(a.activation.intentPath(r), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.activation.verifyNativeWithResources(ctx, r, f.fs); err == nil {
		t.Fatal("changed activation intent accepted")
	}
}

func TestNativeVerificationDoesNotPublishFilesOrRestartService(t *testing.T) {
	a := nativeActivationFixture(t, true)
	ctx := context.Background()
	if err := a.activation.run(ctx, a.request); err != nil {
		t.Fatal(err)
	}
	r := a.request
	r.Phase = "verify"
	f := resourceFixture(t, 2)
	writeResourceFixture(t, f.cpu, "100000 100000\n")
	f.properties = strings.ReplaceAll(f.properties, "1s 250ms", "1s")
	base := a.activation.host.command
	before := len(a.machine.calls)
	a.activation.host.command = func(ctx context.Context, p string, args ...string) (string, error) {
		if p == "systemctl" && len(args) == 3 && strings.Contains(args[2], "ControlGroup") {
			return f.properties, nil
		}
		return base(ctx, p, args...)
	}
	r.Epoch++
	for i := 0; i < 2; i++ {
		if _, err := a.activation.verifyNativeWithResources(ctx, r, f.fs); err != nil {
			t.Fatal(err)
		}
	}
	for _, call := range a.machine.calls[before:] {
		if !strings.Contains(call, "systemctl show ") {
			t.Fatal("verification mutated service", call)
		}
	}
	if _, err := os.Stat(filepath.Join(a.activation.backup.directory(r), "finalized.json")); !os.IsNotExist(err) {
		t.Fatal("local verification finalized installation")
	}
}
