package nodeops

import (
	"context"
	"testing"
)

func TestNativeDeletedExecutableIsOwnedButNeverHealthy(t *testing.T) {
	a := nativeActivationFixture(t, false)
	ctx := context.Background()
	if err := a.activation.run(ctx, a.request); err != nil {
		t.Fatal(err)
	}
	p, err := a.activation.plan(ctx, a.request)
	if err != nil {
		t.Fatal(err)
	}
	a.activation.host.processExecutable = func(int) (string, error) { return a.program + " (deleted)", nil }
	if _, err := a.activation.host.native(ctx, p.target); err != nil {
		t.Fatal("damaged writer cannot be identified for recovery", err)
	}
	if err := a.activation.confirm(ctx, p); err == nil {
		t.Fatal("unlinked target passed activation")
	}
	starts := a.starts
	if err := a.activation.run(ctx, a.request); err == nil || a.starts != starts {
		t.Fatal("replay accepted/restarted damaged writer", err)
	}
	// Recovery must still stop that exact writer, export its current pending
	// events, and restore the intact original executable/configuration.
	a.activation.host.processExecutable = func(int) (string, error) {
		if a.program == p.target.Program {
			return a.program + " (deleted)", nil
		}
		return a.program, nil
	}
	r := a.request
	r.Phase = "restore"
	if err := a.activation.restore(ctx, r); err != nil {
		t.Fatal("damaged target could not be recovered", err)
	}
}

func TestNativeDeletedOriginalCannotPassRollbackVerification(t *testing.T) {
	a := nativeActivationFixture(t, false)
	r := a.request
	r.Phase = "restore"
	if err := a.activation.restore(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	p, err := a.activation.restorePlan(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	a.activation.host.processExecutable = func(int) (string, error) { return a.program + " (deleted)", nil }
	if _, _, _, err := a.activation.restoreState(context.Background(), p); err != nil {
		t.Fatal("damaged original ownership lost", err)
	}
	if err := a.activation.confirmRestored(context.Background(), p); err == nil {
		t.Fatal("unlinked original passed rollback verification")
	}
}
