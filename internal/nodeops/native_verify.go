package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
)

// verifyNative is still private to the lifecycle under construction. It proves
// local service identity and resource enforcement only; the coordinator must
// additionally verify the collector's mTLS/configuration/readiness evidence.
func (a *nativeActivation) verifyNative(ctx context.Context, r Request) (Outcome, error) {
	return a.verifyNativeWithResources(ctx, r, nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"})
}

func (a *nativeActivation) verifyNativeWithResources(ctx context.Context, r Request, fs nativeResources) (Outcome, error) {
	var out Outcome
	if a.runtime == nil || a.backup == nil || r.Validate() != nil || r.Operation != "apply" || r.Phase != "verify" || r.Spec.Mode != "native" {
		return out, errors.New("invalid-native-verification")
	}
	ctx, release, err := acquireServiceOperation(ctx, a.runtime.root)
	if err != nil {
		return out, err
	}
	defer release()
	activation := r
	activation.Phase = "activate"
	p, err := a.plan(ctx, activation)
	if err != nil {
		return out, err
	}
	intent, err := readPrivate(a.intentPath(r), MaxRequestBytes)
	want, marshalErr := json.Marshal(p.intent)
	if err != nil || marshalErr != nil || !bytes.Equal(intent, want) {
		return out, errors.New("native-activation-intent-not-proven")
	}
	if err := a.confirm(ctx, p); err != nil {
		return out, err
	}
	status, err := a.host.native(ctx, p.target)
	if err != nil {
		return out, err
	}
	proof, err := fs.inspect(ctx, a.host, status, p.target, p.material.Settings.Resources)
	if err != nil {
		return out, err
	}
	if err := a.confirm(ctx, p); err != nil {
		return out, err
	}
	last, err := a.host.native(ctx, p.target)
	if err != nil || last.MainPID != proof.PID {
		return out, errors.New("process-changed-during-verification")
	}
	out.Checks = append([]Check{{ID: "native-service", Status: "passed", Code: "running-service-verified"}}, proof.checks()...)
	return out, nil
}
