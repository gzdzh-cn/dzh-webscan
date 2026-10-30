package nodeops

import (
	"context"
	"errors"
	"path/filepath"
	"time"
)

func (n *nativeLifecycle) installationEvidence(r Request) (*InstallationEvidence, error) {
	return withRecovery(n.forRequest(r)).captureEvidence(r)
}

func (d *dockerLifecycle) installationEvidence(r Request) (*InstallationEvidence, error) {
	return withRecovery(d.forRequest(r)).captureEvidence(r)
}

func (q *recoveryLifecycle) captureEvidence(r Request) (*InstallationEvidence, error) {
	if r.Validate() != nil || r.Recovery != nil || r.Phase != "finalize" || !r.Spec.configurationValid() || q.runtime == nil || q.backup == nil {
		return nil, errors.New("installation-evidence-unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx, release, err := acquireServiceOperation(ctx, q.runtime.root)
	if err != nil {
		return nil, err
	}
	defer release()
	r.Operation = "apply" // Immutable legacy member readers use the capture envelope.
	// sourceEvidence authenticates the capture, snapshot, activation and exact
	// target pointer. It reads immutable history, not current release material.
	pointer, err := q.sourceEvidence(ctx, r)
	if err != nil {
		return nil, err
	}
	capture, err := readPrivate(filepath.Join(q.backup.directory(r), "capture/intent.json"), 4<<20)
	if err != nil {
		return nil, err
	}
	return &InstallationEvidence{CaptureSHA256: sha(capture), ActiveSHA256: sha(pointer)}, nil
}
