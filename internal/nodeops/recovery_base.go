package nodeops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// A backup can fail after stopping the original but before publishing its
// snapshot. Restoration may then use the already durable capture, provided no
// activation intent exists. A missing/corrupt post-activation snapshot cannot
// take this branch. The current DB is never replaced in either case.
func (b *transitionBackup) recoveryBase(ctx context.Context, r Request) (bool, string, error) {
	if r.Validate() != nil || r.Operation != "apply" || r.Phase != "restore" {
		return false, "", errors.New("invalid-recovery-request")
	}
	intent, err := b.readIntent(ctx, r)
	if err != nil {
		return false, "", err
	}
	root := filepath.Join(b.directory(r), "snapshot")
	if _, err := os.Lstat(root); err == nil {
		snapshot, err := b.verify(ctx, r)
		if err != nil {
			return false, "", err
		}
		raw, err := readPrivate(filepath.Join(root, "receipt.json"), 16<<20)
		if err != nil {
			return false, "", err
		}
		return snapshot.Database != nil, sha(raw), nil
	} else if !os.IsNotExist(err) {
		return false, "", err
	}
	if _, err := os.Lstat(filepath.Join(b.directory(r), "activation", "intent.json")); !os.IsNotExist(err) {
		return false, "", errors.New("activated-snapshot-missing")
	}
	if intent.DatabasePresent == nil {
		return false, "", errors.New("original-database-presence-unknown")
	}
	return *intent.DatabasePresent, "", nil
}
