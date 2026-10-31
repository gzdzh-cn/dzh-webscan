package nodepki

import (
	"context"
	"os"
	"path/filepath"
)

// WithMaintenanceSnapshot freezes the local issuer, collector revocation floor
// and collector identity in the same order as maintenance/activation. capture
// must not call a PKI writer or re-enter these locks. Callers acquire their
// database checkpoint AFTER these locks: IssueRegistered commits its database
// receipt while holding the issuer lock. No keys are returned by this API.
func WithMaintenanceSnapshot(ctx context.Context, authority, floor, identity string, capture func() error) error {
	if capture == nil || authority == floor || authority == identity || floor == identity {
		return errStorage
	}
	var locks []*os.File
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Close()
		}
	}()
	directories := []string{authority}
	// Creation of this fixed child takes the original authority lock. After
	// holding that parent lock the directory cannot appear during capture.
	// Signers lock issuer -> floor -> identity, so lock a present successor
	// before the floor too. An invalid child is an error, never omitted.
	for index := 0; index < len(directories); index++ {
		directory := directories[index]
		if !filepath.IsAbs(directory) || secureDirectory(directory) != nil {
			return errStorage
		}
		lock, err := authorityLock(ctx, directory)
		if err != nil {
			return err
		}
		locks = append(locks, lock)
		if index == 0 {
			successor := SuccessorAuthorityDirectory(authority)
			if _, err := os.Lstat(successor); err == nil {
				if successor == floor || successor == identity {
					return errStorage
				}
				directories = append(directories, successor)
			} else if !os.IsNotExist(err) {
				return errStorage
			}
			directories = append(directories, floor, identity)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return capture()
}
