//go:build !linux && !darwin

package nodeops

import "errors"

func renameNoReplace(from, to string) error {
	return errors.New("atomic-publication-platform-unsupported")
}
