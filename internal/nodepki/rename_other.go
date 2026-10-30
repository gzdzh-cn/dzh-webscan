//go:build !linux && !darwin

package nodepki

func identityRenameNoReplace(from, to string) error { return errStorage }
