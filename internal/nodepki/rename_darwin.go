package nodepki

import "golang.org/x/sys/unix"

func identityRenameNoReplace(from, to string) error {
	return unix.RenamexNp(from, to, unix.RENAME_EXCL)
}
