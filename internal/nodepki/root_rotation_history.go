package nodepki

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Authenticated immutable history is a durable floor too. Replacing roots.json
// with an older valid snapshot must not undo retirement on the next restart.
// Exceeding the bound fails closed; pruning requires a separate checkpoint
// procedure and is never inferred from filenames or wall-clock ordering.
const maxRootHistoryEntries = 8192

func validateRootHistory(anchor []byte, s RootSetSnapshot) error {
	if s.Format != 1 {
		return ErrRootRotation
	}
	at := s.Dual.IssuedAt
	if s.Final != nil && s.Final.IssuedAt.After(at) {
		at = s.Final.IssuedAt
	}
	if VerifyRootAuthorization(anchor, s.Dual, nil, at, false) != nil || s.Final != nil && VerifyRootAuthorization(anchor, *s.Final, &s.Dual, at, false) != nil {
		return ErrRootRotation
	}
	validate := func(ca, raw []byte) error {
		root, err := parseCertificate(ca)
		if err != nil {
			return ErrRootRotation
		}
		list, err := parseCRL(raw, root)
		if err != nil {
			return ErrRootRotation
		}
		_, err = NewTrust(ca, raw, list.ThisUpdate)
		return err
	}
	if validate(s.Dual.NewCA, s.NewCRL) != nil || validate(anchor, s.OldCRL) != nil {
		return ErrRootRotation
	}
	return nil
}

func rootHistoryAdvance(anchor []byte, previous, next RootSetSnapshot) error {
	if validateRootHistory(anchor, previous) != nil || validateRootHistory(anchor, next) != nil || RootAuthorizationSHA256(previous.Dual) != RootAuthorizationSHA256(next.Dual) || previous.Final != nil && (next.Final == nil || RootAuthorizationSHA256(*previous.Final) != RootAuthorizationSHA256(*next.Final)) {
		return ErrRootRotation
	}
	advance := func(ca, before, after []byte) error {
		root, err := parseCertificate(ca)
		if err != nil {
			return ErrRootRotation
		}
		list, err := parseCRL(after, root)
		if err != nil {
			return ErrRootRotation
		}
		return ValidateCRLAdvance(ca, before, after, list.ThisUpdate)
	}
	if advance(next.Dual.NewCA, previous.NewCRL, next.NewCRL) != nil {
		return ErrRootRotation
	}
	// Preserve the old issuer's history after retirement as well. It can no
	// longer authorize TLS, but cannot be rewritten into an unrevoked audit.
	if !bytes.Equal(previous.OldCRL, next.OldCRL) && advance(anchor, previous.OldCRL, next.OldCRL) != nil {
		return ErrRootRotation
	}
	return nil
}

func latestRootHistory(rotation string, anchor []byte, current RootSetSnapshot, raw []byte) (RootSetSnapshot, []byte, error) {
	empty := RootSetSnapshot{}
	history := filepath.Join(rotation, "history")
	if secureDirectory(history) != nil || validateRootHistory(anchor, current) != nil {
		return empty, nil, ErrRootRotation
	}
	dir, err := os.Open(history)
	if err != nil {
		return empty, nil, ErrRootRotation
	}
	defer dir.Close()
	names, err := dir.Readdirnames(maxRootHistoryEntries + 1)
	if err != nil && err != io.EOF || len(names) == 0 || len(names) > maxRootHistoryEntries {
		return empty, nil, ErrRootRotation
	}
	present := false
	best, bestRaw := current, raw
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") || !recoverySHA(strings.TrimSuffix(name, ".json")) {
			return empty, nil, ErrRootRotation
		}
		entry, err := readIdentityFile(filepath.Join(history, name), MaxRootSetBytes, true)
		if err != nil || publicSHA(entry)+".json" != name {
			return empty, nil, ErrRootRotation
		}
		s, err := ParseRootSetSnapshot(entry)
		if err != nil || validateRootHistory(anchor, s) != nil {
			return empty, nil, ErrRootRotation
		}
		if bytes.Equal(entry, raw) {
			present = true
		}
		if rootHistoryAdvance(anchor, best, s) == nil {
			best, bestRaw = s, entry
		} else if rootHistoryAdvance(anchor, s, best) != nil {
			return empty, nil, ErrRootRotation
		}
	}
	if !present {
		return empty, nil, ErrRootRotation
	}
	return best, bestRaw, nil
}
