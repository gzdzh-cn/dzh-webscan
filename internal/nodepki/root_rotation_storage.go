package nodepki

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const MaxRootSetBytes = 1 << 20

type RootSetReceipt struct {
	SHA256   string `json:"sha256"`
	Rotation string `json:"rotation"`
	Phase    string `json:"phase"`
}

func ParseRootSetSnapshot(raw []byte) (RootSetSnapshot, error) {
	var s RootSetSnapshot
	if len(raw) == 0 || len(raw) > MaxRootSetBytes || json.Unmarshal(raw, &s) != nil {
		return s, ErrRootRotation
	}
	canonical, err := json.Marshal(s)
	if err != nil || !bytes.Equal(canonical, raw) || s.Format != 1 {
		return RootSetSnapshot{}, ErrRootRotation
	}
	return s, nil
}

// An absent migration directory is the only legacy state. Once initialized,
// missing/corrupt material fails closed instead of silently trusting the seed.
func readRootSetSnapshot(directory string, anchor []byte) (RootSetSnapshot, []byte, error) {
	var empty RootSetSnapshot
	if secureDirectory(directory) != nil {
		return empty, nil, ErrRootRotation
	}
	rotation := filepath.Join(directory, "root-rotation")
	if _, err := os.Lstat(rotation); os.IsNotExist(err) {
		return empty, nil, nil
	}
	if secureDirectory(rotation) != nil {
		return empty, nil, ErrRootRotation
	}
	base, err := readIdentityFile(filepath.Join(directory, "ca.crt"), 64<<10, true)
	if err != nil || !bytes.Equal(base, anchor) {
		return empty, nil, ErrRootRotation
	}
	pinned, err := readIdentityFile(filepath.Join(rotation, "anchor.crt"), 64<<10, true)
	if err != nil || !bytes.Equal(pinned, anchor) {
		return empty, nil, ErrRootRotation
	}
	raw, err := readIdentityFile(filepath.Join(rotation, "roots.json"), MaxRootSetBytes, true)
	if err != nil {
		return empty, nil, ErrRootRotation
	}
	s, err := ParseRootSetSnapshot(raw)
	if err != nil {
		return empty, nil, err
	}
	return latestRootHistory(rotation, anchor, s, raw)
}

func ReadRootSet(directory string, anchor []byte, now time.Time) (*RootSet, RootSetReceipt, error) {
	return readRootSet(directory, anchor, now, false)
}

func readRootSet(directory string, anchor []byte, now time.Time, historical bool) (*RootSet, RootSetReceipt, error) {
	s, raw, err := readRootSetSnapshot(directory, anchor)
	if err != nil {
		return nil, RootSetReceipt{}, err
	}
	if len(raw) == 0 {
		return nil, RootSetReceipt{}, nil
	}
	set, err := newRootSet(anchor, s, now, historical)
	if err != nil {
		return nil, RootSetReceipt{}, err
	}
	phase := s.Dual.Phase
	if s.Final != nil {
		phase = s.Final.Phase
	}
	return set, RootSetReceipt{SHA256: publicSHA(raw), Rotation: s.Dual.Rotation, Phase: phase}, nil
}

// PublishRootSet is a privileged local maintenance primitive, not a public
// endpoint. The caller must already hold a persistent administrator task and
// authenticate the exact node, pinned SSH transport and signed helper. Online
// leaf-renewal/CRL methods cannot call it to authorize a root change.
func PublishRootSet(ctx context.Context, directory string, anchor, raw []byte, now time.Time) (RootSetReceipt, error) {
	return publishRootSet(ctx, directory, anchor, raw, now, nil)
}

// validate runs under the durable floor lock before any files are changed.
func publishRootSet(ctx context.Context, directory string, anchor, raw []byte, now time.Time, validate func(RootSetSnapshot, RootSetSnapshot) error) (RootSetReceipt, error) {
	return publishRootSetAuthorized(ctx, directory, anchor, raw, now, true, validate)
}

func publishRootSetAuthorized(ctx context.Context, directory string, anchor, raw []byte, now time.Time, freshAuthorization bool, validate func(RootSetSnapshot, RootSetSnapshot) error) (RootSetReceipt, error) {
	var empty RootSetReceipt
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || secureDirectory(directory) != nil {
		return empty, ErrRootRotation
	}
	s, err := ParseRootSetSnapshot(raw)
	if err != nil {
		return empty, err
	}
	lock, err := authorityLock(ctx, directory)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	pinned, err := readIdentityFile(filepath.Join(directory, "ca.crt"), 64<<10, true)
	if err != nil || !bytes.Equal(pinned, anchor) {
		return empty, ErrRootRotation
	}
	previous, priorRaw, err := readRootSetSnapshot(directory, anchor)
	if err != nil || validateRootSetAdvance(anchor, previous, s, now, freshAuthorization) != nil {
		return empty, ErrRootRotation
	}
	if validate != nil {
		if err := validate(previous, s); err != nil {
			return empty, err
		}
	}
	if len(priorRaw) == 0 {
		floor, err := readIdentityFile(filepath.Join(directory, "ca.crl"), MaxCRLBytes, true)
		if err != nil || ValidateCRLAdvance(anchor, floor, s.OldCRL, now) != nil {
			return empty, ErrRootRotation
		}
		stage, err := os.MkdirTemp(directory, ".root-rotation-*")
		if err != nil {
			return empty, errStorage
		}
		defer os.RemoveAll(stage)
		for name, content := range map[string][]byte{"anchor.crt": anchor, "roots.json": raw} {
			if writeExclusive(filepath.Join(stage, name), content) != nil {
				return empty, errStorage
			}
		}
		if os.Mkdir(filepath.Join(stage, "history"), 0700) != nil || writeExclusive(filepath.Join(stage, "history", publicSHA(raw)+".json"), raw) != nil || syncDir(filepath.Join(stage, "history")) != nil || syncDir(stage) != nil || ctx.Err() != nil {
			return empty, errStorage
		}
		if identityRenameNoReplace(stage, filepath.Join(directory, "root-rotation")) != nil || syncDir(directory) != nil {
			return empty, errStorage
		}
	} else {
		rotation := filepath.Join(directory, "root-rotation")
		history := filepath.Join(rotation, "history")
		if secureDirectory(history) != nil {
			return empty, ErrRootRotation
		}
		file := filepath.Join(history, publicSHA(raw)+".json")
		if existing, err := readIdentityFile(file, MaxRootSetBytes, true); err == nil {
			if !bytes.Equal(existing, raw) {
				return empty, ErrRootRotation
			}
		} else if _, err := os.Lstat(file); !os.IsNotExist(err) {
			return empty, ErrRootRotation
		} else if writeExclusive(file, raw) != nil || syncDir(history) != nil {
			return empty, errStorage
		}
		f, err := os.CreateTemp(rotation, ".roots-*")
		if err != nil {
			return empty, errStorage
		}
		name := f.Name()
		defer os.Remove(name)
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		closed := f.Close()
		if err != nil || closed != nil || ctx.Err() != nil || os.Rename(name, filepath.Join(rotation, "roots.json")) != nil || syncDir(rotation) != nil {
			return empty, errStorage
		}
	}
	phase := s.Dual.Phase
	if s.Final != nil {
		phase = s.Final.Phase
	}
	return RootSetReceipt{publicSHA(raw), s.Dual.Rotation, phase}, nil
}
