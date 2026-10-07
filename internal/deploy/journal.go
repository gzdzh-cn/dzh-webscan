package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"webscan/internal/common"
)

type Journal struct {
	Dir   string
	Index common.Map
}

func NewJournal(dir string) (*Journal, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	index, e := common.ReadJSON(filepath.Join(dir, "index.json"))
	if os.IsNotExist(e) {
		index = common.Map{}
	} else if e != nil {
		return nil, e
	}
	return &Journal{dir, index}, nil
}
func (j *Journal) Remember(path string) error {
	if _, ok := j.Index[path]; ok {
		return nil
	}
	key := strconv.Itoa(len(j.Index))
	info, e := os.Lstat(path)
	if e == nil {
		if !info.Mode().IsRegular() {
			return errors.New("journal_target_not_regular_file")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if e = common.Atomic(filepath.Join(j.Dir, key), b, 0600); e != nil {
			return e
		}
		j.Index[path] = common.Map{"backup": key, "mode": int(info.Mode().Perm())}
	} else if os.IsNotExist(e) {
		j.Index[path] = common.Map{"backup": nil}
	} else {
		return e
	}
	return common.AtomicJSON(filepath.Join(j.Dir, "index.json"), j.Index)
}
func (j *Journal) Write(path string, b []byte, mode os.FileMode) error {
	if e := j.Remember(path); e != nil {
		return e
	}
	return common.Atomic(path, b, mode)
}
func (j *Journal) Rollback() error {
	for path, value := range j.Index {
		saved := common.M(value)
		if saved["backup"] == nil {
			if info, e := os.Lstat(path); e == nil {
				if !info.Mode().IsRegular() {
					return errors.New("rollback_target_not_regular")
				}
				if e = os.Remove(path); e != nil {
					return e
				}
			}
			continue
		}
		b, e := os.ReadFile(filepath.Join(j.Dir, common.S(saved["backup"])))
		if e != nil {
			return e
		}
		if e = common.Atomic(path, b, os.FileMode(common.I(saved["mode"]))); e != nil {
			return e
		}
	}
	return nil
}
