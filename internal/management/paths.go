package management

import (
	"os"
	"path/filepath"
	"syscall"
)

// Host-only inputs must not traverse a link or a directory writable by others.
func secureHostPath(path string) error {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	for p := absolute; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if e == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return userErrorf("宿主机路径不能经过符号链接：%s", p)
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
				return userErrorf("宿主机路径必须由 root 所有且不能由其他用户写入：%s", p)
			}
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}
