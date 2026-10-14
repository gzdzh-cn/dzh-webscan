package management

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"webscan/internal/common"
)

const maxPrivateKeyBytes = 64 << 10

func validatePrivateKeyEdit(edit Edit) error {
	if len(edit.SSHPrivateKeyContent) > maxPrivateKeyBytes {
		return userError("私钥内容不能超过 64 KiB")
	}
	if edit.Node == nil || common.S(common.M(edit.Node["ssh"])["auth_method"]) != "key" {
		return userError("私钥内容只能用于子服务器私钥认证")
	}
	if strings.TrimSpace(common.S(common.M(edit.Node["ssh"])["private_key_path"])) != "" {
		return userError("私钥路径与内容不能同时提交")
	}
	if _, err := ssh.ParsePrivateKey([]byte(edit.SSHPrivateKeyContent)); err != nil {
		var encrypted *ssh.PassphraseMissingError
		if errors.As(err, &encrypted) {
			return userError("此私钥需要口令；本次仅支持未加密私钥")
		}
		return userError("私钥内容无效，请提供未加密的 OpenSSH 或 PEM 私钥，不能使用公钥")
	}
	return nil
}

func (s *Service) newPrivateKeyPath(edit Edit) string {
	if edit.SSHPrivateKeyContent == "" {
		return ""
	}
	return filepath.Join(s.StateDir, "ssh-keys", common.ID()+".key")
}

// The host management service owns this directory. Open relative to verified
// directory descriptors so a substituted symlink cannot redirect a key write.
func (s *Service) writePrivateKey(path, content string) (func(), error) {
	fail := userError("私钥保存失败，请检查主服务器私钥目录权限及磁盘空间；原配置保留")
	root, err := unix.Open(s.StateDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail
	}
	defer unix.Close(root)
	var st unix.Stat_t
	if unix.Fstat(root, &st) != nil || int(st.Uid) != os.Geteuid() || st.Mode&0077 != 0 {
		return nil, fail
	}
	if err = unix.Mkdirat(root, "ssh-keys", 0700); err != nil && err != unix.EEXIST {
		return nil, fail
	}
	dir, err := unix.Openat(root, "ssh-keys", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail
	}
	defer unix.Close(dir)
	if unix.Fstat(dir, &st) != nil || int(st.Uid) != os.Geteuid() || st.Mode&0777 != 0700 {
		return nil, fail
	}
	name := filepath.Base(path)
	if filepath.Dir(path) != filepath.Join(s.StateDir, "ssh-keys") {
		return nil, fail
	}
	tmp := ".new-" + common.ID()
	fd, err := unix.Openat(dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fail
	}
	defer unix.Unlinkat(dir, tmp, 0)
	file := os.NewFile(uintptr(fd), tmp)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write([]byte(content))
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, fail
	}
	// Generated targets must not replace existing files, including symlinks.
	if err = unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		return nil, fail
	}
	if err = unix.Linkat(dir, tmp, dir, name, 0); err != nil {
		return nil, fail
	}
	if err = unix.Unlinkat(dir, tmp, 0); err != nil {
		unix.Unlinkat(dir, name, 0)
		return nil, fail
	}
	if err = unix.Fsync(dir); err != nil {
		unix.Unlinkat(dir, name, 0)
		return nil, fail
	}
	return func() { os.Remove(path) }, nil
}

func (s *Service) commitConfig(before, after []byte, edit Edit, keyPath, source string) error {
	current, err := os.ReadFile(s.ConfigPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, before) {
		return userError("配置已被修改，请重新预览")
	}
	if _, err := s.backup(before, source); err != nil {
		return err
	}
	cleanup := func() {}
	if edit.SSHPrivateKeyContent != "" {
		var err error
		cleanup, err = s.writePrivateKey(keyPath, edit.SSHPrivateKeyContent)
		if err != nil {
			return err
		}
	}
	current, err = os.ReadFile(s.ConfigPath)
	if err != nil || !bytes.Equal(current, before) {
		cleanup()
		if err != nil {
			return err
		}
		return userError("配置已被修改，请重新预览")
	}
	if err := common.Atomic(s.ConfigPath, after, 0600); err != nil {
		// Atomic may report a directory fsync failure after the rename succeeded.
		// Never remove a key already referenced by the committed YAML.
		current, readErr := os.ReadFile(s.ConfigPath)
		if readErr == nil && !bytes.Equal(current, after) {
			cleanup()
		}
		return err
	}
	return nil
}
