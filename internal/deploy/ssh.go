package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"webscan/internal/common"
	"webscan/internal/progress"
)

type Remote struct {
	Client *ssh.Client
	Host   string
}

func Connect(ctx context.Context, n common.Map) (*Remote, error) {
	return connectWithHostKeys(ctx, n, filepath.Join(StateRoot, "ssh_known_hosts"))
}

func connectWithHostKeys(ctx context.Context, n common.Map, hostKeysPath string) (*Remote, error) {
	c := common.M(n["ssh"])
	pin := common.S(c["host_key_sha256"])
	var trusted ssh.HostKeyCallback
	if pin == "" {
		var err error
		_, trusted, err = readHostKeys(hostKeysPath)
		if err != nil {
			return nil, err
		}
	}
	auth := []ssh.AuthMethod{}
	switch common.S(c["auth_method"]) {
	case "key":
		path := common.S(c["private_key_path"])
		st, e := os.Lstat(path)
		if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 && st.Mode().Perm() != 0400 {
			return nil, errors.New("ssh_key_missing_or_insecure_permissions")
		}
		if owner, ok := st.Sys().(*syscall.Stat_t); !ok || int(owner.Uid) != os.Geteuid() {
			return nil, errors.New("ssh_key_owner_mismatch")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		key, e := ssh.ParsePrivateKey(b)
		if e != nil {
			return nil, errors.New("ssh_key_parse_failed")
		}
		auth = append(auth, ssh.PublicKeys(key))
	case "password":
		auth = append(auth, ssh.Password(common.S(c["password"])))
	}
	timeout := time.Duration(max(common.I(c["connect_timeout_seconds"]), 1)) * time.Second
	addr := net.JoinHostPort(common.S(n["host"]), strconv.Itoa(common.I(c["port"])))
	if ip := net.ParseIP(common.S(n["host"])); ip != nil {
		addr = net.JoinHostPort(ip.String(), strconv.Itoa(common.I(c["port"])))
	}
	deadline := time.Now().Add(timeout)
	mismatched := false
	// A fingerprint identifies a particular host key, not every key exposed by
	// sshd. Negotiate each modern algorithm until the pinned key is selected.
	algorithms := []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	for _, algorithm := range algorithms {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		matched := false
		var presented ssh.PublicKey
		cfg := &ssh.ClientConfig{User: "root", Auth: auth, Timeout: timeout, HostKeyAlgorithms: []string{algorithm}, HostKeyCallback: func(host string, addr net.Addr, key ssh.PublicKey) error {
			if pin != "" && ssh.FingerprintSHA256(key) != pin {
				mismatched = true
				return errors.New("ssh_host_fingerprint_mismatch")
			}
			if trusted != nil {
				if err := trusted(host, addr, key); err != nil {
					var unknown *knownhosts.KeyError
					if !errors.As(err, &unknown) || len(unknown.Want) > 0 {
						mismatched = true
						return errors.New("ssh_host_fingerprint_mismatch")
					}
				}
			}
			matched = true
			presented = key
			return nil
		}}
		raw, err := (&net.Dialer{Deadline: deadline}).DialContext(ctx, "tcp", addr)
		if err != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if mismatched {
				return nil, errors.New("ssh_host_fingerprint_mismatch")
			}
			return nil, errors.New("ssh_connect_failed")
		}
		raw.SetDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { raw.Close() })
		conn, channels, requests, err := ssh.NewClientConn(raw, addr, cfg)
		stop()
		if err == nil {
			if err = ctx.Err(); err != nil {
				conn.Close()
				return nil, err
			}
			if pin == "" {
				var added bool
				added, err = recordHostKey(ctx, hostKeysPath, addr, raw.RemoteAddr(), presented)
				if err != nil {
					conn.Close()
					return nil, err
				}
				if added {
					progress.Info(ctx, "首次 SSH 连接已成功，自动保存主机指纹："+ssh.FingerprintSHA256(presented))
				} else {
					progress.Info(ctx, "SSH 主机指纹校验通过（使用已自动记录的密钥）")
				}
			}
			raw.SetDeadline(time.Time{})
			return &Remote{ssh.NewClient(conn, channels, requests), common.S(n["host"])}, nil
		}
		raw.Close()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if matched || time.Now().After(deadline) {
			if !matched && mismatched {
				return nil, errors.New("ssh_host_fingerprint_mismatch")
			}
			return nil, errors.New("ssh_authentication_or_host_verification_failed")
		}
	}
	if mismatched {
		return nil, errors.New("ssh_host_fingerprint_mismatch")
	}
	return nil, errors.New("ssh_authentication_or_host_verification_failed")
}
func (r *Remote) Close() { r.Client.Close() }
func Q(s string) string  { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func (r *Remote) Exec(ctx context.Context, command string, input io.Reader) ([]byte, error) {
	return r.ExecVisible(ctx, command, input, "")
}
func (r *Remote) ExecVisible(ctx context.Context, command string, input io.Reader, label string) ([]byte, error) {
	session, e := r.Client.NewSession()
	if e != nil {
		return nil, errors.New("ssh_session_failed")
	}
	defer session.Close()
	session.Stdin = input
	var output bytes.Buffer
	session.Stdout = &output
	session.Stderr = io.Discard
	if label != "" && progress.Enabled(ctx) {
		stdout := progress.Stream(ctx, label)
		stderr := progress.Stream(ctx, label+"诊断")
		defer stdout.Close()
		defer stderr.Close()
		session.Stdout = io.MultiWriter(progress.Limit(&output, 65536), stdout)
		session.Stderr = stderr
	}
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case <-ctx.Done():
		session.Close()
		return nil, ctx.Err()
	case e := <-done:
		if e != nil {
			return nil, progress.CommandError("remote_command_failed", e)
		}
		return output.Bytes(), nil
	}
}
func (r *Remote) Run(ctx context.Context, command string) ([]byte, error) {
	return r.Exec(ctx, command, nil)
}
func (r *Remote) Read(ctx context.Context, path string) ([]byte, error) {
	return r.Run(ctx, "cat -- "+Q(path))
}
func (r *Remote) Write(ctx context.Context, path string, b []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("invalid_remote_path")
	}
	parent := filepath.Dir(path)
	tmp := path + ".webscan-new-" + common.ID()
	cmd := "set -eu; umask 077; p=" + Q(parent) + "; while [ \"$p\" != / ]; do test ! -L \"$p\"; p=$(dirname -- \"$p\"); done; test ! -L " + Q(path) + "; mkdir -p -- " + Q(parent) + "; trap " + Q("rm -f -- "+Q(tmp)) + " EXIT; cat > " + Q(tmp) + "; chmod " + fmt.Sprintf("%o", mode.Perm()) + " " + Q(tmp) + "; sync -f " + Q(tmp) + "; mv -f -- " + Q(tmp) + " " + Q(path) + "; sync -f " + Q(parent)
	_, e := r.Exec(ctx, cmd, bytes.NewReader(b))
	return e
}
