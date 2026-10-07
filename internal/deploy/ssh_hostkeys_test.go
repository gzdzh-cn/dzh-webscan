package deploy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sys/unix"
	"webscan/internal/common"
)

func testHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func automaticHostFixture(t *testing.T) (common.Map, func(ssh.Signer), *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var mu sync.RWMutex
	signer := testHostSigner(t)
	var attempts atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.RLock()
			hostKey := signer
			mu.RUnlock()
			go func() {
				config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
					attempts.Add(1)
					if string(password) != "fixture-password" {
						return nil, errors.New("incorrect password")
					}
					return nil, nil
				}}
				config.AddHostKey(hostKey)
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					conn.Close()
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					channel.Reject(ssh.Prohibited, "unused")
				}
			}()
		}
	}()
	_, rawPort, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	node := common.Map{"host": "127.0.0.1", "ssh": common.Map{"username": "root", "auth_method": "password", "password": "fixture-password", "port": port, "connect_timeout_seconds": 3}}
	return node, func(next ssh.Signer) { mu.Lock(); signer = next; mu.Unlock() }, &attempts
}

func TestAutomaticHostKeyFirstUseReconnectAndChangedKey(t *testing.T) {
	node, rotate, attempts := automaticHostFixture(t)
	store := filepath.Join(t.TempDir(), "ssh_known_hosts")
	remote, err := connectWithHostKeys(context.Background(), node, store)
	if err != nil {
		t.Fatal(err)
	}
	remote.Close()
	before, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(store)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("unsafe trust file")
	}
	if len(strings.Split(strings.TrimSpace(string(before)), "\n")) != 1 {
		t.Fatal("first host not recorded once")
	}
	remote, err = connectWithHostKeys(context.Background(), node, store)
	if err != nil {
		t.Fatal(err)
	}
	remote.Close()
	after, _ := os.ReadFile(store)
	if string(after) != string(before) || attempts.Load() != 2 {
		t.Fatal("reconnect changed pin or authentication skipped")
	}
	rotate(testHostSigner(t))
	if remote, err = connectWithHostKeys(context.Background(), node, store); err == nil {
		remote.Close()
		t.Fatal("changed host key accepted")
	} else if err.Error() != "ssh_host_fingerprint_mismatch" {
		t.Fatal("host change diagnosis lost", err)
	}
	after, _ = os.ReadFile(store)
	if string(after) != string(before) || attempts.Load() != 2 {
		t.Fatal("changed host authenticated or replaced pin")
	}
}

func TestAutomaticHostKeyFailedAuthenticationDoesNotPin(t *testing.T) {
	node, _, _ := automaticHostFixture(t)
	common.M(node["ssh"])["password"] = "wrong-password"
	store := filepath.Join(t.TempDir(), "ssh_known_hosts")
	if remote, err := connectWithHostKeys(context.Background(), node, store); err == nil {
		remote.Close()
		t.Fatal("bad password accepted")
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatal("failed authentication saved a host key")
	}
	common.M(node["ssh"])["password"] = "fixture-password"
	remote, err := connectWithHostKeys(context.Background(), node, store)
	if err != nil {
		t.Fatal(err)
	}
	remote.Close()
}

func TestAutomaticHostKeysAreScopedByPortAndRejectUnsafeRecords(t *testing.T) {
	first, _, _ := automaticHostFixture(t)
	second, _, attempts := automaticHostFixture(t)
	store := filepath.Join(t.TempDir(), "ssh_known_hosts")
	for _, node := range []common.Map{first, second} {
		r, err := connectWithHostKeys(context.Background(), node, store)
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
	}
	data, _ := os.ReadFile(store)
	if len(strings.Split(strings.TrimSpace(string(data)), "\n")) != 2 {
		t.Fatal("different SSH ports shared a pin")
	}
	if err := os.Chmod(store, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := connectWithHostKeys(context.Background(), second, store); err == nil {
		t.Fatal("unsafe permissions accepted")
	}
	if err := os.Chmod(store, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store, []byte("corrupt host record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := connectWithHostKeys(context.Background(), second, store); err == nil {
		t.Fatal("corrupt trust file accepted as first use")
	}
	if attempts.Load() != 1 {
		t.Fatal("credentials sent before validating trust file")
	}
	sym := filepath.Join(filepath.Dir(store), "symbolic")
	if err := os.Symlink(store, sym); err != nil {
		t.Fatal(err)
	}
	if _, err := connectWithHostKeys(context.Background(), second, sym); err == nil {
		t.Fatal("symbolic trust file accepted")
	}
}

func TestConcurrentHostPinCommitPreservesOthersAndRejectsConflicts(t *testing.T) {
	store := filepath.Join(t.TempDir(), "ssh_known_hosts")
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
	keys := []ssh.PublicKey{testHostSigner(t).PublicKey(), testHostSigner(t).PublicKey()}
	var wg sync.WaitGroup
	var added atomic.Int64
	errorsOut := make(chan error, 2)
	for _, key := range keys {
		wg.Add(1)
		go func(k ssh.PublicKey) {
			defer wg.Done()
			ok, err := recordHostKey(context.Background(), store, "127.0.0.1:2222", remote, k)
			if ok {
				added.Add(1)
			}
			errorsOut <- err
		}(key)
	}
	wg.Wait()
	close(errorsOut)
	failures := 0
	for err := range errorsOut {
		if err != nil {
			if err.Error() != "ssh_host_fingerprint_mismatch" {
				t.Fatal(err)
			}
			failures++
		}
	}
	if added.Load() != 1 || failures != 1 {
		t.Fatal("simultaneous first use overwrote a pin", added.Load(), failures)
	}
	_, callback, err := readHostKeys(store)
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for _, k := range keys {
		if callback("127.0.0.1:2222", remote, k) == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal("conflicting keys both trusted")
	}
	for i, key := range keys {
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(3000+i))
		wg.Add(1)
		go func(addr string, k ssh.PublicKey) {
			defer wg.Done()
			_, err := recordHostKey(context.Background(), store, addr, remote, k)
			if err != nil {
				t.Error(err)
			}
		}(address, key)
	}
	wg.Wait()
	data, _ := os.ReadFile(store)
	if len(strings.Split(strings.TrimSpace(string(data)), "\n")) != 3 {
		t.Fatal("concurrent unrelated pins lost")
	}
}

func TestHostPinLockWaitAndHandshakeHonorCancellation(t *testing.T) {
	store := filepath.Join(t.TempDir(), "ssh_known_hosts")
	lock, err := os.OpenFile(store+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_, err = recordHostKey(ctx, store, "127.0.0.1:2222", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}, testHostSigner(t).PublicKey())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lock cancellation swallowed", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 1024)
		for {
			if _, err = conn.Read(buffer); err != nil {
				return
			}
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	node := common.Map{"host": "127.0.0.1", "ssh": common.Map{"auth_method": "password", "password": "fixture", "port": number, "connect_timeout_seconds": 5}}
	ctx, cancel = context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_, err = connectWithHostKeys(ctx, node, store)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("handshake cancellation swallowed", err)
	}
}

func TestHostKeysOpenSSHIPv6Syntax(t *testing.T) {
	key := testHostSigner(t).PublicKey()
	store := filepath.Join(t.TempDir(), "ssh_known_hosts")
	address := "[2001:db8::1]:555"
	if err := os.WriteFile(store, []byte(knownhosts.Line([]string{address}, key)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, callback, err := readHostKeys(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("[2001:db8::1]:555", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 555}, key); err != nil {
		t.Fatal("IPv6 pin failed", err)
	}
}
