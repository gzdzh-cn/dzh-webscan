package deploy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/progress"
)

type observedOutput struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	first chan struct{}
	once  sync.Once
}

func (o *observedOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, e := o.buf.Write(p)
	if bytes.Contains(p, []byte("下载中")) {
		o.once.Do(func() { close(o.first) })
	}
	return n, e
}
func (o *observedOutput) text() string { o.mu.Lock(); defer o.mu.Unlock(); return o.buf.String() }

func TestDockerProgressAppearsBeforeCommandCompletesAndMasksSecrets(t *testing.T) {
	dir := t.TempDir()
	ack := filepath.Join(dir, "continue")
	command := filepath.Join(dir, "docker")
	script := fmt.Sprintf("#!/bin/sh\nprintf 'Downloading split'; sleep 0.01; printf 'secret\\n'\nwhile [ ! -f '%s' ]; do sleep 0.01; done\nprintf 'diagnostic splitsecret\\n' >&2\n", ack)
	if e := os.WriteFile(command, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	out := &observedOutput{first: make(chan struct{})}
	r := progress.New(out, common.Map{"registry": common.Map{"password": "splitsecret"}}, "部署")
	ctx, cancel := context.WithTimeout(progress.With(context.Background(), r), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := RunCommand(ctx, nil, command, "pull", "example:v1"); done <- e }()
	select {
	case <-out.first:
	case <-ctx.Done():
		t.Fatal("progress did not arrive while process running")
	}
	select {
	case <-done:
		t.Fatal("command finished before acknowledgement")
	default:
	}
	if e := os.WriteFile(ack, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.text(), "splitsecret") || !strings.Contains(out.text(), "诊断") {
		t.Fatal("secret leakage or missing stderr progress")
	}
}

func testRemoteResult(t *testing.T, stdout string, fail bool) *Remote {
	return testRemoteCommand(t, func(string) (string, bool) { return stdout, fail })
}

func testRemoteCommand(t *testing.T, result func(string) (string, bool)) *Remote {
	t.Helper()
	_, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		raw, e := l.Accept()
		if e != nil {
			return
		}
		server, channels, requests, e := ssh.NewServerConn(raw, cfg)
		if e != nil {
			raw.Close()
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for offer := range channels {
			ch, reqs, e := offer.Accept()
			if e != nil {
				return
			}
			for req := range reqs {
				if req.Type == "exec" {
					var payload struct{ Command string }
					ssh.Unmarshal(req.Payload, &payload)
					req.Reply(true, nil)
					io.Copy(io.Discard, ch)
					stdout, fail := result(payload.Command)
					ch.Write([]byte(stdout))
					code := uint32(0)
					if fail {
						code = 1
					}
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
					ch.Close()
					break
				} else {
					req.Reply(false, nil)
				}
			}
		}
	}()
	client, e := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{User: "root", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	return &Remote{Client: client}
}

func TestFreshCollectorCheckDoesNotTreatMissingOrFailedSSHAsInstalled(t *testing.T) {
	for _, tc := range []struct {
		output                   string
		fail, present, wantError bool
	}{{"fresh", false, false, false}, {"installed", false, true, false}, {"unexpected", false, false, true}, {"", true, false, true}} {
		r := testRemoteResult(t, tc.output, tc.fail)
		present, e := existingCollector(context.Background(), r)
		if present != tc.present || (e != nil) != tc.wantError {
			t.Fatalf("output %q: present=%v err=%v", tc.output, present, e)
		}
	}
}

func TestReadingRemoteConfigurationDoesNotStreamIt(t *testing.T) {
	r := testRemoteResult(t, `{"password":"private-config-value"}`, false)
	var out bytes.Buffer
	ctx := progress.With(context.Background(), progress.New(&out, common.Map{}, "部署"))
	data, e := r.Read(ctx, "/etc/webscan-v1/runtime.json")
	if e != nil || !strings.Contains(string(data), "private-config-value") || out.Len() != 0 {
		t.Fatal("configuration read changed or exposed")
	}
}
