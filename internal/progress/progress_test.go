package progress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webscan/internal/common"
)

func TestStreamRedactsSplitSecretsAndKeepsRealtimeLines(t *testing.T) {
	var output bytes.Buffer
	r := New(&output, common.Map{"registry": common.Map{"username": "publisher@example.test", "password": "secret word"}, "feishu": common.Map{"webhook_url": "https://example.test/hook/private", "signing_secret": "signing-value"}}, "部署")
	ctx := With(context.Background(), r)
	w := Stream(ctx, "下载进度")
	io.WriteString(w, "Downloading secret ")
	if output.Len() != 0 {
		t.Fatal("unfinished line emitted")
	}
	io.WriteString(w, "word publisher@example.test https://example.test/hook/private signing-value secret+word\n")
	if !strings.Contains(output.String(), "下载中") {
		t.Fatal("complete line did not appear before close")
	}
	io.WriteString(w, "Bearer abc.def.ghi https://user:password@registry.test/path\x1b[31m tail")
	w.Close()
	for _, secret := range []string{"secret word", "publisher@example.test", "hook/private", "signing-value", "secret+word", "abc.def.ghi", "user:password", "\x1b"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("secret or control sequence leaked: %q", secret)
		}
	}
	if !strings.Contains(output.String(), "tail") {
		t.Fatal("last partial line lost")
	}
}

func TestWaitAndFailureDoNotContinueAfterStageEnds(t *testing.T) {
	var output bytes.Buffer
	r := New(&output, common.Map{}, "部署")
	r.interval = 2 * time.Millisecond
	ctx, cancel := context.WithTimeout(With(context.Background(), r), 15*time.Millisecond)
	defer cancel()
	err := Stage(ctx, "子服务器202 192.0.2.2", "等待文件清单", func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	text := output.String()
	for _, part := range []string{"[部署01]", "[进行]", "[等待]", "[失败]", "子服务器202", "耗时", "操作超时"} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s: %s", part, text)
		}
	}
	time.Sleep(5 * time.Millisecond)
	if output.String() != text {
		t.Fatal("wait messages continued after completion")
	}
	if err := Stage(With(context.Background(), r), "主服务器", "快速检查", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "[部署02][成功]") {
		t.Fatal(output.String())
	}
}

func TestPrivateLogPlainTextAndUnsafeFileRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deployment.log")
	t.Setenv("WEBSCAN_PROGRESS_LOG", path)
	r, err := Open(common.Map{}, "部署", dir)
	if err != nil {
		t.Fatal(err)
	}
	r.out = io.Discard
	r.color = true
	if err = Stage(With(context.Background(), r), "主服务器", "完成检查", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	r.Close()
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte("\x1b")) || !bytes.Contains(data, []byte("[成功]")) {
		t.Fatal(string(data))
	}
	link := filepath.Join(dir, "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WEBSCAN_PROGRESS_LOG", link)
	if r, err = Open(common.Map{}, "部署", dir); err == nil {
		r.Close()
		t.Fatal("symlink accepted")
	}
}

func TestNoArbitraryCommandOrCredentialsStreamed(t *testing.T) {
	for _, args := range [][]string{{"docker", "login", "--username", "pull", "--password-stdin"}, {"docker", "inspect", "pull"}, {"docker", "login", "--password-stdin"}, {"docker", "inspect", "container"}, {"docker", "compose", "config"}, {"bash", "-c", "cat /etc/private"}, {"docker", "cp", "secret:/file", "-"}} {
		if label := CommandLabel(args); label != "" {
			t.Fatalf("unexpected streaming: %v", args)
		}
	}
	for _, args := range [][]string{{"docker", "--config", "/tmp/auth", "pull", "image:v1"}, {"docker", "compose", "-f", "config.yml", "up", "-d"}} {
		if CommandLabel(args) == "" {
			t.Fatal(args)
		}
	}
	var output bytes.Buffer
	r := New(&output, common.Map{}, "部署")
	data := []byte(strings.Repeat("a", 2*1048576))
	copy, err := io.ReadAll(Reader(With(context.Background(), r), bytes.NewReader(data), int64(len(data)), "SSH 传输"))
	if err != nil || !bytes.Equal(copy, data) || !strings.Contains(output.String(), "100%") {
		t.Fatal("transfer byte count or stream changed")
	}
}
