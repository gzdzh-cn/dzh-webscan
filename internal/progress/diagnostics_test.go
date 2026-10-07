package progress

import (
	"errors"
	"os"
	"strings"
	"testing"
	"webscan/internal/config"
)

type commandExit struct{}

func (commandExit) Error() string   { return "never-echo-password-or-command" }
func (commandExit) ExitStatus() int { return 127 }

func TestCommandFailureRetainsStatusWithoutRawOutput(t *testing.T) {
	err := CommandError("remote_command_failed", commandExit{})
	message := Explain(err)
	if err.Error() != "remote_command_failed" || !strings.Contains(message, "退出码：127") || !strings.Contains(message, "命令未找到") || strings.Contains(message, "never-echo") {
		t.Fatal(message)
	}
}

func TestConfigurationAndOperationalErrorsUseSharedGuidance(t *testing.T) {
	for _, tt := range []struct {
		err  error
		hint string
	}{
		{config.WithField(errors.New("invalid_ssh_port"), "nodes[1].ssh.port"), "nodes[1].ssh.port"},
		{errors.New("compose_output_exists_use_new_directory"), "--output compose-deploy-new"},
		{errors.New("feishu_env_file_unreadable"), "FEISHU_WEBHOOK_URL"},
		{errors.New("ssh_connect_failed"), "云安全组"},
		{errors.New("unknown_operation_code"), "最近的失败阶段"},
		{&os.PathError{Op: "open", Path: "never-echo-secret", Err: os.ErrPermission}, "权限"},
	} {
		message := Explain(tt.err)
		if !strings.Contains(message, tt.hint) || strings.Contains(message, "never-echo") {
			t.Fatal(message)
		}
	}
	// Every generator error must have specific corrective steps, not fallback text.
	b, err := os.ReadFile("../deploy/compose_package.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		_, rest, ok := strings.Cut(line, `errors.New("`)
		if !ok {
			continue
		}
		code, _, _ := strings.Cut(rest, `"`)
		if _, ok := explainOperation(errors.New(code)); !ok {
			t.Errorf("no guidance: %s", code)
		}
	}
}
