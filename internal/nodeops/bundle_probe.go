package nodeops

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"webscan/internal/assets"
)

func probeBundle(ctx context.Context, dir string, s Spec) error {
	version, err := bundleCommand(ctx, filepath.Join(dir, "webscan"), "version")
	if err != nil || strings.TrimSpace(version) != s.Release {
		return errors.New("bundle-program-version-mismatch")
	}
	yara := filepath.Join(dir, "tools/bin/yara")
	if output, err := bundleCommand(ctx, yara, "--version"); err != nil || strings.TrimSpace(output) == "" {
		return errors.New("bundled-yara-unavailable")
	}
	rules, err := currentYaraRules()
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".rules-check-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(rules); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if _, err := bundleCommand(ctx, yara, "-w", f.Name(), "/dev/null"); err != nil {
		return errors.New("current-yara-rules-invalid")
	}
	if s.ClamAV {
		if output, err := bundleCommand(ctx, filepath.Join(dir, "tools/bin/clamdscan"), "--version"); err != nil || strings.TrimSpace(output) == "" {
			return errors.New("bundled-clamav-client-unavailable")
		}
	}
	return nil
}

func bundleCommand(ctx context.Context, program string, args ...string) (string, error) {
	probe, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	cmd := exec.CommandContext(probe, program, args...)
	b := &boundedOutput{}
	cmd.Stdout, cmd.Stderr = b, io.Discard
	err := cmd.Run()
	return string(b.raw), err
}

func currentYaraRules() ([]byte, error) {
	const file = "/etc/webscan-v1/php-webshell.yar"
	if _, err := os.Lstat(file); os.IsNotExist(err) {
		return assets.Files.ReadFile("php-webshell.yar")
	}
	// Current deployment files are private; a different file type, inaccessible
	// file, or bad rules must fail instead of silently replacing active rules.
	return readPrivate(file, 1<<20)
}
