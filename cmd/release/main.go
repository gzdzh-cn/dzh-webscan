// Local-only versioned build and publication. Credentials come from YAML only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/deploy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "发布工具:", common.SecretFree(err))
		os.Exit(1)
	}
}
func run() error {
	action := flag.String("action", "build", "build, stage (unsigned version bootstrap), publish-versioned, promote-latest, or publish (legacy: also updates latest)")
	config := flag.String("config", "webscan.yaml", "local YAML, never included in build context")
	version := flag.String("release", "", "immutable version tag")
	verification := flag.String("verification", "", "isolated acceptance record bound to the committed build")
	manifest := flag.String("manifest", "", "signed deployment release manifest")
	signature := flag.String("signature", "", "detached release signature")
	publicKey := flag.String("public-key", "", "independently trusted release public key")
	productionVerification := flag.String("production-verification", "", "production acceptance receipt required by promote-latest")
	flag.Parse()
	if !regexp.MustCompile(`^v[0-9][A-Za-z0-9._-]{1,80}$`).MatchString(*version) {
		return errors.New("explicit_release_version_required")
	}
	c, err := deploy.Load(*config)
	if err != nil {
		return err
	}
	timeout := 40 * time.Minute
	if *action == "build" {
		timeout = 3 * time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if *action == "build" {
		command := exec.CommandContext(ctx, "bash", "scripts/package.sh", *version)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err = command.Run(); err != nil {
			return errors.New("crosscompile_package_failed")
		}
		var build buildRecord
		if err = readReleaseJSON(filepath.Join("dist", *version, "build-info.json"), &build); err != nil {
			return err
		}
		base, err := os.ReadFile("config/base-images.lock")
		if err != nil {
			return err
		}
		ref := ""
		for _, line := range strings.Split(string(base), "\n") {
			if strings.HasPrefix(line, "RUNTIME_IMAGE=") {
				ref = strings.TrimPrefix(line, "RUNTIME_IMAGE=")
			}
		}
		if !strings.Contains(ref, "@sha256:") {
			return errors.New("base_digest_lock_required")
		}
		// Build uses an anonymous, isolated Docker config; no login needed.
		anonymous := &deploy.Config{Raw: common.Clone(c.Raw)}
		common.M(anonymous.Raw["registry"])["auth_required"] = false
		d, err := deploy.NewDocker(ctx, anonymous, false)
		if err != nil {
			return err
		}
		defer d.Close()
		locked, err := d.Pull(ctx, ref)
		if err != nil {
			return errors.New("runtime_base_pull_failed")
		}
		for _, role := range []string{"central", "agent"} {
			fmt.Println("本地构建 linux/amd64: " + role)
			if _, err = d.Exec(ctx, nil, "build", "--platform", "linux/amd64", "--build-arg", "RUNTIME_IMAGE="+locked, "--build-arg", "RELEASE="+*version, "--build-arg", "SOURCE_COMMIT="+build.Commit, "--build-arg", "SOURCE_DIGEST="+build.Source, "--target", role, "-f", "Dockerfile.release", "-t", "webscan-"+role+":"+*version, filepath.Join("dist", *version)); err != nil {
				return errors.New("local_image_build_failed_" + role)
			}
		}
		// Publish the exact native bundle embedded in the verified agent image.
		name := "webscan-release-bundle-" + common.ID()
		if _, err = d.Exec(ctx, nil, "create", "--name", name, "webscan-agent:"+*version, "version"); err != nil {
			return err
		}
		defer d.Exec(context.WithoutCancel(ctx), nil, "rm", "-f", name)
		archive := filepath.Join("dist", *version, "agent-native.tar.gz")
		if _, err = d.Exec(ctx, nil, "cp", name+":/usr/local/lib/webscan/agent-native.tar.gz", archive); err != nil {
			return err
		}
		bundle, err := os.ReadFile(archive)
		if err != nil {
			return err
		}
		if err = common.Atomic(filepath.Join("dist", *version, "agent-native.sha256"), []byte(common.Hash(bundle)+"  agent-native.tar.gz\n"), 0644); err != nil {
			return err
		}
		built := map[string]string{}
		for _, role := range []string{"central", "agent"} {
			raw, err := d.Exec(ctx, nil, "image", "inspect", "--format", "{{.Id}}", "webscan-"+role+":"+*version)
			if err != nil {
				return err
			}
			built[role] = strings.TrimSpace(string(raw))
		}
		return writeBuildReceipt(filepath.Join("dist", *version), built)
	}
	return runPublication(ctx, c, publicationOptions{
		Action: *action, Root: filepath.Join("dist", *version), Version: *version,
		Verification: *verification, Manifest: *manifest, Signature: *signature,
		PublicKey: *publicKey, ProductionVerification: *productionVerification,
	}, publicationChecks{Source: checkPublicationSource, Verification: checkVerification, Signed: checkSignedArtifacts}, newPublicationRegistry)
}
