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
	action := flag.String("action", "build", "build or publish")
	config := flag.String("config", "webscan.yaml", "local YAML, never included in build context")
	version := flag.String("release", "", "immutable version tag")
	flag.Parse()
	if !regexp.MustCompile(`^v[0-9][A-Za-z0-9._-]{1,80}$`).MatchString(*version) {
		return errors.New("explicit_release_version_required")
	}
	c, err := deploy.Load(*config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	if *action == "build" {
		command := exec.CommandContext(ctx, "bash", "scripts/package.sh", *version)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err = command.Run(); err != nil {
			return errors.New("crosscompile_package_failed")
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
			if _, err = d.Exec(ctx, nil, "build", "--platform", "linux/amd64", "--build-arg", "RUNTIME_IMAGE="+locked, "--target", role, "-f", "Dockerfile.release", "-t", "webscan-"+role+":"+*version, filepath.Join("dist", *version)); err != nil {
				return errors.New("local_image_build_failed_" + role)
			}
		}
		for _, role := range []string{"central", "agent"} {
			if _, err = d.Exec(ctx, nil, "tag", "webscan-"+role+":"+*version, "webscan-"+role+":latest"); err != nil {
				return errors.New("local_latest_tag_failed_" + role)
			}
		}
		return nil
	}
	if *action != "publish" {
		return errors.New("unknown_release_action")
	}
	d, err := deploy.NewDocker(ctx, c, true)
	if err != nil {
		return err
	}
	defer d.Close()
	images := common.Map{}
	for _, role := range []string{"central", "agent"} {
		source := "webscan-" + role + ":" + *version
		target := common.S(common.M(c.Raw["registry"])["prefix"]) + "/" + source
		fmt.Println("推送版本化自研镜像: " + role)
		if _, err = d.Exec(ctx, nil, "tag", source, target); err != nil {
			return err
		}
		if _, err = d.Exec(ctx, nil, "push", target); err != nil {
			return errors.New("registry_push_failed_" + role)
		}
		locked, err := d.Resolve(ctx, target)
		if err != nil || !strings.Contains(locked, "@sha256:") {
			return errors.New("published_manifest_digest_not_verified")
		}
		images[role] = locked
	}
	latest := common.Map{}
	// Move latest only after both versioned images have been published.
	for _, role := range []string{"central", "agent"} {
		target := common.S(common.M(c.Raw["registry"])["prefix"]) + "/webscan-" + role + ":latest"
		fmt.Println("更新 latest 标签: " + role)
		if _, err = d.Exec(ctx, nil, "tag", "webscan-"+role+":"+*version, target); err != nil {
			return err
		}
		if _, err = d.Exec(ctx, nil, "push", target); err != nil {
			return errors.New("registry_latest_push_failed_" + role)
		}
		locked, err := d.Resolve(ctx, target)
		if err != nil || locked != common.S(images[role]) {
			return errors.New("published_latest_digest_mismatch_" + role)
		}
		latest[role] = target
	}
	binary, err := os.ReadFile(filepath.Join("dist", *version, "webscan"))
	if err != nil {
		return err
	}
	base, err := os.ReadFile("config/base-images.lock")
	if err != nil {
		return err
	}
	report := common.Map{"release": *version, "platform": "linux/amd64", "go": "1.26.3", "goframe": "2.10.3", "binary_sha256": common.Hash(binary), "published_at": common.Stamp(), "images": images, "latest": latest, "base_images": string(base)}
	if err = common.AtomicJSON(filepath.Join("dist", *version, "release.json"), report); err != nil {
		return err
	}
	fmt.Println("镜像摘要已保存至 dist/" + *version + "/release.json")
	return nil
}
