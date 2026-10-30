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
	action := flag.String("action", "build", "build, stage (versioned images only), or publish")
	config := flag.String("config", "webscan.yaml", "local YAML, never included in build context")
	version := flag.String("release", "", "immutable version tag")
	verification := flag.String("verification", "", "isolated acceptance record bound to the committed build")
	manifest := flag.String("manifest", "", "signed deployment release manifest")
	signature := flag.String("signature", "", "detached release signature")
	publicKey := flag.String("public-key", "", "independently trusted release public key")
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
	if *action != "publish" && *action != "stage" {
		return errors.New("unknown_release_action")
	}
	root := filepath.Join("dist", *version)
	receipt, err := readBuildReceipt(root, *version)
	if err != nil {
		return err
	}
	if err = checkPublicationSource(ctx, receipt.Build); err != nil {
		return err
	}
	// Version tags are public release artifacts too. A staging operation may
	// omit the final signature (it needs the registry digest), never acceptance.
	if err = checkVerification(*verification, receipt.Build); err != nil {
		return err
	}
	var signedImage string
	if *action == "publish" {
		signed, err := checkSignedArtifacts(root, *manifest, *signature, *publicKey, *version)
		if err != nil {
			return err
		}
		signedImage = signed.Image
	}
	d, err := deploy.NewDocker(ctx, c, true)
	if err != nil {
		return err
	}
	defer d.Close()
	// Verify every local image before the first registry mutation. Tags alone
	// are mutable and cannot prove which binary passed acceptance.
	for _, role := range []string{"central", "agent"} {
		raw, err := d.Exec(ctx, nil, "image", "inspect", "--format", "{{.Id}}/{{index .Config.Labels \"org.opencontainers.image.version\"}}/{{index .Config.Labels \"org.opencontainers.image.revision\"}}/{{index .Config.Labels \"io.webscan.source.digest\"}}", "webscan-"+role+":"+*version)
		if err != nil || strings.TrimSpace(string(raw)) != receipt.Images[role]+"/"+*version+"/"+receipt.Build.Commit+"/"+receipt.Build.Source {
			return errPublicationGate
		}
	}
	images := common.Map{}
	versionedImages := common.Map{}
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
		versionedImages[role] = target + locked[strings.LastIndex(locked, "@"):]
	}
	if *action == "stage" {
		return common.AtomicJSON(filepath.Join(root, "staged-images.json"), common.Map{"release": *version, "commit": receipt.Build.Commit, "source_digest": receipt.Build.Source, "images": images, "versioned_images": versionedImages})
	}
	if !strings.HasSuffix(signedImage, "@"+strings.Split(common.S(images["agent"]), "@")[1]) {
		return errPublicationGate
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
	bundle, err := os.ReadFile(filepath.Join("dist", *version, "agent-native.tar.gz"))
	if err != nil {
		return err
	}
	report := common.Map{"release": *version, "platform": "linux/amd64", "go": "1.26.3", "goframe": "2.10.3", "binary_sha256": common.Hash(binary), "native_package_sha256": common.Hash(bundle), "published_at": common.Stamp(), "images": images, "versioned_images": versionedImages, "latest": latest, "base_images": string(base)}
	if err = common.AtomicJSON(filepath.Join("dist", *version, "release.json"), report); err != nil {
		return err
	}
	fmt.Println("镜像摘要已保存至 dist/" + *version + "/release.json")
	return nil
}
