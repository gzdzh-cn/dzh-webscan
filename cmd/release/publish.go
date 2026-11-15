package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"webscan/internal/common"
	"webscan/internal/controlplane"
	"webscan/internal/deploy"
)

type publicationOptions struct {
	Action, Root, Version, Verification, Manifest, Signature, PublicKey, ProductionVerification string
}

type publicationChecks struct {
	Source       func(context.Context, buildRecord) error
	Verification func(string, buildRecord) error
	Signed       func(string, string, string, string, string) (controlplane.ReleaseManifest, error)
}

type publicationRegistry interface {
	Exec(context.Context, io.Reader, ...string) ([]byte, error)
	Lookup(context.Context, string) (string, bool, error)
	Close()
}

type publicationRegistryFactory func(context.Context, *deploy.Config) (publicationRegistry, error)

type dockerPublicationRegistry struct{ *deploy.Docker }

func newPublicationRegistry(ctx context.Context, c *deploy.Config) (publicationRegistry, error) {
	d, err := deploy.NewDocker(ctx, c, true)
	if err != nil {
		return nil, err
	}
	return &dockerPublicationRegistry{d}, nil
}

var registryDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Resolve on deploy.Docker inspects the local daemon. Registry publication must
// inspect the remote manifest independently, including when the local tag exists.
func (d *dockerPublicationRegistry) Lookup(ctx context.Context, ref string) (string, bool, error) {
	cmd := exec.CommandContext(ctx, "docker", "--host", d.Host, "--config", d.Dir,
		"buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", ref)
	var out, diagnostic bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", false, ctx.Err()
		}
		message := strings.ToLower(strings.TrimSpace(diagnostic.String()))
		// Authentication and network errors must never become permission to
		// replace a version. Only explicit registry absence is bootstrappable.
		if !strings.Contains(message, "unauthorized") && !strings.Contains(message, "denied") &&
			(strings.Contains(message, "manifest unknown") || strings.Contains(message, "no such manifest") ||
				strings.HasSuffix(message, strings.ToLower(ref)+": not found")) {
			return "", false, nil
		}
		return "", false, errors.New("registry_manifest_lookup_failed")
	}
	var manifest struct {
		Digest string `json:"digest"`
	}
	if json.Unmarshal(out.Bytes(), &manifest) != nil || !registryDigestPattern.MatchString(manifest.Digest) {
		return "", false, errors.New("registry_manifest_digest_missing")
	}
	return imageRepositoryForPublication(ref) + "@" + manifest.Digest, true, nil
}

type stagedPublication struct {
	Release         string            `json:"release"`
	Commit          string            `json:"commit"`
	Source          string            `json:"source_digest"`
	Images          map[string]string `json:"images"`
	VersionedImages map[string]string `json:"versioned_images"`
}

type productionPublicationAcceptance struct {
	Release  string            `json:"release"`
	Commit   string            `json:"commit"`
	Source   string            `json:"source_digest"`
	Images   map[string]string `json:"images"`
	Accepted bool              `json:"accepted"`
}

var publicationRoles = []string{"central", "agent"}

func runPublication(ctx context.Context, c *deploy.Config, o publicationOptions, checks publicationChecks, factory publicationRegistryFactory) error {
	if o.Action != "stage" && o.Action != "publish" && o.Action != "publish-versioned" && o.Action != "promote-latest" {
		return errors.New("unknown_release_action")
	}
	r, err := readBuildReceipt(o.Root, o.Version)
	if err != nil {
		return err
	}
	if checks.Source == nil || checks.Verification == nil || checks.Signed == nil || factory == nil {
		return errPublicationGate
	}
	if err = checks.Source(ctx, r.Build); err != nil {
		return err
	}
	if err = checks.Verification(o.Verification, r.Build); err != nil {
		return err
	}
	var signed controlplane.ReleaseManifest
	if o.Action != "stage" {
		if o.Manifest == "" || o.Signature == "" || o.PublicKey == "" {
			return errPublicationGate
		}
		if signed, err = checks.Signed(o.Root, o.Manifest, o.Signature, o.PublicKey, o.Version); err != nil {
			return err
		}
	}
	prefix := strings.TrimSuffix(common.S(common.M(c.Raw["registry"])["prefix"]), "/")
	if prefix == "" {
		return errors.New("registry_prefix_required")
	}
	var staged stagedPublication
	_, priorStageErr := os.Stat(filepath.Join(o.Root, "staged-images.json"))
	if priorStageErr != nil && !os.IsNotExist(priorStageErr) {
		return errPublicationGate
	}
	hasPriorStage := priorStageErr == nil
	if hasPriorStage || o.Action == "publish-versioned" || o.Action == "promote-latest" {
		if staged, err = readStagedPublication(o.Root, prefix, r.Build); err != nil {
			return err
		}
		if o.Action != "stage" && !samePublicationImage(signed.Image, staged.Images["agent"]) {
			return errPublicationGate
		}
	}
	if o.Action == "promote-latest" {
		var accepted productionPublicationAcceptance
		if readReleaseJSON(o.ProductionVerification, &accepted) != nil || !accepted.Accepted || accepted.Release != r.Build.Release ||
			accepted.Commit != r.Build.Commit || accepted.Source != r.Build.Source {
			return errors.New("production_acceptance_required_before_latest")
		}
		for _, role := range publicationRoles {
			if accepted.Images[role] != staged.Images[role] {
				return errors.New("production_acceptance_image_mismatch")
			}
		}
	}
	base, err := os.ReadFile("config/base-images.lock")
	if err != nil {
		return err
	}
	d, err := factory(ctx, c)
	if err != nil {
		return err
	}
	defer d.Close()
	if o.Action == "stage" || o.Action == "publish" {
		for _, role := range publicationRoles {
			if err = checkPublicationImage(ctx, d, "webscan-"+role+":"+o.Version, role, r); err != nil {
				return err
			}
		}
	}
	remote := map[string]string{}
	// Check both version tags before the first registry mutation. A conflicting
	// immutable version is never overwritten, even if the other role is absent.
	for _, role := range publicationRoles {
		target := publicationTarget(prefix, role, o.Version)
		locked, exists, lookupErr := d.Lookup(ctx, target)
		if lookupErr != nil {
			return lookupErr
		}
		if hasPriorStage || o.Action == "publish-versioned" || o.Action == "promote-latest" {
			if !exists || locked != staged.Images[role] {
				return errors.New("published_version_digest_mismatch_" + role)
			}
		}
		if !exists {
			continue
		}
		if role == "agent" && o.Action != "stage" && !samePublicationImage(signed.Image, locked) {
			return errPublicationGate
		}
		if err = pullAndCheckPublicationImage(ctx, d, locked, role, r); err != nil {
			return errors.New("immutable_version_already_exists_with_different_image_" + role)
		}
		remote[role] = locked
	}
	if o.Action == "stage" || o.Action == "publish" {
		for _, role := range publicationRoles {
			if remote[role] != "" {
				continue
			}
			target := publicationTarget(prefix, role, o.Version)
			// Check once more immediately before push, including a tag created
			// concurrently during the all-role preflight.
			locked, exists, lookupErr := d.Lookup(ctx, target)
			if lookupErr != nil {
				return lookupErr
			}
			if exists {
				if pullAndCheckPublicationImage(ctx, d, locked, role, r) != nil {
					return errors.New("immutable_version_already_exists_with_different_image_" + role)
				}
			} else {
				fmt.Println("推送版本化自研镜像: " + role)
				if _, err = d.Exec(ctx, nil, "tag", r.Images[role], target); err != nil {
					return err
				}
				if _, err = d.Exec(ctx, nil, "push", target); err != nil {
					return errors.New("registry_push_failed_" + role)
				}
				locked, exists, lookupErr = d.Lookup(ctx, target)
				if lookupErr != nil || !exists || pullAndCheckPublicationImage(ctx, d, locked, role, r) != nil {
					return errors.New("published_manifest_digest_not_verified")
				}
			}
			remote[role] = locked
		}
		staged = stagedPublication{Release: o.Version, Commit: r.Build.Commit, Source: r.Build.Source,
			Images: remote, VersionedImages: map[string]string{}}
		for _, role := range publicationRoles {
			staged.VersionedImages[role] = publicationTarget(prefix, role, o.Version) + "@" + publicationImageDigest(remote[role])
		}
		if err = common.AtomicJSON(filepath.Join(o.Root, "staged-images.json"), staged); err != nil {
			return err
		}
	}
	if o.Action == "stage" {
		return nil
	}
	if !samePublicationImage(signed.Image, staged.Images["agent"]) {
		return errPublicationGate
	}
	latest := map[string]string{}
	if o.Action == "publish" || o.Action == "promote-latest" {
		if o.Action == "publish" {
			fmt.Println("兼容 publish 操作会同时更新 latest；分阶段发布请使用 publish-versioned，生产验收后使用 promote-latest")
		}
		for _, role := range publicationRoles {
			locked, exists, lookupErr := d.Lookup(ctx, publicationTarget(prefix, role, o.Version))
			if lookupErr != nil || !exists || locked != staged.Images[role] {
				return errors.New("published_version_digest_mismatch_" + role)
			}
		}
		for _, role := range publicationRoles {
			target := publicationTarget(prefix, role, "latest")
			fmt.Println("更新 latest 标签: " + role)
			if _, err = d.Exec(ctx, nil, "tag", staged.Images[role], target); err != nil {
				return err
			}
			if _, err = d.Exec(ctx, nil, "push", target); err != nil {
				return errors.New("registry_latest_push_failed_" + role)
			}
			locked, exists, lookupErr := d.Lookup(ctx, target)
			if lookupErr != nil || !exists || locked != staged.Images[role] {
				return errors.New("published_latest_digest_mismatch_" + role)
			}
			latest[role] = target
		}
	}
	report := common.Map{"release": o.Version, "commit": r.Build.Commit, "source_digest": r.Build.Source,
		"platform": "linux/amd64", "go": "1.26.3", "goframe": "2.10.3", "binary_sha256": r.Artifacts["webscan"],
		"native_package_sha256": r.Artifacts["agent-native.tar.gz"], "published_at": common.Stamp(), "images": staged.Images,
		"versioned_images": staged.VersionedImages, "latest": latest, "base_images": string(base), "action": o.Action}
	if err = common.AtomicJSON(filepath.Join(o.Root, "release.json"), report); err != nil {
		return err
	}
	fmt.Println("镜像摘要已保存至 " + filepath.Join(o.Root, "release.json"))
	return nil
}

func publicationTarget(prefix, role, version string) string {
	return prefix + "/webscan-" + role + ":" + version
}

func imageRepositoryForPublication(ref string) string {
	repo := strings.Split(ref, "@")[0]
	if colon := strings.LastIndex(repo, ":"); colon > strings.LastIndex(repo, "/") {
		repo = repo[:colon]
	}
	return repo
}

func publicationImageDigest(ref string) string {
	_, digest, _ := strings.Cut(ref, "@")
	if !registryDigestPattern.MatchString(digest) {
		return ""
	}
	return digest
}

func samePublicationImage(a, b string) bool {
	return publicationImageDigest(a) != "" && publicationImageDigest(a) == publicationImageDigest(b) &&
		publicationRepositoryKey(imageRepositoryForPublication(a)) == publicationRepositoryKey(imageRepositoryForPublication(b))
}

func publicationRepositoryKey(repo string) string {
	for _, alias := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		if strings.HasPrefix(repo, alias) {
			repo = strings.TrimPrefix(repo, alias)
			break
		}
	}
	if !strings.Contains(repo, "/") {
		return "library/" + repo
	}
	return repo
}

func checkPublicationImage(ctx context.Context, d publicationRegistry, ref, role string, r imageBuildReceipt) error {
	raw, err := d.Exec(ctx, nil, "image", "inspect", "--format", "{{.Id}}/{{index .Config.Labels \"org.opencontainers.image.version\"}}/{{index .Config.Labels \"org.opencontainers.image.revision\"}}/{{index .Config.Labels \"io.webscan.source.digest\"}}", ref)
	if err != nil || strings.TrimSpace(string(raw)) != r.Images[role]+"/"+r.Build.Release+"/"+r.Build.Commit+"/"+r.Build.Source {
		return errPublicationGate
	}
	return nil
}

func pullAndCheckPublicationImage(ctx context.Context, d publicationRegistry, ref, role string, r imageBuildReceipt) error {
	if publicationImageDigest(ref) == "" {
		return errPublicationGate
	}
	if _, err := d.Exec(ctx, nil, "pull", "--platform", "linux/amd64", ref); err != nil {
		return err
	}
	return checkPublicationImage(ctx, d, ref, role, r)
}

func readStagedPublication(root, prefix string, b buildRecord) (stagedPublication, error) {
	var s stagedPublication
	if readReleaseJSON(filepath.Join(root, "staged-images.json"), &s) != nil || s.Release != b.Release || s.Commit != b.Commit || s.Source != b.Source {
		return s, errPublicationGate
	}
	for _, role := range publicationRoles {
		if publicationImageDigest(s.Images[role]) == "" || imageRepositoryForPublication(s.Images[role]) != prefix+"/webscan-"+role ||
			s.VersionedImages[role] != publicationTarget(prefix, role, b.Release)+"@"+publicationImageDigest(s.Images[role]) {
			return s, errPublicationGate
		}
	}
	return s, nil
}
