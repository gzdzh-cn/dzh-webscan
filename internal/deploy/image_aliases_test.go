package deploy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"webscan/internal/common"
)

func TestReadableContainerImagesKeepImmutableLocks(t *testing.T) {
	c := fixture(t)
	common.M(c.Raw["images"])["central"] = "webscan-central:latest"
	common.M(c.Raw["images"])["agent"] = "webscan-agent:latest"
	for _, role := range []string{"central", "agent", "prometheus"} {
		locked := "mirror.example.test/team/" + role + "@sha256:" + strings.Repeat("a", 64)
		s := imageService(c, role, locked)
		if strings.Contains(common.S(s["image"]), "@") || lockedServiceImage(s) != locked || s["pull_policy"] != "never" {
			t.Fatal("readable alias discarded the immutable identity", s)
		}
		if role != "prometheus" && !strings.HasSuffix(common.S(s["image"]), ":latest") {
			t.Fatal("custom service did not display latest", s)
		}
	}
}

func TestRetainedVendorImagesShowVersionsWithoutChangingContent(t *testing.T) {
	c := fixture(t)
	services, pending := common.Map{}, common.Map{}
	for _, role := range []string{"prometheus", "alertmanager", "grafana", "loki", "exporter"} {
		name := role
		if role == "exporter" {
			name = "host-exporter"
		}
		services[name] = common.Map{"image": "mirror.example.test/" + role + "@sha256:" + strings.Repeat("a", 64), "volumes": []string{"/data:/data"}, "labels": common.Map{"custom": "preserved"}}
		pending[role] = "other.example.test/" + role + "@sha256:" + strings.Repeat("b", 64)
	}
	services["manual"] = common.Map{"image": "custom/app:old"}
	if names := updateVendorImageAliases(c, services, pending, false); len(names) != 5 {
		t.Fatal("retained components weren't migrated", names)
	}
	for name, value := range services {
		if name == "manual" {
			if common.S(common.M(value)["image"]) != "custom/app:old" {
				t.Fatal("unrelated service changed")
			}
			continue
		}
		role := name
		if name == "host-exporter" {
			role = "exporter"
		}
		s := common.M(value)
		if common.S(s["image"]) != "docker.io/"+VendorImages[role] || lockedServiceImage(s) != "mirror.example.test/"+role+"@sha256:"+strings.Repeat("a", 64) || common.S(common.M(s["labels"])["custom"]) != "preserved" || common.SS(s["volumes"])[0] != "/data:/data" {
			t.Fatal("display migration changed content or configuration", s)
		}
	}
	if names := updateVendorImageAliases(c, services, pending, false); len(names) != 0 {
		t.Fatal("already migrated components needlessly recreated", names)
	}
	if names := updateVendorImageAliases(c, services, pending, true); len(names) != 5 {
		t.Fatal("explicit component upgrade ignored", names)
	}
	if lockedServiceImage(common.M(services["grafana"])) != common.S(pending["grafana"]) {
		t.Fatal("explicit component upgrade retained old image")
	}
}

func TestRestoredComposeRetagsOriginalImageAfterLatestMoved(t *testing.T) {
	c := fixture(t)
	common.M(c.Raw["images"])["agent"] = "webscan-agent:latest"
	oldID, newID := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	locked := "registry.example.test/team/agent@sha256:" + strings.Repeat("c", 64)
	s := imageService(c, "agent", locked)
	alias := common.S(s["image"])
	local := map[string]string{locked: oldID, alias: newID}
	compose := common.Map{"services": common.Map{"agent": s}}
	var calls []string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[1] {
		case "inspect":
			return []byte(local[args[len(args)-1]] + "\n"), nil
		case "tag":
			local[args[3]] = args[2]
			return nil, nil
		}
		return nil, errors.New("unexpected Docker command")
	}
	if err := pinComposeImages(context.Background(), compose, run); err != nil {
		t.Fatal(err)
	}
	if local[alias] != oldID || len(calls) != 3 || strings.Contains(strings.Join(calls, "\n"), "pull") {
		t.Fatal("rollback used a moved latest or contacted the registry", calls)
	}
	// A missing old image must fail rather than substituting the new latest.
	runMissing := func(_ context.Context, _ ...string) ([]byte, error) { return nil, errors.New("missing") }
	if err := pinComposeImages(context.Background(), compose, runMissing); err == nil || err.Error() != "runtime_locked_image_unavailable" {
		t.Fatal("missing backup image silently substituted", err)
	}
	// A concurrent retag must be detected before creating a container.
	runMoved := func(_ context.Context, args ...string) ([]byte, error) {
		if args[1] == "tag" {
			return nil, nil
		}
		if args[len(args)-1] == alias {
			return []byte(newID), nil
		}
		return []byte(oldID), nil
	}
	if err := pinComposeImages(context.Background(), compose, runMoved); err == nil || err.Error() != "runtime_image_alias_identity_mismatch" {
		t.Fatal("moved alias not detected", err)
	}
}

func TestStandaloneComposeCanPullLatestOnFreshHost(t *testing.T) {
	c := fixture(t)
	image := "docker.io/gzdzh/webscan-central@sha256:" + strings.Repeat("a", 64)
	s := imageService(c, "central", image)
	standaloneImage(s, image)
	if s["image"] != image {
		t.Fatal("offline explicit reference changed")
	}
	if _, exists := s["pull_policy"]; exists {
		t.Fatal("fresh package cannot download")
	}
	if common.S(common.M(s["labels"])[imageLockLabel]) != "" {
		t.Fatal("offline package pretended to lock a local image")
	}
}

func TestRealDockerAliasShowsLatestAndRetainsSavedImage(t *testing.T) {
	version := os.Getenv("WEBSCAN_IMAGE_VERSION")
	if version == "" {
		t.Skip("requires built release images")
	}
	ctx := context.Background()
	source := "webscan-central:" + version
	b, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", source).Output()
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(string(b))
	alias := "webscan-test/central-" + common.ID() + ":latest"
	defer exec.Command("docker", "image", "rm", alias).Run()
	compose := common.Map{"services": common.Map{"receiver": common.Map{"image": alias, "labels": common.Map{imageLockLabel: id}}}}
	if err = pinComposeImages(ctx, compose, func(ctx context.Context, args ...string) ([]byte, error) {
		return RunCommand(ctx, nil, append([]string{"docker"}, args...)...)
	}); err != nil {
		t.Fatal(err)
	}
	name := "webscan-alias-test-" + common.ID()
	defer exec.Command("docker", "rm", "-f", name).Run()
	if out, err := exec.Command("docker", "create", "--platform", "linux/amd64", "--pull", "never", "--name", name, alias, "version").CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	b, err = exec.Command("docker", "inspect", "--format", "{{.Config.Image}} {{.Image}}", name).Output()
	if err != nil || strings.TrimSpace(string(b)) != alias+" "+id {
		t.Fatal("Docker did not retain a short name and pinned ID", err, string(b))
	}
	b, err = exec.Command("docker", "start", "-a", name).Output()
	if err != nil || strings.TrimSpace(string(b)) != version {
		t.Fatal("unexpected actual binary version", err, string(b))
	}
}
