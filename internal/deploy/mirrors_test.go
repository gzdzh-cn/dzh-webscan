package deploy

import (
	"reflect"
	"testing"
	"webscan/internal/common"
)

func TestPublicHubProjectUsesConfiguredMirrors(t *testing.T) {
	c := fixture(t)
	reg := common.M(c.Raw["registry"])
	reg["prefix"] = "docker.io/gzdzh"
	reg["auth_required"] = false
	reg["mirrors"] = []string{"https://mirror.example", "https://backup.example"}
	for _, role := range []string{"central", "agent"} {
		for _, suffix := range []string{":latest", ":v2.0.28", "@sha256:abc"} {
			path := "gzdzh/webscan-" + role + suffix
			want := []string{"mirror.example/" + path, "backup.example/" + path, "docker.io/" + path}
			if got := pullCandidates(c, "docker.io/"+path); !reflect.DeepEqual(got, want) {
				t.Fatalf("public project candidates: got %v, want %v", got, want)
			}
		}
	}
	reg["auth_required"] = true
	image := "docker.io/gzdzh/webscan-agent:latest"
	if got := pullCandidates(c, image); !reflect.DeepEqual(got, []string{image}) {
		t.Fatalf("authenticated project must bypass anonymous mirrors: %v", got)
	}
}

func TestAnonymousCustomRegistryDoesNotUseHubMirrors(t *testing.T) {
	c := fixture(t)
	reg := common.M(c.Raw["registry"])
	reg["prefix"] = "registry.example/team"
	reg["auth_required"] = false
	reg["mirrors"] = []string{"https://mirror.example"}
	image := "registry.example/team/webscan-agent:latest"
	if got := pullCandidates(c, image); !reflect.DeepEqual(got, []string{image}) {
		t.Fatalf("custom registry was remapped to Docker Hub: %v", got)
	}
}
