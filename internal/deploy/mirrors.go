package deploy

import (
	"net/url"
	"strings"
	"webscan/internal/common"
)

// Docker Hub mirrors never receive the custom registry's credentials. Digests
// are retained verbatim when remapping a previously locked reference.
func pullCandidates(c *Config, image string) []string {
	if c == nil {
		return []string{image}
	}
	reg := common.M(c.Raw["registry"])
	privateHost := strings.Split(common.S(reg["prefix"]), "/")[0]
	if common.B(reg["auth_required"]) && privateHost != "" && strings.HasPrefix(image, privateHost+"/") {
		return []string{image}
	}
	mirrors := common.SS(reg["mirrors"])
	upstream := image
	for _, mirror := range mirrors {
		u, _ := url.Parse(mirror)
		if u != nil && strings.HasPrefix(upstream, u.Host+"/") {
			upstream = strings.TrimPrefix(upstream, u.Host+"/")
			break
		}
	}
	upstream = strings.TrimPrefix(strings.TrimPrefix(upstream, "docker.io/"), "index.docker.io/")
	first, _, hasSlash := strings.Cut(upstream, "/")
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return []string{image}
	}
	if !hasSlash {
		upstream = "library/" + upstream
	}
	out := []string{}
	seen := map[string]bool{}
	for _, mirror := range mirrors {
		u, _ := url.Parse(mirror)
		if u != nil {
			candidate := u.Host + "/" + upstream
			if !seen[candidate] {
				out = append(out, candidate)
				seen[candidate] = true
			}
		}
	}
	canonical := "docker.io/" + upstream
	return append(out, canonical)
}
