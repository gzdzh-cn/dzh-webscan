package config

import (
	"errors"
	"net/url"
	"strings"
)

func ValidateMirrors(mirrors []string) error {
	if len(mirrors) > 8 {
		return errors.New("too_many_registry_mirrors")
	}
	seen := map[string]bool{}
	for _, mirror := range mirrors {
		u, err := url.Parse(mirror)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(u.Host, " \t\r\n") {
			return errors.New("registry_mirror_requires_https_origin")
		}
		if seen[u.Host] {
			return errors.New("duplicate_registry_mirror")
		}
		seen[u.Host] = true
	}
	return nil
}
