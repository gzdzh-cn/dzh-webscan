package nodeops

import (
	"strings"
	"testing"
)

func boundCommandRequest(t *testing.T, mode string) Request {
	t.Helper()
	r := testRequest(testRoot(t))
	r.Spec.Mode = mode
	r.Spec.Release = "v3.0.0-local-test"
	r.Spec.BundleSHA256 = strings.Repeat("b", 64)
	r.Spec.ArtifactBytes = 100
	r.Spec.RuntimeSHA256 = strings.Repeat("c", 64)
	r.Spec.RuntimeBytes = 200
	r.Spec.ConfigVersion = 2
	r.Spec.ConfigSourceSHA256 = strings.Repeat("d", 64)
	r.Spec.ServerName = "node.test"
	if mode == "docker" {
		r.Spec.AgentImage = "docker.io/example/agent@sha256:" + strings.Repeat("e", 64)
	}
	return r
}

func TestLifecycleCommandSelectsRealHandlersAndRequiresBoundConfiguration(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			r := boundCommandRequest(t, mode)
			h, err := lifecycleHandler(r)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "native" {
				if n, ok := h.(*nativeLifecycle); !ok || !n.valid(r) || n.runtime.root != DeploymentRoot || n.activation.host.unitPath != nativeUnitPath {
					t.Fatal("not the actual native handler")
				}
			} else {
				if d, ok := h.(*dockerLifecycle); !ok || !d.valid(r) || d.runtime.root != DeploymentRoot || d.activation.host.unitPath != nativeUnitPath {
					t.Fatal("not the actual Docker handler")
				}
			}
			for _, phase := range append(append([]string{}, forward...), rollback...) {
				if !h.Supports(phase) {
					t.Fatal("missing lifecycle phase", phase)
				}
			}
			if h.Supports("arbitrary-command") {
				t.Fatal("unknown phase accepted")
			}
			for _, change := range []func(*Request){func(r *Request) { r.Spec.RuntimeSHA256 = "" }, func(r *Request) { r.Spec.ConfigVersion = 0 }, func(r *Request) { r.Spec.ConfigSourceSHA256 = "" }, func(r *Request) { r.Spec.Mode = "unknown" }, func(r *Request) { r.Spec.ServerName = "" }, func(r *Request) { r.Spec.BundleSHA256 = "" }} {
				bad := r
				change(&bad)
				if _, err := lifecycleHandler(bad); err == nil {
					t.Fatal("incomplete binding allowed")
				}
			}
			if mode == "docker" {
				r.Spec.AgentImage = ""
				if _, err := lifecycleHandler(r); err == nil {
					t.Fatal("Docker lifecycle without immutable image")
				}
			}
		})
	}
	// Existing preparation clients keep their original no-service boundary.
	prep := NewLocalRuntime()
	if prep.Supports("backup") || prep.Supports("activate") || prep.Supports("restore") {
		t.Fatal("default command can mutate services")
	}
}
