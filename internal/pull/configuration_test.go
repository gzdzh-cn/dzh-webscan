package pull

import (
	"context"
	"strings"
	"testing"

	agentv1 "webscan/sdk/agent/v1"
)

func TestCapabilitiesReportRunningConfigurationWithoutChangingLegacyContract(t *testing.T) {
	source := testSource(t)
	legacy := source.Capabilities()
	if legacy.ConfigurationVersion != 0 || legacy.ConfigurationSha256 != "" {
		t.Fatal("legacy source claimed an effective version")
	}
	config := Configuration{Version: 9007199254740993, SHA256: strings.Repeat("a", 64)}
	current, err := New(source.DB, "node-a", "v3.0.0", source.WriteMu, config)
	if err != nil {
		t.Fatal(err)
	}
	config.Version++
	reported, err := (&Server{Source: current}).Capabilities(context.Background(), &agentv1.CapabilitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if reported.ConfigurationVersion != 9007199254740993 || reported.ConfigurationSha256 != strings.Repeat("a", 64) || reported.Protocol != agentv1.ProtocolVersion {
		t.Fatal("running config acknowledgement changed or rounded")
	}
	for _, bad := range []Configuration{{Version: 0, SHA256: strings.Repeat("a", 64)}, {Version: 1, SHA256: ""}, {Version: 1, SHA256: strings.Repeat("A", 64)}} {
		if _, err := New(source.DB, "node-a", "v3", source.WriteMu, bad); err == nil {
			t.Fatal("invalid config acknowledgement accepted")
		}
	}
	if _, err := New(source.DB, "node-a", "v3", source.WriteMu, config, config); err == nil {
		t.Fatal("ambiguous config acknowledgements accepted")
	}
}
