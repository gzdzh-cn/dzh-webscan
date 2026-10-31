package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRetirementCheckpointCommandKeepsPrivateFilesAndBoundContext(t *testing.T) {
	s, input := nodeHistoryRetirementFixture(t)
	f := newConfigurationLocalFixture(t)
	ctx := context.Background()
	confirmNodeHistoryRetirement(t, s, input, "command-retirement")
	output := filepath.Join(privateTestDir(t), "checkpoint")
	var receipt bytes.Buffer
	options := Options{Action: "export-node-retirements", Username: "admin", Output: output}
	if err := s.localRetirementCheckpointCommand(ctx, f.c, options, &receipt); err != nil {
		t.Fatal("export command", err)
	}
	var result struct {
		SHA256  string `json:"checkpoint_sha256"`
		Cutover bool   `json:"cutover_authorized"`
	}
	file := filepath.Join(output, "retirements.json")
	data, err := readTrustData(file, true, maxRetirementCheckpointBytes)
	if err != nil || json.Unmarshal(receipt.Bytes(), &result) != nil || digest(data) != result.SHA256 || result.Cutover {
		t.Fatal("private checkpoint/receipt not verified", err)
	}
	if err := s.localRetirementCheckpointCommand(ctx, f.c, options, &bytes.Buffer{}); err == nil {
		t.Fatal("export overwrote an existing directory")
	}
	request := filepath.Join(privateTestDir(t), "request.json")
	raw, _ := json.Marshal(map[string]any{"checkpoint_file": file, "checkpoint_sha256": result.SHA256, "confirm": true})
	localWrite(t, request, raw)
	options = Options{Action: "reconcile-node-retirements", Username: "admin", RequestKey: "command-checkpoint-reconcile", Source: request}
	receipt.Reset()
	if err := s.localRetirementCheckpointCommand(ctx, f.c, options, &receipt); err != nil {
		t.Fatal("reconcile command", err)
	}
	var reconciled retirementReconcileResult
	if json.Unmarshal(receipt.Bytes(), &reconciled) != nil || reconciled.Existing != 1 || reconciled.Imported != 0 || reconciled.CutoverAuthorized {
		t.Fatal("command changed existing retirement or authorized cutover")
	}
	for _, scenario := range []string{"wrong-instance", "viewer", "no-key", "public-request", "duplicate", "symlink-checkpoint", "wrong-ca"} {
		t.Run(scenario, func(t *testing.T) {
			config, op := f.c, options
			localWrite(t, request, raw)
			switch scenario {
			case "wrong-instance":
				config.Central.Instance = "other-center"
			case "viewer":
				op.Username = "viewer"
			case "no-key":
				op.RequestKey = ""
			case "public-request":
				if err := os.Chmod(request, 0644); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(request, 0600)
			case "duplicate":
				localWrite(t, request, append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"confirm":true}`)...))
			case "symlink-checkpoint":
				link := filepath.Join(privateTestDir(t), "link")
				if err := os.Symlink(file, link); err != nil {
					t.Fatal(err)
				}
				bad, _ := json.Marshal(map[string]any{"checkpoint_file": link, "checkpoint_sha256": result.SHA256, "confirm": true})
				localWrite(t, request, bad)
			case "wrong-ca":
				config.Collector.CAFile = filepath.Join(privateTestDir(t), "other-ca")
				localWrite(t, config.Collector.CAFile, f.collector.Certificate)
			}
			var out bytes.Buffer
			if err := s.localRetirementCheckpointCommand(ctx, config, op, &out); err == nil || out.Len() != 0 {
				t.Fatal("invalid command replay accepted")
			}
		})
	}
}
