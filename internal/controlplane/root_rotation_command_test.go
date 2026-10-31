package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestRootCommandRequiresExplicitConfirmationAndKeepsPublicStatus(t *testing.T) {
	f, members := rootTaskFixture(t)
	ctx := context.Background()
	file := filepath.Join(privateTestDir(t), "root-command.json")
	input := rootRotationFile{Members: members}
	writeProvisioningInput(t, file, input)
	options := Options{Action: "prepare-root-rotation", Username: "admin", RequestKey: "root-cli-prepare", Source: file}
	var out bytes.Buffer
	if err := f.s.localRootRotationCommand(ctx, f.c, options, &out); err == nil || tableCount(t, f.s, "v3_root_rotations") != 0 {
		t.Fatal("unconfirmed CLI created root task")
	}
	input.Confirm = true
	writeProvisioningInput(t, file, input)
	options.Username = "viewer"
	if err := f.s.localRootRotationCommand(ctx, f.c, options, &out); err == nil {
		t.Fatal("viewer created root task")
	}
	options.Username = "admin"
	if err := f.s.localRootRotationCommand(ctx, f.c, options, &out); err != nil {
		t.Fatal("confirmed host preparation", err)
	}
	var view rootRotationView
	if json.Unmarshal(out.Bytes(), &view) != nil || view.Status != "prepared" || len(view.Members) != 2 {
		t.Fatal("invalid public task view")
	}
	for _, secret := range []string{f.c.NodePKI.AuthorityDirectory, f.c.DeploymentTrust.VaultKeyFile, members[0].Credential, "PRIVATE KEY", "certificate"} {
		if bytes.Contains(out.Bytes(), []byte(secret)) {
			t.Fatal("host material leaked in root view")
		}
	}
	writeProvisioningInput(t, file, rootRotationFile{ID: view.ID})
	options.Action, options.RequestKey = "root-rotation-status", ""
	out.Reset()
	if err := f.s.localRootRotationCommand(ctx, f.c, options, &out); err != nil {
		t.Fatal("read-only status required write confirmation", err)
	}
	options.Action = "run-root-rotation"
	if err := f.s.localRootRotationCommand(ctx, f.c, options, &out); err == nil {
		t.Fatal("run accepted unconfirmed input")
	}
	writeProvisioningInput(t, file, rootRotationFile{ID: view.ID, Confirm: true})
	options.Action, options.RequestKey = "cancel-root-rotation", "root-cli-cancel"
	out.Reset()
	if err := f.s.localRootRotationCommand(ctx, f.c, options, &out); err != nil {
		t.Fatal("prepared task cancellation", err)
	}
	if json.Unmarshal(out.Bytes(), &view) != nil || view.Status != "canceled" {
		t.Fatal("cancellation not reflected")
	}
}
