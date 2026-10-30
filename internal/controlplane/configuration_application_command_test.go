package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigurationApplicationLocalCommandQueueControlAndReplay(t *testing.T) {
	s, f, stage, revision := workerSourceFixture(t, false)
	ctx := context.Background()
	source := filepath.Join(f.f.root, "application.json")
	localWrite(t, source, []byte(fmt.Sprintf(`{"stage":%q,"generation":"%d","confirm":true}`, stage.ID, revision.Generation)))
	op := Options{Action: "queue-configuration-application", Username: "admin", RequestKey: "cli-queue", Source: source}
	var out, replay bytes.Buffer
	if err := s.localConfigurationApplicationCommand(ctx, f.c, op, &out); err != nil {
		t.Fatal(err)
	}
	job := applicationReceipt(t, out.Bytes(), nil)
	if err := s.localConfigurationApplicationCommand(ctx, f.c, op, &replay); err != nil || !sameProvisioningResponse(out.Bytes(), replay.Bytes()) {
		t.Fatal("queue replay changed receipt", err)
	}
	p := claimApplicationForTest(t, s, f, "local-command-worker")
	if err := s.failConfigurationApplication(ctx, f.v, p, "environment-failed"); err != nil {
		t.Fatal(err)
	}
	localWrite(t, source, []byte(fmt.Sprintf(`{"id":%q,"action":"resume","confirm":true}`, job.ID)))
	op.Action, op.RequestKey = "control-configuration-application", "cli-resume"
	out.Reset()
	if err := s.localConfigurationApplicationCommand(ctx, f.c, op, &out); err != nil {
		t.Fatal(err)
	}
	if resumed := applicationReceipt(t, out.Bytes(), nil); resumed.ID != job.ID || resumed.Status != "queued" {
		t.Fatal("resume created unrelated work")
	}
	// Harmless queued work can be cancelled with the worker disabled.
	f.c.Executor.ApplicationsEnabled = false
	localWrite(t, source, []byte(fmt.Sprintf(`{"id":%q,"action":"cancel","confirm":true}`, job.ID)))
	op.RequestKey = "cli-cancel"
	out.Reset()
	if err := s.localConfigurationApplicationCommand(ctx, f.c, op, &out); err != nil {
		t.Fatal(err)
	}
	if cancelled := applicationReceipt(t, out.Bytes(), nil); cancelled.Status != "cancelled" || cancelled.RecoveryRequired {
		t.Fatal("cancelled harmless work incorrectly")
	}
	if tableCount(t, s, "v3_configuration_applications") != 1 || tableCount(t, s, "v3_deployment_jobs") != 0 {
		t.Fatal("local control deployed or duplicated work")
	}
	for _, secret := range []string{f.f.root, p.planProof, p.stateProof, p.sourceProof, "private-dsn-password"} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("local receipt exposed private plan")
		}
	}
}

func TestConfigurationApplicationLocalCommandRejectsInputAndAuthority(t *testing.T) {
	s, f, stage, revision := workerSourceFixture(t, false)
	source := filepath.Join(f.f.root, "rejected.json")
	valid := fmt.Sprintf(`{"stage":%q,"generation":"%d","confirm":true}`, stage.ID, revision.Generation)
	for _, tc := range []struct {
		name, raw, user, key string
		disabled             bool
	}{
		{"missing-confirm", fmt.Sprintf(`{"stage":%q,"generation":"%d"}`, stage.ID, revision.Generation), "admin", "reject", false},
		{"unknown-field", strings.TrimSuffix(valid, "}") + `,"command":"private-secret"}`, "admin", "reject", false},
		{"duplicate", strings.TrimSuffix(valid, "}") + `,"confirm":true}`, "admin", "reject", false},
		{"numeric-generation", strings.Replace(valid, fmt.Sprintf(`"%d"`, revision.Generation), fmt.Sprint(revision.Generation), 1), "admin", "reject", false},
		{"stale-generation", fmt.Sprintf(`{"stage":%q,"generation":"%d","confirm":true}`, stage.ID, revision.Generation+1), "admin", "reject", false},
		{"disabled", valid, "admin", "reject", true},
		{"missing-account", valid, "absent", "reject", false},
		{"missing-key", valid, "admin", "", false},
		{"unsafe-key", valid, "admin", "../bad", false},
		{"second-object", valid + `{}`, "admin", "reject", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			localWrite(t, source, []byte(tc.raw))
			c := f.c
			c.Executor.ApplicationsEnabled = !tc.disabled
			var out bytes.Buffer
			err := s.localConfigurationApplicationCommand(context.Background(), c, Options{Action: "queue-configuration-application", Username: tc.user, RequestKey: tc.key, Source: source}, &out)
			if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private-secret") {
				t.Fatal("invalid request accepted or exposed input")
			}
			if tableCount(t, s, "v3_configuration_applications") != 0 {
				t.Fatal("rejected request created job")
			}
		})
	}
	localWrite(t, source, []byte(valid))
	if err := os.Chmod(source, 0644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	op := Options{Action: "queue-configuration-application", Username: "admin", RequestKey: "public-file", Source: source}
	if err := s.localConfigurationApplicationCommand(context.Background(), f.c, op, &out); err == nil || out.Len() != 0 {
		t.Fatal("world-readable input accepted")
	}
	if err := os.Chmod(source, 0600); err != nil {
		t.Fatal(err)
	}
	link := source + ".link"
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	op.Source = link
	if err := s.localConfigurationApplicationCommand(context.Background(), f.c, op, &out); err == nil {
		t.Fatal("symlink input accepted")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
	op.Source = source
	if err := s.localConfigurationApplicationCommand(context.Background(), f.c, op, &out); err == nil {
		t.Fatal("viewer queued application")
	}
}

func TestConfigurationApplicationLocalCommandLoadsConfiguration(t *testing.T) {
	s, f, stage, revision := workerSourceFixture(t, false)
	raw, err := yaml.Marshal(f.c)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(f.f.root, "command-control.yaml")
	localWrite(t, config, raw)
	source := filepath.Join(f.f.root, "command-queue.json")
	localWrite(t, source, []byte(fmt.Sprintf(`{"stage":%q,"generation":"%d","confirm":true}`, stage.ID, revision.Generation)))
	var out bytes.Buffer
	op := Options{Config: config, Action: "queue-configuration-application", Username: "admin", RequestKey: "real-command-queue", Source: source}
	if err = Command(context.Background(), op, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	job := applicationReceipt(t, out.Bytes(), nil)
	localWrite(t, source, []byte(fmt.Sprintf(`{"id":%q,"action":"cancel","confirm":true}`, job.ID)))
	op.Action, op.RequestKey = "control-configuration-application", "real-command-cancel"
	out.Reset()
	if err = Command(context.Background(), op, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	var done configurationApplicationJob
	if json.Unmarshal(out.Bytes(), &done) != nil || done.Status != "cancelled" || tableCount(t, s, "v3_configuration_applications") != 1 {
		t.Fatal("real command did not recover original task")
	}
}

func TestConfigurationApplicationLocalCommandRollbackPreservesRecovery(t *testing.T) {
	s, f, _ := workerSavedFixture(t, false)
	p := claimApplicationForTest(t, s, f, "rollback-command-worker")
	var err error
	p, err = s.checkpointConfigurationApplication(context.Background(), f.v, p, applicationComplete(p))
	if err != nil {
		t.Fatal(err)
	}
	p = claimApplicationForTest(t, s, f, "rollback-command-worker")
	p, err = s.armConfigurationApplication(context.Background(), f.v, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.failConfigurationApplication(context.Background(), f.v, p, "deployment-failed"); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(f.f.root, "rollback-command.json")
	op := Options{Action: "control-configuration-application", Username: "admin", RequestKey: "command-rollback", Source: source}
	var out bytes.Buffer
	for _, action := range []string{"cancel", "rollback"} {
		localWrite(t, source, []byte(fmt.Sprintf(`{"id":%q,"action":%q,"confirm":true}`, p.ID, action)))
		err = s.localConfigurationApplicationCommand(context.Background(), f.c, op, &out)
		if action == "cancel" {
			if err == nil || out.Len() != 0 {
				t.Fatal("cancel discarded rollback responsibility")
			}
		} else {
			job := applicationReceipt(t, out.Bytes(), err)
			if job.Direction != "rollback" || job.Status != "queued" || !job.RecoveryRequired {
				t.Fatal("rollback released recovery before verification")
			}
		}
	}
}
