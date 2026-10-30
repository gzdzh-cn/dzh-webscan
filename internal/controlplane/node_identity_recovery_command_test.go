package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func recoveryCommandSource(t *testing.T, f identityRecoveryFixture, input any) string {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(f.identity), "recovery-command.json")
	localWrite(t, path, raw)
	return path
}

func TestNodeIdentityRecoveryLocalCommandPreparationStatusAndCancel(t *testing.T) {
	f := newIdentityRecoveryFixture(t)
	ctx := context.Background()
	in := nodeIdentityRecoveryPreparationFile{Node: f.input.Node, Expected: f.input.Expected, Credential: f.input.Credential, CertificatePEM: string(f.input.Certificate), LifetimeHours: f.input.LifetimeHours, Confirm: true}
	o := Options{Action: "prepare-node-identity-recovery", Username: "admin", RequestKey: "recover-identity", Source: recoveryCommandSource(t, f, in)}
	var out, replay bytes.Buffer
	if err := f.s.localNodeIdentityRecoveryCommand(ctx, f.c, o, &out); err != nil {
		t.Fatal(err)
	}
	if err := f.s.localNodeIdentityRecoveryCommand(ctx, f.c, o, &replay); err != nil || !sameProvisioningResponse(out.Bytes(), replay.Bytes()) {
		t.Fatal("prepare replay", err)
	}
	var view nodeIdentityRecoveryView
	if err := json.Unmarshal(out.Bytes(), &view); err != nil || view.ID != f.job.ID || view.Status != "prepared" || view.Expired {
		t.Fatal("wrong preparation receipt", err)
	}
	if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
		t.Fatal("prepare signed identity")
	}
	o.Source = recoveryCommandSource(t, f, nodeIdentityRecoveryTargetFile{ID: view.ID})
	o.Action = "node-identity-recovery-status"
	out.Reset()
	if err := f.s.localNodeIdentityRecoveryCommand(ctx, f.c, o, &out); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.in.Credential, f.identity, f.c.Collector.CAFile, "PRIVATE KEY", "certificate_pem", "request_sha256", "actor_revision", "password"} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("status exposed private material", secret)
		}
	}
	o.Source = recoveryCommandSource(t, f, nodeIdentityRecoveryTargetFile{ID: view.ID, Confirm: true})
	o.Action = "cancel-node-identity-recovery"
	o.RequestKey = "cli-cancel-recovery"
	out.Reset()
	if err := f.s.localNodeIdentityRecoveryCommand(ctx, f.c, o, &out); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(out.Bytes(), &view) != nil || view.Status != "canceled" || view.Expired {
		t.Fatal("cancel status incorrect")
	}
	if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
		t.Fatal("status/cancel signed identity")
	}
}

func TestNodeIdentityRecoveryLocalCommandRejectsUnboundOrUnsafeInput(t *testing.T) {
	f := newIdentityRecoveryFixture(t)
	path := recoveryCommandSource(t, f, nodeIdentityRecoveryTargetFile{ID: f.job.ID, Confirm: true})
	valid, _ := os.ReadFile(path)
	for _, scenario := range []string{"unknown", "duplicate", "trailing", "no-confirm", "other-user", "viewer", "missing-key", "public-file", "link", "wrong-id", "invalid-json"} {
		t.Run(scenario, func(t *testing.T) {
			raw := append([]byte(nil), valid...)
			o := Options{Action: "cancel-node-identity-recovery", Username: "admin", RequestKey: "must-not-cancel", Source: path}
			switch scenario {
			case "unknown":
				raw = append(raw[:len(raw)-1], []byte(`,"password":"isolated-private-input"}`)...)
			case "duplicate":
				raw = append(raw[:len(raw)-1], []byte(`,"confirm":true}`)...)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "no-confirm":
				raw = []byte(`{"id":"` + f.job.ID + `"}`)
			case "other-user":
				o.Username = "absent-admin"
			case "viewer":
				o.Username = "viewer"
			case "missing-key":
				o.RequestKey = ""
			case "wrong-id":
				raw = []byte(`{"id":"absent-task","confirm":true}`)
			case "invalid-json":
				raw = []byte(`{"confirm":`)
			}
			localWrite(t, path, raw)
			if scenario == "public-file" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(path, 0600)
			}
			if scenario == "link" {
				o.Source = path + ".link"
				if err := os.Symlink(path, o.Source); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			err := f.s.localNodeIdentityRecoveryCommand(context.Background(), f.c, o, &out)
			if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "isolated-private-input") {
				t.Fatal("invalid request accepted or echoed", err)
			}
			j, err := f.s.nodeIdentityRecovery(context.Background(), f.t.vault, f.job.ID)
			if err != nil || j.Status != "prepared" || tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("rejected command mutated task", err)
			}
		})
	}
}

func TestNodeIdentityRecoveryHistoricalStatusIsNotRunAuthorization(t *testing.T) {
	for _, scenario := range []string{"expired", "canceled", "completed"} {
		t.Run(scenario, func(t *testing.T) {
			w, r := newRecoveryRunner(t)
			f := r.f
			if scenario == "completed" {
				if err := w.run(context.Background(), "admin", f.job.ID, func(identityRecoveryProgress) error { return nil }); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "canceled" {
				if _, err := f.s.cancelNodeIdentityRecovery(context.Background(), "admin", "historical-cancel", f.job.ID); err != nil {
					t.Fatal(err)
				}
			} else {
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_identity_recoveries SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.job.ID)
			}
			o := Options{Action: "node-identity-recovery-status", Username: "admin", Source: recoveryCommandSource(t, f, nodeIdentityRecoveryTargetFile{ID: f.job.ID})}
			var out bytes.Buffer
			if err := f.s.localNodeIdentityRecoveryCommand(context.Background(), f.c, o, &out); err != nil {
				t.Fatal("historical status unreadable", err)
			}
			var view nodeIdentityRecoveryView
			if json.Unmarshal(out.Bytes(), &view) != nil || view.Expired != (scenario == "expired") {
				t.Fatal("wrong historical view")
			}
			r.calls = nil
			err := w.run(context.Background(), "admin", f.job.ID, func(identityRecoveryProgress) error { return nil })
			if (err == nil) != (scenario == "completed") || len(r.calls) != 0 {
				t.Fatal("historical state authorized new remote work", err)
			}
		})
	}
}

func TestNodeIdentityRecoveryPublicCommandRejectsUnsupportedHostBeforeConfig(t *testing.T) {
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Geteuid() == 0 {
		return
	}
	for _, action := range []string{"prepare-node-identity-recovery", "run-node-identity-recovery", "cancel-node-identity-recovery", "node-identity-recovery-status"} {
		var out bytes.Buffer
		err := Command(context.Background(), Options{Action: action, Config: "/absent/private-config"}, strings.NewReader(""), &out)
		if err == nil || strings.Contains(err.Error(), "无法读取 v3 配置") || out.Len() != 0 {
			t.Fatal("unsupported host bypassed platform guard", action, err)
		}
	}
}
