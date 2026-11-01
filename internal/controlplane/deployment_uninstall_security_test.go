package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// These tests exercise real PostgreSQL transactions and Vault authentication.
// Installation receipts are synthetic; the separate kernel gate exercises SSH
// and actual service/container removal and restoration.
func uninstallSecurityInstallation(t *testing.T, mode string) (*Store, *Vault, string, DeploymentJob) {
	t.Helper()
	v, path := testVault(t)
	s, _, j, proof := installationFixtureMode(t, mode, v)
	// installationFixture's credential uses an independent Vault. Seal the
	// original credential with this fixture's key before committing its proof.
	c := credentialFixture()
	id := j.Plan.Request.Credential
	key, nonce, sealed, err := v.seal(id, j.Node, 1, c)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_credentials SET key_id=$2,nonce=$3,ciphertext=$4 WHERE id=$1`, id, key, nonce, sealed)
	if err := s.completeDeploymentPhase(context.Background(), j, v, &proof); err != nil {
		t.Fatal(err)
	}
	return s, v, path, reloadDeployment(t, s, j.ID)
}

func uninstallSecurityNode(t *testing.T, s *Store, id string) Node {
	t.Helper()
	n, err := scanNode(s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, id))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func uninstallSecuritySummary(t *testing.T, s *Store, vaultPath, node string) nodeLifecycleSummary {
	t.Helper()
	a := NewAPI(s, Config{DeploymentTrust: DeploymentTrustConfig{VaultKeyFile: vaultPath}})
	result, err := a.uninstallSummaries(context.Background(), []string{node})
	if err != nil {
		t.Fatal(err)
	}
	return result[node]
}

func TestUninstallSecurityActualTargetSurvivesDisabledSavedDraft(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			s, v, path, installed := uninstallSecurityInstallation(t, mode)
			ctx := context.Background()
			n := uninstallSecurityNode(t, s, installed.Node)
			original := n
			n.Endpoint, n.ServerName, n.Enabled = "192.0.2.99:19200", "192.0.2.99", false
			if mode == "native" {
				n.Mode = "docker"
			} else {
				n.Mode = "native"
			}
			if _, err := s.SaveNode(ctx, "admin", "pending-address-mode", n, n.Version, 256); err != nil {
				t.Fatal(err)
			}
			n = uninstallSecurityNode(t, s, installed.Node)
			// A newly saved credential for the draft destination must never
			// redirect removal of the still-installed source.
			pending := credentialFixture()
			pending.Host, pending.Port = "192.0.2.99", 2222
			if _, err := s.AddCredential(ctx, v, "admin", "pending-credential", n.ID, n.Version, pending); err != nil {
				t.Fatal(err)
			}
			source, credential, remote, _, err := s.webUninstallSource(ctx, v, n)
			if err != nil {
				t.Fatal("disabled node with saved draft cannot uninstall original", err)
			}
			if source.Job != installed.ID || source.Node.Endpoint != original.Endpoint || source.Spec.Mode != mode || source.Snapshot != installed.Plan.TargetRuntime || credential != installed.Plan.Request.Credential || remote.Host != "192.0.2.1" || remote.Port != 22 {
				t.Fatal("uninstall destination or credential followed saved draft")
			}
			target := publicUninstallTarget(source, remote)
			if target.Endpoint != original.Endpoint || target.Mode != mode || target.Host != remote.Host || target.SSHPort != 22 || target.PlanDigest != installed.PlanDigest {
				t.Fatal("public confirmation did not identify actual installation")
			}
			state := uninstallSecuritySummary(t, s, path, n.ID)
			if !state.CanUninstall || state.State != "installed" {
				t.Fatal("disabled saved intent hid authenticated installed source", state)
			}
			if tableCount(t, s, "v3_deployment_jobs") != 1 {
				t.Fatal("source inspection created a deployment")
			}
		})
	}
}

func TestUninstallSecurityDamagedEvidenceStaysUnknown(t *testing.T) {
	for _, damage := range []string{"missing-installation", "installation-hmac", "lifecycle-hmac", "lifecycle-body", "generation", "wrong-vault", "source-status", "source-plan"} {
		t.Run(damage, func(t *testing.T) {
			s, v, path, j := uninstallSecurityInstallation(t, "native")
			switch damage {
			case "missing-installation":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_deployment_installations WHERE job=$1`, j.ID)
			case "installation-hmac":
				mustHistoryExec(t, s.DB, `UPDATE v3_deployment_installations SET proof=repeat('f',64) WHERE job=$1`, j.ID)
			case "lifecycle-hmac":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_lifecycle SET proof=repeat('f',64) WHERE node=$1`, j.Node)
			case "lifecycle-body":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_lifecycle SET body=jsonb_set(body,'{state}','"uninstalled"') WHERE node=$1`, j.Node)
			case "generation":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1`, j.Node)
			case "wrong-vault":
				v, path = testVault(t)
			case "source-status":
				mustHistoryExec(t, s.DB, `UPDATE v3_deployment_jobs SET status='rolled_back' WHERE id=$1`, j.ID)
			case "source-plan":
				mustHistoryExec(t, s.DB, `UPDATE v3_deployment_jobs SET plan=jsonb_set(plan,'{target_runtime}',to_jsonb(repeat('e',64))) WHERE id=$1`, j.ID)
			}
			before := tableCount(t, s, "v3_deployment_jobs")
			if _, _, _, _, err := s.webUninstallSource(context.Background(), v, uninstallSecurityNode(t, s, j.Node)); err == nil {
				t.Fatal("unauthenticated source authorized uninstall")
			}
			state := uninstallSecuritySummary(t, s, path, j.Node)
			if state.CanUninstall || state.State != "unknown" || state.Reason == "" {
				t.Fatal("missing evidence became success or an authorized installation", state)
			}
			if tableCount(t, s, "v3_deployment_jobs") != before {
				t.Fatal("rejected inspection changed task history")
			}
		})
	}
}

func TestUninstallSecurityDisabledDraftCanPreviewAndConfirmActualInstallation(t *testing.T) {
	f, sourceJob := uninstallControllerFixture(t)
	ctx := context.Background()
	n := uninstallSecurityNode(t, f.s, sourceJob.Node)
	n.Endpoint, n.ServerName, n.Mode, n.Enabled = "192.0.2.99:19200", "192.0.2.99", "docker", false
	if _, err := f.s.SaveNode(ctx, "admin", "saved-disabled-draft", n, n.Version, 256); err != nil {
		t.Fatal(err)
	}
	n = uninstallSecurityNode(t, f.s, sourceJob.Node)
	source, credential, _, _, err := f.s.webUninstallSource(ctx, f.t.vault, n)
	if err != nil {
		t.Fatal(err)
	}
	in, err := f.s.prepareUninstallDeployment(ctx, f.c, f.t, n, source, credential)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.s.previewLocalDeployment(ctx, f.c, f.t, "admin", in)
	if err != nil {
		t.Fatal("disabled node cannot preview uninstall", err)
	}
	if p.Kind != "uninstall" || p.Comparison != "uninstall-preserve-data" || p.Target.Mode != "native" || p.Target.Release != source.Spec.Release || p.Target.SHA256 != source.Spec.BundleSHA256 {
		t.Fatal("uninstall confirmation described saved draft or helper version")
	}
	raw, err := f.s.confirmLocalDeployment(ctx, f.c, f.t, "admin", "confirm-disabled-uninstall", p.Token)
	if err != nil {
		t.Fatal("disabled node cannot confirm uninstall", err)
	}
	var created struct{ ID string }
	if json.Unmarshal(raw, &created) != nil || created.ID == "" {
		t.Fatal("missing uninstall task")
	}
	j := claimDeployment(t, f.s, "uninstall-security")
	request, err := f.s.uninstallRequest(ctx, f.t.vault, j, "apply")
	if err != nil {
		t.Fatal("actual uninstall request rejected", err)
	}
	if j.ID != created.ID || j.Plan.Uninstall == nil || j.Plan.Uninstall.Source.Job != sourceJob.ID || j.Plan.Uninstall.Source.Node.Endpoint != sourceJob.Plan.Node.Endpoint || request.Spec.Mode != "native" || request.Spec.Action != "uninstall" || request.Uninstall.SourceJob != sourceJob.ID {
		t.Fatal("executor request followed disabled pending target")
	}
	if err := f.s.checkUninstallSSH(ctx, f.t.vault, j, credentialFixture()); err != nil {
		t.Fatal("actual credential rejected", err)
	}
	wrong := credentialFixture()
	wrong.Host = "192.0.2.99"
	if err := f.s.checkUninstallSSH(ctx, f.t.vault, j, wrong); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatal("pending-target credential accepted", err)
	}
}

func TestUninstallSecurityOverrideCredentialCannotRedirectSource(t *testing.T) {
	s, v, _, j := uninstallSecurityInstallation(t, "native")
	ctx := context.Background()
	n := uninstallSecurityNode(t, s, j.Node)
	source, _, _, _, err := s.webUninstallSource(ctx, v, n)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"192.0.2.99", "192.0.2.1"} {
		t.Run(host, func(t *testing.T) {
			id := token()
			c := credentialFixture()
			c.Host, c.Port = host, 2222
			key, nonce, sealed, err := v.seal(id, n.ID, 1, c)
			if err != nil {
				t.Fatal(err)
			}
			mustHistoryExec(t, s.DB, `INSERT INTO v3_credentials(id,node,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5)`, id, n.ID, key, nonce, sealed)
			mustHistoryExec(t, s.DB, `INSERT INTO v3_web_uninstall_credentials(node,source,credential) VALUES($1,$2,$3) ON CONFLICT(node,source) DO UPDATE SET credential=excluded.credential`, n.ID, source.Job, id)
			_, gotID, got, _, err := s.webUninstallSource(ctx, v, n)
			if host != "192.0.2.1" {
				if !errors.Is(err, ErrCredentialUnavailable) {
					t.Fatal("credential for another host accepted", err)
				}
			} else if err != nil || gotID != id || got.Host != host || got.Port != 2222 {
				t.Fatal("same-host authenticated override not selected", err)
			}
		})
	}
}

func TestUninstallSecurityCapabilityIndependentOfIssuerAndRules(t *testing.T) {
	f := webDeployFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, f.s.DB, `UPDATE v3_role_status SET details=details||'{"issuer":false,"rules":false}'::jsonb,heartbeat=clock_timestamp()`)
	if f.api.deploymentAvailability(ctx).Available {
		t.Fatal("installation advertised without issuer and rules")
	}
	if !f.api.deploymentOperationAvailability(ctx, true).Available {
		t.Fatal("uninstall incorrectly requires signing a new node identity or rules")
	}
	r := f.call("GET", "/api/v3/capabilities", nil, "")
	var public struct {
		Operations struct {
			Uninstall struct {
				Available bool `json:"available"`
			} `json:"uninstall"`
		} `json:"operations"`
	}
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &public) != nil || !public.Operations.Uninstall.Available {
		t.Fatal("public uninstall availability differs from worker evidence", r.Code)
	}
	for _, missing := range []string{"executor", "deployment-preparations"} {
		t.Run(missing, func(t *testing.T) {
			mustHistoryExec(t, f.s.DB, `UPDATE v3_role_status SET heartbeat=clock_timestamp()-interval '30 seconds' WHERE role=$1`, missing)
			if result := f.api.deploymentOperationAvailability(ctx, true); result.Available || strings.TrimSpace(result.Reason) == "" {
				t.Fatal("stale worker advertised uninstall readiness")
			}
			mustHistoryExec(t, f.s.DB, `UPDATE v3_role_status SET heartbeat=clock_timestamp()`)
		})
	}
}

func TestUninstallSecurityPublicDetailNeverInfersSuccessfulRemoval(t *testing.T) {
	s, _, path, j := uninstallSecurityInstallation(t, "native")
	a := NewAPI(s, Config{DeploymentTrust: DeploymentTrustConfig{VaultKeyFile: path}})
	session := historyAPISession(t, s, "admin", "admin")
	for _, installed := range []bool{true, false} {
		if !installed {
			mustHistoryExec(t, s.DB, `UPDATE v3_node_lifecycle SET body=jsonb_set(body,'{state}','"uninstalled"'),state='uninstalled' WHERE node=$1`, j.Node)
		}
		r := webCall(a, "GET", "/api/v3/servers/"+j.Node, "", session, "", true, "")
		var public struct {
			Node Node `json:"node"`
		}
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &public) != nil {
			t.Fatal("public detail unavailable", r.Code)
		}
		want := "unknown"
		if installed {
			want = "installed"
		}
		if public.Node.Lifecycle != want || public.Node.CanUninstall != installed {
			t.Fatal("public detail falsely confirmed removal", public.Node.Lifecycle)
		}
		if strings.Contains(r.Body.String(), credentialFixture().Password) {
			t.Fatal("public lifecycle leaked credential")
		}
	}
}
