package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"webscan/internal/common"
)

// Real isolated PostgreSQL stores plans, reservations, leases and journals.
// SSH fingerprint reads use a local synthetic SSH server. Service operations
// and collector evidence are explicit test adapters, not Linux acceptance.
type monitoringApplicationFixture struct {
	provisioningFixture
	worker  *monitoringApplicationWorker
	global  string
	request monitoringApplicationRequest
	port    int
}

func newMonitoringApplicationFixture(t *testing.T) monitoringApplicationFixture {
	t.Helper()
	ctx := context.Background()
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	f.c.Executor.RulesFile = f.in.RulesFile
	port, fp := fingerprintServer(t)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET endpoint='127.0.0.1:19100',config='{"monitoring_policy":{"source":"inherited","rules_version":"0"}}' WHERE id=$1`, f.in.Node)
	c := credentialFixture()
	c.Host = "127.0.0.1"
	c.Port = port
	c.Fingerprint = fp
	raw, e := f.s.AddCredential(ctx, f.t.vault, "admin", "monitoring-credential", f.in.Node, 1, c)
	if e != nil {
		t.Fatal(e)
	}
	var credential struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &credential) != nil {
		t.Fatal("credential receipt")
	}
	f.in.Credential = credential.ID
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_web_node_credentials(node,credential) VALUES($1,$2)`, f.in.Node, credential.ID)
	identity := issuedNode(t, f, "monitoring-seed")
	f.in.IdentityID = identity.ID
	f.in.IdentityDirectory = ""
	request, e := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.in)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "monitoring-initial-install", request)
	if e != nil {
		t.Fatal(e)
	}
	var receipt struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &receipt) != nil {
		t.Fatal("initial job receipt")
	}
	job := claimDeployment(t, f.s, "monitoring-baseline")
	runtime := readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, f.s}
	if e = (&DeploymentRunner{Store: f.s, Vault: f.t.vault, Runtime: runtime}).Execute(ctx, job); e != nil {
		t.Fatal(e)
	}
	rules := defaultMonitoringRules()
	rules.Extensions = append(rules.Extensions, ".migrationtest")
	tx, e := f.s.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	d, e := readSettingsDraftTx(ctx, tx, true)
	if e != nil {
		t.Fatal(e)
	}
	state, e := putSettingsDraftTx(ctx, tx, f.t.vault, common.JSON(map[string]any{"file_monitoring": rules}), d.RuntimeVersion, d.Runtime)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	generation := fmt.Sprint(state.Generation)
	worker := NewMonitoringApplicationWorker(f.s, f.c, f.t, readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, f.s}, "monitoring-test-worker")
	return monitoringApplicationFixture{f, worker, generation, monitoringApplicationRequest{generation, []monitoringApplicationTarget{{f.in.Node, 1}}}, port}
}
func (f monitoringApplicationFixture) preview(t *testing.T) (monitoringApplication, string) {
	t.Helper()
	p, capability, e := f.s.previewMonitoringApplication(context.Background(), f.t, "admin", "monitoring-preview", f.request)
	if e != nil {
		t.Fatal(e)
	}
	return p, capability
}
func (f monitoringApplicationFixture) confirmed(t *testing.T) monitoringApplication {
	t.Helper()
	p, capability := f.preview(t)
	if _, e := f.s.confirmMonitoringApplication(context.Background(), f.t, "admin", "monitoring-confirm", p.ID, capability); e != nil {
		t.Fatal(e)
	}
	p, e := f.worker.claim(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestMonitoringApplicationPreviewBindingsAndNoEarlyChanges(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	p, capability := f.preview(t)
	if p.Status != "preview" || len(p.Nodes) != 1 || !p.Nodes[0].Changed || p.Nodes[0].Rules.RulesVersion != f.global {
		t.Fatal("incorrect preview projection")
	}
	replay, replayed, e := f.s.previewMonitoringApplication(context.Background(), f.t, "admin", "monitoring-preview", f.request)
	if e != nil || replay.ID != p.ID || replayed != capability {
		t.Fatal("preview replay changed capability", e)
	}
	var version int
	var reserved bool
	if e = f.s.DB.QueryRow(`SELECT version FROM v3_nodes WHERE id=$1`, f.in.Node).Scan(&version); e != nil || version != 1 {
		t.Fatal("preview modified saved node", e)
	}
	if e = f.s.DB.QueryRow(`SELECT reserved FROM v3_monitoring_application_nodes WHERE application=$1`, p.ID).Scan(&reserved); e != nil || reserved {
		t.Fatal("preview reserved before confirmation", e)
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 1 {
		t.Fatal("preview created remote task")
	}
	var audits string
	if e = f.s.DB.QueryRow(`SELECT string_agg(result::text,' ') FROM v3_audit`).Scan(&audits); e != nil || strings.Contains(audits, capability) {
		t.Fatal("capability leaked to audit", e)
	}
	for _, change := range []string{"account", "node", "credential", "generation", "token"} {
		t.Run(change, func(t *testing.T) {
			g := newMonitoringApplicationFixture(t)
			p, capability := g.preview(t)
			switch change {
			case "account":
				mustHistoryExec(t, g.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "node":
				mustHistoryExec(t, g.s.DB, `UPDATE v3_nodes SET version=version+1 WHERE id=$1`, g.in.Node)
			case "credential":
				mustHistoryExec(t, g.s.DB, `UPDATE v3_credentials SET revision=revision+1 WHERE id=$1`, g.in.Credential)
			case "generation":
				mustHistoryExec(t, g.s.DB, `UPDATE v3_settings_drafts SET generation=generation+1`)
			case "token":
				capability = "wrong"
			}
			if _, e := g.s.confirmMonitoringApplication(context.Background(), g.t, "admin", "reject-confirm", p.ID, capability); e == nil {
				t.Fatal("stale preview accepted")
			}
		})
	}
}
func TestMonitoringApplicationRealSignedPreparationRunnerAndTerminalRelease(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	p := f.confirmed(t)
	// Ordinary edits and jobs cannot consume the durable reservation.
	n := nodeFixture(f.in.Node)
	n.Endpoint = "127.0.0.1:19100"
	if _, e := f.s.SaveNode(context.Background(), "admin", "reserved-edit", n, 1, 256); !errors.Is(e, ErrDeploymentBusy) {
		t.Fatal("reserved node edited", e)
	}
	f.worker.execute(context.Background(), p)
	done, e := f.s.monitoringApplication(context.Background(), f.t.vault, "admin", p.ID)
	if e != nil || done.Status != "succeeded" || len(done.Nodes) != 1 || done.Nodes[0].State != "succeeded" || done.Nodes[0].Job == "" {
		t.Fatal("rule application did not finish", done.Status, done.Error, e)
	}
	j := reloadDeployment(t, f.s, done.Nodes[0].Job)
	if j.Plan.Request.Release != f.t.release.manifest.Release || j.Plan.Node.Version != 2 || j.Kind != "upgrade" {
		t.Fatal("did not reuse pinned signed upgrade")
	}
	if deploymentBackupPinCount(t, f.s, j, "") != 0 {
		t.Fatal("terminal parent retained rollback pins")
	}
	var version, applied int64
	var reserved bool
	if e = f.s.DB.QueryRow(`SELECT version,applied_version FROM v3_nodes WHERE id=$1`, f.in.Node).Scan(&version, &applied); e != nil || version != 2 || applied != 2 {
		t.Fatal("incorrect saved/applied versions", version, applied, e)
	}
	if e = f.s.DB.QueryRow(`SELECT reserved FROM v3_monitoring_application_nodes WHERE application=$1`, p.ID).Scan(&reserved); e != nil || reserved {
		t.Fatal("terminal reservation retained", e)
	}
	if _, e = f.s.ClaimDeployment(context.Background(), "ordinary-worker"); e != sql.ErrNoRows {
		t.Fatal("ordinary runner claimed linked work", e)
	}
}
func TestMonitoringApplicationFailureResumeAndSuccessfulChildRollback(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	p := f.confirmed(t)
	ctx := context.Background()
	remote := &fakeDeploymentRuntime{failPhase: "activate"}
	f.worker.runtime = readinessFixtureRuntime{remote, t, f.s}
	f.worker.execute(ctx, p)
	paused, e := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if e != nil || paused.Status != "paused" || !paused.CanResume || !paused.CanRollback {
		t.Fatal("failure not recoverable", paused.Status, e)
	}
	if len(paused.Nodes) != 1 || paused.Nodes[0].Job == "" {
		t.Fatal("failure lost original task")
	}
	original := reloadDeployment(t, f.s, paused.Nodes[0].Job)
	if !original.RecoveryRequired || deploymentBackupPinCount(t, f.s, original, "rollback") != 1 {
		t.Fatal("failure lost rollback responsibility")
	}
	if _, e = f.s.recoverMonitoringApplication(ctx, f.t.vault, "admin", "continue-parent", p.ID, paused.Expected, "forward", f.in.Node); e != nil {
		t.Fatal(e)
	}
	p, e = f.worker.claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	remote.failPhase = ""
	f.worker.execute(ctx, p)
	partial, e := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if e != nil || partial.Status != "paused" || partial.Nodes[0].State != "succeeded" || !partial.Nodes[0].CanRollback {
		t.Fatal("single-target recovery lost rollback", partial.Status, e)
	}
	succeeded := reloadDeployment(t, f.s, original.ID)
	if deploymentBackupPinCount(t, f.s, succeeded, "rollback") != 1 {
		t.Fatal("partial success released original archive")
	}
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_events(node,id,received_at,operation,payload) VALUES($1,'after-rule-switch',clock_timestamp(),'modify','{}')`, f.in.Node)
	if _, e = f.s.recoverMonitoringApplication(ctx, f.t.vault, "admin", "rollback-parent", p.ID, partial.Expected, "rollback"); e != nil {
		t.Fatal(e)
	}
	p, e = f.worker.claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	f.worker.execute(ctx, p)
	done, e := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if e != nil || done.Status != "rolled_back" {
		t.Fatal("rollback incomplete", done.Status, done.Error, e)
	}
	restored := reloadDeployment(t, f.s, original.ID)
	if restored.Status != "rolled_back" || restored.PlanDigest != original.PlanDigest || restored.Plan.BeforeBackup != original.Plan.BeforeBackup {
		t.Fatal("rollback replaced immutable task")
	}
	if tableCount(t, f.s, "v3_events") != 1 {
		t.Fatal("rollback lost new event")
	}
	var applied int
	if e = f.s.DB.QueryRow(`SELECT applied_version FROM v3_nodes WHERE id=$1`, f.in.Node).Scan(&applied); e != nil || applied != 1 {
		t.Fatal("rollback invented applied version", e)
	}
}
func TestMonitoringApplicationLeaseAndPlanTamperFencing(t *testing.T) {
	for _, scenario := range []string{"lease", "ciphertext", "proof", "link", "hold"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMonitoringApplicationFixture(t)
			p := f.confirmed(t)
			ctx := context.Background()
			scoped := monitoringNodeContext(ctx, f.t.vault, p, f.in.Node, "")
			n, e := f.s.prepareMonitoringNode(scoped, f.c, f.t, p, f.in.Node)
			if e != nil {
				t.Fatal(e)
			}
			input := f.in
			input.Kind = "upgrade"
			input.Expected = n.Version
			request, e := f.s.prepareLocalDeployment(scoped, f.c, f.t, input)
			if e != nil {
				t.Fatal(e)
			}
			_, e = f.s.queueMonitoringNode(scoped, f.c, f.t, p, request)
			if e != nil {
				t.Fatal(e)
			}
			j, childContext, e := f.s.claimMonitoringNode(ctx, f.t.vault, p, f.in.Node)
			if e != nil {
				t.Fatal(e)
			}
			if e = f.s.RenewDeployment(ctx, j); e == nil {
				t.Fatal("public path renewed owned child")
			}
			switch scenario {
			case "lease":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_applications SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, p.ID)
			case "ciphertext":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_applications SET ciphertext=set_byte(ciphertext,0,get_byte(ciphertext,0)#1) WHERE id=$1`, p.ID)
			case "proof":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_applications SET proof='tampered' WHERE id=$1`, p.ID)
			case "link":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_application_nodes SET proof='tampered' WHERE application=$1`, p.ID)
			case "hold":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_applications SET recovery_hold=true WHERE id=$1`, p.ID)
			}
			if e = f.s.RenewDeployment(childContext, j); e == nil {
				t.Fatal("fenced child renewed")
			}
		})
	}
}
func TestMonitoringApplicationStrictTargetAndTransport(t *testing.T) {
	for _, input := range []string{`{"ID":"node-a","expected_version":1}`, `{"id":"node-a","expected_version":null}`, `{"id":"node-a","Expected_Version":1}`, `{"id":"node-a","expected_version":1,"extra":1}`} {
		var n monitoringApplicationTarget
		if json.Unmarshal([]byte(input), &n) == nil {
			t.Fatal("noncanonical target accepted")
		}
	}
	f := newMonitoringApplicationFixture(t)
	a := NewAPI(f.s, f.c)
	for _, role := range []string{"admin", "viewer"} {
		r := httptest.NewRequest("POST", "https://local/api/v3/monitoring/applications/preview", bytes.NewBufferString(`{}`))
		r.Header.Set("Idempotency-Key", "preview-test")
		w := httptest.NewRecorder()
		a.monitoringApplicationRoutes(w, r, identity{Username: role, Role: role})
		if role == "viewer" && w.Code != 403 {
			t.Fatal("viewer authorized", w.Code)
		}
	}
}

// Concurrency assertions for scheduler itself use a real database parent and a
// blocked local runtime, never real production machines or notifications.
func TestMonitoringApplicationExplicitReauthorizationAfterPasswordRevision(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	ctx := context.Background()
	p, capability := f.preview(t)
	if _, e := f.s.confirmMonitoringApplication(ctx, f.t, "admin", "confirm-before-password", p.ID, capability); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
	if _, e := f.worker.claim(ctx); e != sql.ErrNoRows {
		t.Fatal("stale authority claimed work", e)
	}
	paused, e := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if e != nil || paused.Status != "paused" || !paused.CanReauthorize || paused.CanResume || paused.CanRollback {
		t.Fatal("stale controller projection", paused.Status, e)
	}
	if _, e = f.s.recoverMonitoringApplication(ctx, f.t.vault, "admin", "cannot-bypass-reset", p.ID, paused.Expected, "forward"); e == nil {
		t.Fatal("reset silently granted old plan authority")
	}
	ticket, expires, e := f.s.previewMonitoringReauthorization(ctx, f.t.vault, "admin", "reauth-preview", p.ID, paused.Expected)
	if e != nil || !expires.After(time.Now()) {
		t.Fatal("reauth preview", e)
	}
	if _, _, e = f.s.previewMonitoringReauthorization(ctx, f.t.vault, "viewer", "viewer-reauth", p.ID, paused.Expected); e == nil {
		t.Fatal("viewer preview authorized")
	}
	beforeJobs := tableCount(t, f.s, "v3_deployment_jobs")
	if _, e = f.s.reauthorizeMonitoringApplication(ctx, f.t.vault, "admin", "reauth-confirm", p.ID, paused.Expected, ticket); e != nil {
		t.Fatal(e)
	}
	authorized, e := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if e != nil || authorized.Status != "paused" || authorized.CanReauthorize || !authorized.CanResume || authorized.Digest != paused.Digest || authorized.ControllerRevision != 2 {
		t.Fatal("reauthorization replaced plan or started work", e)
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != beforeJobs {
		t.Fatal("reauthorization executed remote work")
	}
	if _, e = f.s.recoverMonitoringApplication(ctx, f.t.vault, "admin", "continue-after-reauth", p.ID, authorized.Expected, "forward"); e != nil {
		t.Fatal(e)
	}
	p, e = f.worker.claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	f.worker.execute(ctx, p)
	done, e := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if e != nil || done.Status != "succeeded" {
		t.Fatal("new authority could not finish fixed plan", done.Status, e)
	}
}
func TestMonitoringApplicationReauthorizationExpiryStateAndConcurrentPassword(t *testing.T) {
	for _, scenario := range []string{"expiry", "password", "child-state", "hold"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMonitoringApplicationFixture(t)
			ctx := context.Background()
			p := f.confirmed(t)
			// Persist a safe paused state before remote changes, retaining reservations.
			tx, e := f.s.DB.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			p, e = lockMonitoringParentTx(ctx, tx, f.t.vault, p)
			if e != nil {
				t.Fatal(e)
			}
			p.Status = "paused"
			p.Owner = sql.NullString{}
			p.Lease = sql.NullTime{}
			if e = updateMonitoringApplicationTx(ctx, tx, f.t.vault, &p); e != nil {
				t.Fatal(e)
			}
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
			ticket, _, e := f.s.previewMonitoringReauthorization(ctx, f.t.vault, "admin", "test-reauth-preview", p.ID, p.Expected)
			if e != nil {
				t.Fatal(e)
			}
			switch scenario {
			case "expiry":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_application_authorizations SET expires_at=clock_timestamp()-interval '1 second'`)
			case "password":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "child-state":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_application_nodes SET state='failed' WHERE application=$1`, p.ID)
			case "hold":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_applications SET recovery_hold=true WHERE id=$1`, p.ID)
			}
			if _, e = f.s.reauthorizeMonitoringApplication(ctx, f.t.vault, "admin", "stale-reauth", p.ID, p.Expected, ticket); e == nil {
				t.Fatal("stale reauthorization accepted")
			}
		})
	}
}

type monitoringCountingRuntime struct {
	active, max atomic.Int32
	mu          sync.Mutex
	started     map[string]bool
	release     chan struct{}
	failNode    string
}

func (r *monitoringCountingRuntime) Inspect(_ context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	return checkpoint(j, "absent"), nil
}
func (r *monitoringCountingRuntime) Apply(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	if j.Phase() == "preflight" {
		active := r.active.Add(1)
		defer r.active.Add(-1)
		for {
			old := r.max.Load()
			if old >= active || r.max.CompareAndSwap(old, active) {
				break
			}
		}
		r.mu.Lock()
		r.started[j.Node] = true
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return RemoteDeploymentCheckpoint{}, ctx.Err()
		case <-r.release:
		}
		if j.Node == r.failNode {
			return RemoteDeploymentCheckpoint{}, DeploymentFailure{"preflight-failed"}
		}
		select {
		case <-ctx.Done():
			return RemoteDeploymentCheckpoint{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return checkpoint(j, "complete"), nil
}
func (f *monitoringApplicationFixture) addInstalledNode(t *testing.T, id string) {
	t.Helper()
	ctx := context.Background()
	n := nodeFixture(id)
	n.Endpoint = "127.0.0.1:19100"
	n.Config = []byte(`{"monitoring_policy":{"source":"inherited","rules_version":"0"}}`)
	if e := f.s.PutNode(ctx, n, 0, f.c.Collector.Shards); e != nil {
		t.Fatal(e)
	}
	credential, e := f.s.ReadCredential(ctx, f.t.vault, f.in.Credential, f.in.Node)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := f.s.AddCredential(ctx, f.t.vault, "admin", "credential-"+id, id, 1, credential)
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &c) != nil {
		t.Fatal("extra credential")
	}
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_web_node_credentials(node,credential) VALUES($1,$2)`, id, c.ID)
	raw, e = f.s.IssueNodeCertificate(ctx, f.c, f.t.vault, "admin", "identity-"+id, NodeCertificateInput{Node: id, Expected: 1})
	if e != nil {
		t.Fatal(e)
	}
	var identity NodeCertificateRecord
	if json.Unmarshal(raw, &identity) != nil {
		t.Fatal("extra identity")
	}
	input := f.in
	input.Node = id
	input.Credential = c.ID
	input.IdentityID = identity.ID
	request, e := f.s.prepareLocalDeployment(ctx, f.c, f.t, input)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "install-"+id, request); e != nil {
		t.Fatal(e)
	}
	j := claimDeployment(t, f.s, "baseline-"+id)
	if e = (&DeploymentRunner{Store: f.s, Vault: f.t.vault, Runtime: readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, f.s}}).Execute(ctx, j); e != nil {
		t.Fatal(e)
	}
	f.request.Nodes = append(f.request.Nodes, monitoringApplicationTarget{id, 1})
}
func TestMonitoringApplicationBatchAndConcurrencyFailurePausesLaterNodes(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	for i := 0; i < 20; i++ {
		f.addInstalledNode(t, fmt.Sprintf("batch-node-%02d", i))
	}
	p := f.confirmed(t)
	remote := &monitoringCountingRuntime{started: map[string]bool{}, release: make(chan struct{}), failNode: "batch-node-00"}
	f.worker.runtime = readinessFixtureRuntime{remote, t, f.s}
	done := make(chan struct{})
	go func() { defer close(done); f.worker.execute(context.Background(), p) }()
	deadline := time.Now().Add(10 * time.Second)
	for remote.active.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if remote.active.Load() != 5 {
		close(remote.release)
		<-done
		t.Fatal("scheduler failed to admit five isolated nodes", remote.active.Load())
	}
	close(remote.release)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("failed batch did not settle")
	}
	remote.mu.Lock()
	started := len(remote.started)
	remote.mu.Unlock()
	if remote.max.Load() != 5 || started != 5 {
		t.Fatal("failed batch exceeded concurrency or started later nodes", remote.max.Load(), started)
	}
	paused, e := f.s.monitoringApplication(context.Background(), f.t.vault, "admin", p.ID)
	if e != nil || paused.Status != "paused" || len(paused.Nodes) != 21 {
		t.Fatal("batch failure not persistent", paused.Status, e)
	}
	pending := 0
	for _, n := range paused.Nodes {
		if n.Batch > 1 {
			t.Fatal("batch exceeds twenty")
		}
		if n.State == "pending" {
			pending++
		}
		if n.ID == f.in.Node && (n.Batch != 1 || n.State != "pending" || n.Job != "") {
			t.Fatal("second batch began before first succeeded")
		}
	}
	if pending != 16 {
		t.Fatal("failure did not pause pending nodes", pending)
	}
	var reservations int
	if e = f.s.DB.QueryRow(`SELECT count(*) FROM v3_monitoring_application_nodes WHERE application=$1 AND reserved`, p.ID).Scan(&reservations); e != nil || reservations != 21 {
		t.Fatal("partial batch lost node reservations", reservations, e)
	}
}
func TestMonitoringApplicationNewGlobalGenerationStillPermitsRollback(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	p := f.confirmed(t)
	ctx := context.Background()
	remote := &fakeDeploymentRuntime{failPhase: "activate"}
	f.worker.runtime = readinessFixtureRuntime{remote, t, f.s}
	f.worker.execute(ctx, p)
	paused, e := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if e != nil || paused.Status != "paused" {
		t.Fatal(e)
	}
	tx, e := f.s.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	d, e := readSettingsDraftTx(ctx, tx, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = putSettingsDraftTx(ctx, tx, f.t.vault, d.Desired, d.RuntimeVersion, d.Runtime); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	changed, e := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if e != nil || changed.CanResume || !changed.CanRollback {
		t.Fatal("new global rules blocked fixed rollback", e)
	}
	if _, e = f.s.recoverMonitoringApplication(ctx, f.t.vault, "admin", "rollback-after-global-save", p.ID, changed.Expected, "rollback"); e != nil {
		t.Fatal(e)
	}
	p, e = f.worker.claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	remote.failPhase = ""
	f.worker.execute(ctx, p)
	done, e := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if e != nil || done.Status != "rolled_back" {
		t.Fatal("fixed old plan rollback failed", done.Status, e)
	}
}
