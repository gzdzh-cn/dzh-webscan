package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func singleBackupUpgradeFixture(t *testing.T, plan singleBackupPlan) (singleBackupSchedule, []byte, singleBackupUpgradeSpec, string) {
	t.Helper()
	ctx := context.Background()
	directory := filepath.Join(filepath.Dir(plan.spec.Root), "upgrade-backups")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	trust, err := loadDeploymentTrust(ctx, plan.config.DeploymentTrust)
	if err != nil {
		t.Fatal(err)
	}
	p := singleBackupSchedule{Format: 1, Spec: singleBackupScheduleSpec{Format: 1, Directory: directory, Keep: 2, Request: plan.request}, Helper: plan.config.DeploymentTrust.HelperFile, Hash: trust.release.manifest.Helper.SHA256, Release: trust.release.manifest.Release}
	policyRaw, _ := json.Marshal(p)
	policyDirectory := filepath.Join(filepath.Dir(plan.spec.Root), "original-backup-maintenance")
	if err := os.Mkdir(policyDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	schedule := filepath.Join(policyDirectory, "schedule.json")
	localWrite(t, schedule, policyRaw)
	nextTrust := newTrustToolFixture(t)
	localWrite(t, nextTrust.helper, []byte("isolated-new-backup-upgrade-helper"))
	nextTrust.sign.Output += "-backup-upgrade"
	if err := ReleaseCommand(ctx, nextTrust.sign, io.Discard); err != nil {
		t.Fatal(err)
	}
	nextTrust.signed = nextTrust.sign.Output
	config := plan.config
	config.DeploymentTrust = nextTrust.config()
	config.DeploymentTrust.VaultKeyFile = plan.config.DeploymentTrust.VaultKeyFile
	config.DeploymentTrust.PreviousKeyFiles = plan.config.DeploymentTrust.PreviousKeyFiles
	nextDirectory := filepath.Join(filepath.Dir(plan.spec.Root), "new-backup-runtime")
	if err := os.Mkdir(nextDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	apiRaw, err := os.ReadFile(plan.request.APIConfig)
	if err != nil {
		t.Fatal(err)
	}
	api, err := decodeSingleBackupConfig(apiRaw)
	if err != nil {
		t.Fatal(err)
	}
	api.DeploymentTrust = config.DeploymentTrust
	api.DeploymentTrust.HelperFile, api.DeploymentTrust.NativeBundleFile, api.DeploymentTrust.ImageArchiveFile = "", "", ""
	request := singleBackupUpgradeSpec{Format: 1, ScheduleFile: schedule, Backup: plan.request}
	request.Backup.HostConfig, request.Backup.APIConfig = filepath.Join(nextDirectory, "executor.yaml"), filepath.Join(nextDirectory, "config.yaml")
	hostRaw, _ := yaml.Marshal(config)
	apiRaw, _ = yaml.Marshal(api)
	localWrite(t, request.Backup.HostConfig, hostRaw)
	localWrite(t, request.Backup.APIConfig, apiRaw)
	return p, policyRaw, request, filepath.Join(filepath.Dir(plan.spec.Root), "backup-upgrade")
}

func publishSingleBackupUpgradeFixture(t *testing.T, request singleBackupUpgradeSpec, output string) {
	t.Helper()
	input, _ := json.Marshal(request)
	source := filepath.Join(filepath.Dir(output), "backup-upgrade-request.json")
	localWrite(t, source, input)
	if err := singleBackupUpgradeCommand(context.Background(), Options{Action: "prepare-single-backup-upgrade", Source: source, Output: output}, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestSingleBackupUpgradePreservesOriginalPolicyAndTrust(t *testing.T) {
	ctx := context.Background()
	plan, _ := newSingleBackupFixture(t)
	p, original, request, output := singleBackupUpgradeFixture(t, plan)
	before := map[string][]byte{}
	for _, file := range []string{request.ScheduleFile, plan.request.Installation, filepath.Join(plan.spec.Root, "journal.json"), plan.config.DeploymentTrust.VaultKeyFile, filepath.Join(plan.spec.Root, "authority", "ca.key"), filepath.Join(plan.spec.Root, "webscan")} {
		var err error
		before[file], err = os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
	}
	files, err := singleBackupUpgradeFiles(ctx, request, output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("preview wrote maintenance files")
	}
	if len(files) != 3 || !strings.Contains(string(files["backup.timer"]), "OnCalendar=*-*-* *:*:00") || !strings.Contains(string(files["backup.service"]), "run-single-backup-upgrade") || strings.Contains(string(files["backup.service"]), "PartOf=") {
		t.Fatal("upgrade must use an independent minute timer and upgraded action")
	}
	publishSingleBackupUpgradeFixture(t, request, output)
	old, previous, next, raw, manifest, err := readSingleBackupUpgrade(ctx, filepath.Join(output, "upgrade.json"), "", "")
	if err != nil || !bytes.Equal(raw, original) || old.Spec.Keep != p.Spec.Keep || old.Spec.Directory != p.Spec.Directory || previous.spec.Root != next.spec.Root || manifest.Helper == old.Helper || manifest.HelperSHA256 == old.Hash {
		t.Fatal("old policy was not reused with a distinct signed helper", manifest, err)
	}
	if _, _, _, _, _, err := readSingleBackupUpgrade(ctx, filepath.Join(output, "upgrade.json"), manifest.Helper, manifest.Release); err != nil {
		t.Fatal("new verified executable rejected", err)
	}
	for _, args := range [][2]string{{old.Helper, manifest.Release}, {manifest.Helper, "development"}, {manifest.Helper, "v0.0.1"}} {
		if _, _, _, _, _, err := readSingleBackupUpgrade(ctx, filepath.Join(output, "upgrade.json"), args[0], args[1]); err == nil {
			t.Fatal("wrong executable/release was accepted", args)
		}
	}
	found := false
	for _, source := range next.sources {
		found = found || source.Path == output && source.Directory
	}
	if !found {
		t.Fatal("active upgrade overlay omitted from full backup recovery material")
	}
	if next.bindings[request.ScheduleFile] != digest(original) || next.bindings[old.Helper] != old.Hash {
		t.Fatal("original schedule/helper recovery bindings were dropped")
	}
	for file, expected := range before {
		actual, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("original policy, installation or key changed", file, err)
		}
	}
	if err := publishTrustFiles(ctx, output, files); err == nil {
		t.Fatal("existing upgrade package overwritten")
	}
}

func TestSingleBackupUpgradeRejectsTamperedOrReboundMaterials(t *testing.T) {
	for _, change := range []string{"manifest", "policy", "service", "helper", "config", "schema"} {
		t.Run(change, func(t *testing.T) {
			plan, _ := newSingleBackupFixture(t)
			_, _, request, output := singleBackupUpgradeFixture(t, plan)
			publishSingleBackupUpgradeFixture(t, request, output)
			source := filepath.Join(output, "upgrade.json")
			raw, _ := os.ReadFile(source)
			var manifest singleBackupUpgradeManifest
			if json.Unmarshal(raw, &manifest) != nil {
				t.Fatal("invalid fixture")
			}
			switch change {
			case "manifest":
				manifest.Keep++
				raw, _ = json.Marshal(manifest)
				localWrite(t, source, raw)
			case "policy":
				p, _ := os.ReadFile(request.ScheduleFile)
				localWrite(t, request.ScheduleFile, append(p, '\n'))
			case "service":
				localWrite(t, filepath.Join(output, "backup.service"), []byte("ExecStart=/usr/bin/false"))
			case "helper":
				localWrite(t, manifest.Helper, []byte("untrusted replacement"))
			case "config":
				localWrite(t, request.Backup.HostConfig, []byte("central: {}"))
			case "schema":
				manifest.Schema--
				v, err := OpenVault(plan.config.DeploymentTrust.VaultKeyFile)
				if err != nil {
					t.Fatal(err)
				}
				manifest.Proof, _ = singleBackupUpgradeProof(v, manifest)
				raw, _ = json.Marshal(manifest)
				localWrite(t, source, raw)
			}
			if _, _, _, _, _, err := readSingleBackupUpgrade(context.Background(), source, "", ""); err == nil {
				t.Fatal("tampered/rebound material accepted")
			}
		})
	}
}

func TestSingleBackupUpgradeRejectsOtherInstallationAndInvalidPrivateRequest(t *testing.T) {
	plan, _ := newSingleBackupFixture(t)
	_, _, request, output := singleBackupUpgradeFixture(t, plan)
	other, _ := newSingleBackupFixture(t)
	changed := request
	changed.Backup = other.request
	if _, err := singleBackupUpgradeFiles(context.Background(), changed, output); err == nil {
		t.Fatal("upgrade redirected to another valid installation")
	}
	if _, err := singleBackupUpgradeFiles(context.Background(), request, filepath.Join(plan.spec.Root, "upgrade")); err == nil {
		t.Fatal("overlay placed inside immutable installation")
	}
	raw, _ := json.Marshal(request)
	for _, input := range [][]byte{append([]byte(`{"format":1,`), raw[1:]...), append(raw[:len(raw)-1:len(raw)-1], []byte(`,"command":"do-not-run"}`)...)} {
		source := filepath.Join(filepath.Dir(output), "invalid-request.json")
		localWrite(t, source, input)
		if err := singleBackupUpgradeCommand(context.Background(), Options{Action: "prepare-single-backup-upgrade", Source: source, Output: output}, io.Discard); err == nil {
			t.Fatal("duplicate or unknown request accepted")
		}
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("invalid request published an overlay")
	}
}

// Only a new synthetic installation is rebound to its isolated test schema.
// The production upgrade code never rewrites an installation or DSN file.
func singleBackupUpgradeBindTestDatabase(t *testing.T, s *Store, p singleBackupPlan) singleBackupPlan {
	t.Helper()
	var schema string
	if err := s.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("WEBSCAN_V3_TEST_DSN"))
	if err != nil || dsn.Scheme != "postgres" && dsn.Scheme != "postgresql" {
		t.Fatal("isolated PostgreSQL URL required")
	}
	query := dsn.Query()
	query.Set("search_path", schema)
	dsn.RawQuery = query.Encode()
	localWrite(t, p.config.Database.DSNFile, []byte(dsn.String()))
	raw, err := os.ReadFile(p.request.Installation)
	var install singleInstallManifest
	if err != nil || json.Unmarshal(raw, &install) != nil {
		t.Fatal("invalid synthetic installation")
	}
	install.Files["postgres.dsn"] = digest([]byte(dsn.String()))
	raw, _ = json.Marshal(install)
	localWrite(t, p.request.Installation, raw)
	if err := saveSingleJournal(p.spec.Root, singleInstallJournal{Format: 1, Manifest: digest(raw), Step: 6}); err != nil {
		t.Fatal(err)
	}
	if err := s.BindCluster(context.Background(), p.config); err != nil {
		t.Fatal(err)
	}
	p, err = planSingleBackup(context.Background(), p.request, p.output)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSingleBackupUpgradePostgresPolicyAndRestartContinuity(t *testing.T) {
	s := testStore(t)
	plan, _ := newSingleBackupFixture(t)
	plan = singleBackupUpgradeBindTestDatabase(t, s, plan)
	_, original, request, output := singleBackupUpgradeFixture(t, plan)
	if err := s.configureSingleBackup(context.Background(), plan.spec.Instance, original); err != nil {
		t.Fatal(err)
	}
	publishSingleBackupUpgradeFixture(t, request, output)
	ctx := context.Background()
	for attempt := 0; attempt < 2; attempt++ {
		p, old, next, raw, _, err := readSingleBackupUpgrade(ctx, filepath.Join(output, "upgrade.json"), "", "")
		if err != nil {
			t.Fatal(err)
		}
		current, enabled, err := checkSingleBackupUpgradeStore(ctx, old, next, raw)
		if err != nil || !enabled {
			t.Fatal("new helper could not read original enabled policy", err)
		}
		// The direct runner bypasses only timer's wall-clock due gate; it uses
		// real PostgreSQL and the same stable original policy identity.
		r, err := current.runSingleBackupSchedule(ctx, p, next, raw)
		current.DB.Close()
		if err != nil || attempt == 0 && r.State != "captured" || attempt == 1 && r.State != "not-due" {
			t.Fatal("restart repeated or failed backup", r, err)
		}
		if r.Receipt != nil {
			m, err := verifySingleBackup(ctx, r.Receipt.Directory, r.Receipt.ManifestSHA256)
			if err != nil {
				t.Fatal(err)
			}
			found, oldPolicy := false, false
			for _, source := range m.Sources {
				found = found || source.Path == output
				oldPolicy = oldPolicy || source.Path == request.ScheduleFile || source.Directory && singleBackupContains(source.Path, request.ScheduleFile)
			}
			if !found || !oldPolicy {
				t.Fatal("archive omitted upgraded or original maintenance package")
			}
		}
	}
	var hash string
	if err := s.DB.QueryRow(`SELECT sha256 FROM v3_single_backup_policies WHERE instance=$1`, plan.spec.Instance).Scan(&hash); err != nil || hash != digest(original) || tableCount(t, s, "v3_single_backup_runs") != 1 {
		t.Fatal("original policy or persistent run identity changed", err)
	}
	if _, err := s.DB.Exec(`UPDATE v3_single_backup_policies SET enabled=false`); err != nil {
		t.Fatal(err)
	}
	_, old, next, raw, _, err := readSingleBackupUpgrade(ctx, filepath.Join(output, "upgrade.json"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	current, enabled, err := checkSingleBackupUpgradeStore(ctx, old, next, raw)
	if err != nil || enabled {
		t.Fatal("check silently enabled a restored policy", err)
	}
	current.DB.Close()
	if err := enableSingleBackupUpgradePolicy(ctx, s, plan.spec.Instance, append(append([]byte{}, raw...), '\n')); err == nil {
		t.Fatal("another policy identity enabled restored policy")
	}
	if err := enableSingleBackupUpgradePolicy(ctx, s, plan.spec.Instance, raw); err != nil {
		t.Fatal("explicit original-policy enable failed", err)
	}
	if err := s.DB.QueryRow(`SELECT enabled FROM v3_single_backup_policies`).Scan(&enabled); err != nil || !enabled {
		t.Fatal("explicit enable did not persist", err)
	}
	for _, changed := range []string{"sha256", "policy"} {
		if changed == "sha256" {
			_, err = s.DB.Exec(`UPDATE v3_single_backup_policies SET sha256=$1`, digest([]byte("other-policy")))
		} else {
			_, err = s.DB.Exec(`UPDATE v3_single_backup_policies SET policy='{}'::jsonb`)
		}
		if err != nil {
			t.Fatal(err)
		}
		if current, _, err := checkSingleBackupUpgradeStore(ctx, old, next, raw); err == nil {
			current.DB.Close()
			t.Fatal("changed stored policy accepted", changed)
		}
		if _, err = s.DB.Exec(`UPDATE v3_single_backup_policies SET sha256=$1,policy=$2`, digest(raw), string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`DELETE FROM v3_schema WHERE version=$1`, SchemaVersion); err != nil {
		t.Fatal(err)
	}
	if current, _, err := checkSingleBackupUpgradeStore(ctx, old, next, raw); err == nil {
		current.DB.Close()
		t.Fatal("unmigrated database accepted by new maintenance helper")
	}
	var schema int
	if err := s.DB.QueryRow(`SELECT max(version) FROM v3_schema`).Scan(&schema); err != nil || schema == SchemaVersion {
		t.Fatal("maintenance silently migrated the database", err)
	}
}

func TestSingleBackupUpgradeRejectsAnotherSchemaWithIdenticalCluster(t *testing.T) {
	s, other := testStore(t), testStore(t)
	plan, _ := newSingleBackupFixture(t)
	plan = singleBackupUpgradeBindTestDatabase(t, s, plan)
	_, original, request, output := singleBackupUpgradeFixture(t, plan)
	for _, store := range []*Store{s, other} {
		if err := store.BindCluster(context.Background(), plan.config); err != nil {
			t.Fatal(err)
		}
		if err := store.configureSingleBackup(context.Background(), plan.spec.Instance, original); err != nil {
			t.Fatal(err)
		}
	}
	var otherSchema string
	if err := other.DB.QueryRow(`SELECT current_schema()`).Scan(&otherSchema); err != nil {
		t.Fatal(err)
	}
	dsn, _ := url.Parse(os.Getenv("WEBSCAN_V3_TEST_DSN"))
	query := dsn.Query()
	query.Set("search_path", otherSchema)
	dsn.RawQuery = query.Encode()
	newDSN := filepath.Join(filepath.Dir(request.Backup.HostConfig), "other-schema.dsn")
	localWrite(t, newDSN, []byte(dsn.String()))
	for _, file := range []string{request.Backup.HostConfig, request.Backup.APIConfig} {
		raw, _ := os.ReadFile(file)
		c, err := decodeSingleBackupConfig(raw)
		if err != nil {
			t.Fatal(err)
		}
		c.Database.DSNFile = newDSN
		raw, _ = yaml.Marshal(c)
		localWrite(t, file, raw)
	}
	if _, err := singleBackupUpgradeFiles(context.Background(), request, output); err == nil {
		t.Fatal("offline preparation accepted a changed installation DSN path")
	}
	before, err := singleBackupUpgradeDatabaseIdentity(context.Background(), s.DB)
	if err != nil {
		t.Fatal(err)
	}
	after, err := singleBackupUpgradeDatabaseIdentity(context.Background(), other.DB)
	if err != nil || before == after {
		t.Fatal("database identity did not include the actual namespace", err)
	}
	// Defence in depth: the database check also rejects a redirected plan,
	// even before considering the stricter installation-path validation.
	next := plan
	next.config.Database.DSNFile = newDSN
	if current, _, err := checkSingleBackupUpgradeStore(context.Background(), plan, next, original); err == nil {
		current.DB.Close()
		t.Fatal("matching cluster payload in a different schema accepted")
	}
	if tableCount(t, s, "v3_single_backup_runs") != 0 || tableCount(t, other, "v3_single_backup_runs") != 0 {
		t.Fatal("failed binding check created a backup job")
	}
}
