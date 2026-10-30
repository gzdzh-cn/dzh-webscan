package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

func bootstrapStateForTest(s *Store, v *Vault, c Config) (privateBootstrapDraft, error) {
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		return privateBootstrapDraft{}, err
	}
	defer tx.Rollback()
	return readBootstrapDraftTx(context.Background(), tx, v, c)
}

func TestBootstrapDraftKeyRotationAndRuntimeBinding(t *testing.T) {
	s, f := newSavedConfigurationStore(t)
	doc, err := newConfigurationDocument(f.c, []byte(`{}`), 1, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	common.M(doc.Bootstrap["collector"])["concurrency"] = 32
	stage, revision := savedRestoreFromDocument(t, s, f, doc)
	raw, err := s.commitConfigurationRestoreSaved(context.Background(), f.v, f.c, "admin", "bootstrap-key-save", stage.ID, revision.Generation)
	_ = savedReceipt(t, raw, err)
	current, err := bootstrapStateForTest(s, nil, f.c)
	if err != nil || !current.Pending {
		t.Fatal("bootstrap reader could not open configured key", err)
	}
	next, path := testVault(t)
	if _, err := bootstrapStateForTest(s, next, f.c); err == nil {
		t.Fatal("bootstrap accepted missing signing key")
	}
	rotated, err := OpenVault(path, f.c.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrapStateForTest(s, rotated, f.c); err != nil {
		t.Fatal("bootstrap rejected previous key", err)
	}
	tx, err := s.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = lockConfigurationRestoreStateTx(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if _, err = putBootstrapDraftTx(context.Background(), tx, rotated, f.c, current.Desired); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	updated, err := bootstrapStateForTest(s, next, f.c)
	if err != nil || updated.Generation <= current.Generation || !strings.HasPrefix(updated.Proof, next.active+":") {
		t.Fatal("new bootstrap proof did not rotate", err)
	}
	drift := f.c
	drift.Collector.Concurrency++
	if _, err = bootstrapStateForTest(s, rotated, drift); err == nil {
		t.Fatal("unconfirmed running bootstrap drift accepted")
	}
	// No business settings draft exists; bootstrap intent alone protects init.
	source := writeLegacySettings(t, legacySettingsFixture(t))
	if _, err = s.ImportLegacySettings(context.Background(), source, privateTestDir(t)); err == nil {
		t.Fatal("legacy init overwrote bootstrap-only saved state")
	}
}

func TestConfigurationSavedNormalizedProfilesAndLosslessNumbers(t *testing.T) {
	s, f := newSavedConfigurationStore(t)
	a, b := nodeFixture("number-a"), nodeFixture("number-b")
	a.Config = []byte(`{"private":{"counter":18446744073709551615,"decimal":1.234567890123456789,"exponent":1e3,"negative_zero":-0}}`)
	b.Config = []byte(`{"private":{"counter":18446744073709551615,"decimal":1.234567890123456789,"exponent":1000,"negative_zero":0}}`)
	doc, err := newConfigurationDocument(f.c, []byte(`{"email":{"enabled":false,"private_number":9007199254740993}}`), 1, []Node{a, b}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stage, revision := savedRestoreFromDocumentOptions(t, s, f, doc, configurationRestoreOptions{UseBackupCredentials: true})
	raw, err := s.commitConfigurationRestoreSaved(context.Background(), f.v, f.c, "admin", "normalized-restore", stage.ID, revision.Generation)
	_ = savedReceipt(t, raw, err)
	if _, _, err = savedStateForTest(s, f, stage.ID, true); err != nil {
		t.Fatal("PostgreSQL normalization invalidated saved proof", err)
	}
	for _, id := range []string{a.ID, b.ID} {
		var raw []byte
		if err := s.DB.QueryRow(`SELECT config FROM v3_nodes WHERE id=$1`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		v, err := common.Decode(raw)
		p := common.M(common.M(v)["private"])
		if err != nil || fmt.Sprint(p["counter"]) != "18446744073709551615" || fmt.Sprint(p["decimal"]) != "1.234567890123456789" || fmt.Sprint(p["exponent"]) != "1000" {
			t.Fatal("saved node numeric precision changed", err)
		}
	}
	draft := settingsStateForTest(t, s)
	var settings configurationValues
	if decodeConfigurationObject(draft.Desired, &settings) != nil || common.M(settings["email"])["private_number"] != json.Number("9007199254740993") {
		t.Fatal("saved settings numeric precision changed")
	}
}
