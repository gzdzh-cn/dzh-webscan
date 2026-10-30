//go:build linux

package nodeops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"webscan/internal/agent"
	"webscan/internal/common"
	"webscan/internal/persist"
	agentv1 "webscan/sdk/agent/v1"
)

// Uses the real current Agent constructor, SQLite lock, migration and pull
// queue, without starting service management or scanner/notification workers.
// Fixed Agent paths exist only in an explicitly opted-in disposable container.
func TestLegacyReconciliationFeedsRealAgentPullQueue(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_LEGACY_IMPORT") != "1" {
		t.Skip("requires opted-in disposable Linux legacy import container")
	}
	for _, path := range []string{agentDataDirectory, agentLogDirectory} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing existing Agent data", path, err)
		}
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(path) })
	}
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	r.Spec.MonitorDirectories = []string{testRoot(t)}
	attachConfiguration(t, w, &r, nil)
	if _, err := w.Apply(r); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(w.configurationDir(r.Spec), "runtime.json")
	db, err := persist.OpenDB(filepath.Join(agentDataDirectory, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(agent.Schema + agent.IndexSchema); err != nil {
		db.Close()
		t.Fatal(err)
	}
	for _, id := range []string{"known", "confirmed"} {
		if _, err := db.Exec(`INSERT INTO events(id,payload,created,accepted) VALUES(?,?,1,?)`, id, legacyImportEvent(id), map[string]any{"known": nil, "confirmed": 42}[id]); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	input := legacyImportEvent("only-in-log") + "\n" + legacyImportEvent("known") + "\n" + legacyImportEvent("confirmed") + "\n"
	if err := os.WriteFile(filepath.Join(agentLogDirectory, "events-legacy.jsonl"), []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	// Service ownership here is synthetic: this test proves the data handoff,
	// and does not certify a v2 systemd/Docker installation or a network listener.
	host := &backupHostFixture{installed: Installation{Node: r.Node, Generation: "v2", Mode: "native", Runtime: configPath, Services: []ServiceRecord{}}}
	b := &transitionBackup{root: w.root, data: agentDataDirectory, logs: agentLogDirectory, host: host}
	r.Phase = "backup"
	if _, err := b.run(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := acquireServiceOperation(context.Background(), w.root)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := b.agentLock()
	if err != nil {
		release()
		t.Fatal(err)
	}
	r.Phase = "activate"
	err = b.reconcileLegacyLogsLocked(ctx, r)
	lock.Close()
	release()
	if err != nil {
		t.Fatal(err)
	}
	read := func() *agent.Agent {
		config, err := common.ReadJSON(configPath)
		if err != nil {
			t.Fatal(err)
		}
		a, err := agent.New(config, configPath)
		if err != nil {
			t.Fatal("real Agent rejected reconciled DB", err)
		}
		if a.Pull == nil {
			a.Close()
			t.Fatal("pull queue unavailable")
		}
		return a
	}
	a := read()
	batch, err := a.Pull.Fetch(context.Background(), 1, 100, 0)
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, event := range batch.Events {
		seen[event.Id] = true
		var payload map[string]json.RawMessage
		if json.Unmarshal(event.Json, &payload) != nil || string(payload["sequence"]) != "9007199254740993" {
			a.Close()
			t.Fatal("event digits changed")
		}
	}
	if len(seen) != 2 || !seen["known"] || !seen["only-in-log"] || seen["confirmed"] {
		a.Close()
		t.Fatal("reconciled pull queue incorrect", seen)
	}
	a.Close() // Lost response: no ACK. The same SQLite is reopened by a new Agent.
	a = read()
	defer a.Close()
	batch, err = a.Pull.Fetch(context.Background(), 2, 100, 0)
	if err != nil || len(batch.Events) != 2 {
		t.Fatal("restart lost imported event", err)
	}
	ids := []string{}
	for _, event := range batch.Events {
		if !seen[event.Id] {
			t.Fatal("restart replaced original ID")
		}
		ids = append(ids, event.Id)
	}
	confirmed, err := a.Pull.Ack(context.Background(), &agentv1.AckEventsRequest{Epoch: 2, Receipt: batch.Receipt, Accepted: ids})
	if err != nil || confirmed != 2 {
		t.Fatal("imported events not confirmable", confirmed, err)
	}
	batch, err = a.Pull.Fetch(context.Background(), 2, 100, 0)
	if err != nil || len(batch.Events) != 0 {
		t.Fatal("confirmed import reappeared", err)
	}
	var n int
	if err := a.DB.QueryRow(`SELECT count(*) FROM events WHERE id='confirmed' AND accepted=42`).Scan(&n); err != nil || n != 1 {
		t.Fatal("old confirmation lost", n, err)
	}
}
