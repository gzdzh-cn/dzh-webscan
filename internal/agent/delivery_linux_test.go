//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"webscan/internal/common"
)

func directAgent(t *testing.T) (*Agent, context.Context) {
	a, ctx := testAgent(t)
	a.C["direct_transport"] = true
	a.C["max_request_mib"] = 2
	if e := a.directSchema(); e != nil {
		t.Fatal(e)
	}
	return a, ctx
}
func insertDelivery(t *testing.T, a *Agent, id string, exported any) {
	t.Helper()
	p := string(common.JSON(common.Map{"event_id": id, "node_id": "test"}))
	if _, e := a.DB.Exec("INSERT INTO events(id,payload,created,exported) VALUES(?,?,?,?)", id, p, common.Now(), exported); e != nil {
		t.Fatal(e)
	}
}
func deliveryRemaining(a *Agent) int {
	var n int
	a.DB.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL AND id NOT IN(SELECT id FROM delivery_failures)").Scan(&n)
	return n
}
func TestDirectDeliveryPartialRetryAndLegacyExported(t *testing.T) {
	a, ctx := directAgent(t)
	insertDelivery(t, a, "first", "old.jsonl")
	insertDelivery(t, a, "second", nil)
	var mu sync.Mutex
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var p []common.Map
		json.NewDecoder(r.Body).Decode(&p)
		calls++
		ids := []string{}
		for _, v := range p {
			ids = append(ids, common.S(v["event_id"]))
		}
		if calls == 1 {
			ids = ids[:1]
		}
		w.Write(common.JSON(common.Map{"accepted": ids}))
	}))
	defer s.Close()
	a.C["public_url"] = s.URL
	if e := a.DirectExport(ctx); e == nil {
		t.Fatal("partial confirmation accepted as complete")
	}
	if deliveryRemaining(a) != 1 {
		t.Fatal("lost unconfirmed event")
	}
	if e := a.DirectExport(ctx); e != nil {
		t.Fatal(e)
	}
	if deliveryRemaining(a) != 0 {
		t.Fatal("retry failed")
	}
}
func TestDirectRejectIsolationAndPausedQueue(t *testing.T) {
	a, ctx := directAgent(t)
	insertDelivery(t, a, "bad", nil)
	insertDelivery(t, a, "good", nil)
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var p []common.Map
		json.NewDecoder(r.Body).Decode(&p)
		ids := []string{}
		for _, v := range p {
			if common.S(v["event_id"]) == "bad" {
				http.Error(w, "invalid_event", 400)
				return
			}
			ids = append(ids, common.S(v["event_id"]))
		}
		w.Write(common.JSON(common.Map{"accepted": ids}))
	}))
	defer s.Close()
	a.C["public_url"] = s.URL
	pause := filepath.Join(a.Data, "transport-paused")
	os.WriteFile(pause, []byte("test"), 0600)
	if e := a.DirectExport(ctx); e != nil || calls != 0 {
		t.Fatal(e, calls)
	}
	os.Remove(pause)
	if e := a.DirectExport(ctx); e != nil {
		t.Fatal(e)
	}
	var bad int
	if e := a.DB.QueryRow("SELECT count(*) FROM delivery_failures WHERE id='bad'").Scan(&bad); e != nil || bad != 1 {
		t.Fatal(e, bad)
	}
	var accepted float64
	if e := a.DB.QueryRow("SELECT accepted FROM events WHERE id='good'").Scan(&accepted); e != nil || accepted == 0 {
		t.Fatal(e)
	}
	if e := a.DirectExport(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestResponseLostUsesDurableReceipts(t *testing.T) {
	a, ctx := directAgent(t)
	insertDelivery(t, a, "lost", nil)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/events") {
			http.Error(w, "response lost", 503)
			return
		}
		w.Write([]byte(`{"accepted":["lost"]}`))
	}))
	defer s.Close()
	a.C["public_url"] = s.URL
	_ = a.DirectExport(ctx)
	if deliveryRemaining(a) != 0 {
		t.Fatal("center receipt ignored")
	}
}
func TestLegacyImportAndRollbackPreserveIDsAndHistory(t *testing.T) {
	a, ctx := directAgent(t)
	insertDelivery(t, a, "unconfirmed", nil)
	os.WriteFile(filepath.Join(a.Logs, "events-old.jsonl"), []byte(`{"event_id":"old","node_id":"test"}`+"\n"), 0600)
	if e := importLegacyLogs(ctx, a.DB, a.Logs); e != nil {
		t.Fatal(e)
	}
	if e := importLegacyLogs(ctx, a.DB, a.Logs); e != nil {
		t.Fatal(e)
	}
	if deliveryRemaining(a) != 2 {
		t.Fatal("legacy IDs not idempotent")
	}
	if e := PrepareLegacyDelivery(ctx, a.Data, a.Logs); e != nil {
		t.Fatal(e)
	}
	var n int
	a.DB.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL AND exported IS NOT NULL").Scan(&n)
	if n != 2 {
		t.Fatal("rollback omitted events")
	}
	if _, e := New(a.C, a.ConfigPath); e == nil {
		t.Fatal("second writer acquired process lock")
	}
}
func TestDirectRequestBoundedAndNoFalseAcknowledgement(t *testing.T) {
	a, ctx := directAgent(t)
	a.C["max_request_mib"] = 1
	insertDelivery(t, a, "huge", nil)
	raw := string(common.JSON(common.Map{"event_id": "huge", "padding": strings.Repeat("a", 2<<20)}))
	a.DB.Exec("UPDATE events SET payload=? WHERE id='huge'", raw)
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; fmt.Fprint(w, `{"accepted":[]}`) }))
	defer s.Close()
	a.C["public_url"] = s.URL
	if e := a.DirectExport(ctx); e != nil {
		t.Fatal(e)
	}
	if calls != 0 {
		t.Fatal("oversized request sent")
	}
	var confirmed int
	a.DB.QueryRow("SELECT count(*) FROM events WHERE id='huge' AND accepted IS NOT NULL").Scan(&confirmed)
	if confirmed != 0 {
		t.Fatal("invalid event falsely confirmed")
	}
}
