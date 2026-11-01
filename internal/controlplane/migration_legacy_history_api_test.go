package controlplane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLegacyMigrationHistoryAPIStrictReadOnly(t *testing.T) {
	for _, tc := range []struct {
		method, role, path string
		sessions           bool
		want               int
	}{
		{"POST", "admin", "", false, 405}, {"GET", "viewer", "", false, 403},
		{"GET", "admin", "?url=https://private.invalid", false, 400},
		{"GET", "admin", "?session=x&session=y", false, 400},
		{"GET", "admin", "?limit=201", false, 400},
		{"GET", "admin", "?session=bad", false, 400},
		{"GET", "admin", "?session=" + strings.Repeat("a", 64) + "&table=arbitrary", false, 400},
		{"GET", "admin", "?command=private", true, 400},
	} {
		w := httptest.NewRecorder()
		(&API{}).legacyMigrationHistory(w, httptest.NewRequest(tc.method, "/api/v3/legacy-history"+tc.path, nil), identity{Role: tc.role}, tc.sessions)
		if w.Code != tc.want || strings.Contains(w.Body.String(), "private.invalid") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestLegacyMigrationHistoryAPIActualPGPaginationAndProjection(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	session := digest([]byte(t.Name()))
	if _, err := s.BeginMigrationSession(ctx, session, 0, []string{"host-manager"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		if _, err := s.DB.Exec(`INSERT INTO v3_legacy_history(id,session,source_id,role,table_name,record_key,payload)VALUES($1,$2,'source','host-manager','jobs',$3,'{"status":"complete","read_only":true}')`, id, session, int(id[0])); err != nil {
			t.Fatal(err)
		}
	}
	a := &API{Store: s}
	request := func(path string, sessions bool) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.legacyMigrationHistory(w, httptest.NewRequest("GET", path, nil), identity{Role: "admin"}, sessions)
		return w
	}
	w := request("/api/v3/migration-history/sessions", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"history_records":2`) || strings.Contains(w.Body.String(), "snapshot") {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request("/api/v3/legacy-history?session="+session+"&limit=1", false)
	var page MigrationLegacyHistoryPage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 || !page.ReadOnly || page.NextCursor == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request("/api/v3/legacy-history?session="+session+"&limit=1&cursor="+page.NextCursor, false)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.NextCursor != "" || page.Items[0].ID != strings.Repeat("b", 64) {
		t.Fatal(w.Code, w.Body.String())
	}
}
