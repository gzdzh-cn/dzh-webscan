package central

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
	"webscan/internal/common"
)

func TestNetworkPreflightIsInternalAuthenticatedAndBounded(t *testing.T) {
	s := consoleFixture(t)
	s.Config["alert_token"] = "fixture-preflight-token"
	for _, tc := range []struct {
		path, auth, body string
		public           bool
		want             int
	}{
		{"/node-preflight", "", `{}`, false, 401},
		{"/node-preflight", "wrong", `{}`, false, 401},
		{"/node-preflight", "fixture-preflight-token", `{"node":"a","probe":{"host":"127.0.0.1","port":19100}}`, false, 400},
		{"/node-preflight", "fixture-preflight-token", `{"node":"a","probe":{"host":"192.0.2.1","port":19100},"url":"http://secret/"}`, false, 400},
		{"/node-preflight", "fixture-preflight-token", `{"node":"a","probe":{"host":"192.0.2.1","port":19100,"event_token":"forbidden"}}`, false, 400},
		{"/node-preflight", "fixture-preflight-token", `{"node":"a","probe":{"host":"192.0.2.1","port":19100}}`, false, 200},
	} {
		r := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer "+tc.auth)
		w := httptest.NewRecorder()
		s.Handler(w, r)
		if w.Code != tc.want {
			t.Fatal(tc, w.Code, w.Body.String())
		}
	}
	// Public event ingress cannot invoke the new internal diagnostic route.
	r := httptest.NewRequest("POST", "/node-preflight", bytes.NewReader(common.JSON(common.Map{})))
	r.Header.Set("Authorization", "Bearer fixture-preflight-token")
	r.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.publicHTTPHandler(w, r)
	if w.Code != 404 && w.Code != 403 {
		t.Fatal("public diagnostic route exposed", w.Code)
	}
}
