package diagnostic

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func availablePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func runProbe(t *testing.T, p Probe) (Result, io.WriteCloser, <-chan error) {
	t.Helper()
	input, writer := io.Pipe()
	out, output := io.Pipe()
	done := make(chan error, 1)
	go func() { defer output.Close(); defer input.Close(); done <- Run(context.Background(), input, output) }()
	b, _ := json.Marshal(p)
	go func() { writer.Write(append(b, '\n')) }()
	var result Result
	if e := json.NewDecoder(bufio.NewReader(out)).Decode(&result); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { writer.Close(); out.Close() })
	return result, writer, done
}
func TestTemporaryProbeTLSAuthenticationAndCleanup(t *testing.T) {
	p, e := NewTLS("127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	p.Port = availablePort(t)
	p.Token = strings.Repeat("a", 64)
	p.Listen = true
	p.AllowedSource = "127.0.0.1"
	result, writer, done := runProbe(t, p)
	if !result.Ready {
		t.Fatal(result)
	}
	client, e := Client(p.CA, p.ClientCert, p.ClientKey)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	url := "https://127.0.0.1:" + strconv.Itoa(p.Port) + "/__webscan_preflight"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != 200 || body["challenge"] != p.Token || body["source"] != "127.0.0.1" {
		t.Fatal(resp.Status, body)
	}
	bad, _ := Client(p.CA, "", "")
	if resp, e := bad.Get(url); e == nil {
		resp.Body.Close()
		t.Fatal("missing client certificate accepted")
	}
	bad.CloseIdleConnections()
	req.Header.Set("Authorization", "Bearer wrong")
	resp, e = client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("wrong token accepted")
	}
	writer.Close()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SSH EOF did not stop listener")
	}
	l, e := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(p.Port))
	if e != nil {
		t.Fatal("probe left port occupied", e)
	}
	l.Close()
}
func TestOccupiedPortAndEmptyReceiptDoNotAffectBusiness(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/webscan/v1/receipts" {
			t.Error("wrong request")
		}
		raw, _ := io.ReadAll(r.Body)
		if string(raw) != `{"event_ids":[]}` {
			t.Error("probe submitted events")
		}
		w.WriteHeader(401)
	}))
	defer server.Close()
	listener, e := net.Listen("tcp", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	p := Probe{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Token: strings.Repeat("b", 32), Listen: true, EventURL: server.URL}
	result, writer, done := runProbe(t, p)
	writer.Close()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if result.Ready || !result.Occupied || result.EventStatus != 401 || calls != 1 {
		t.Fatal(result, calls)
	}
}
func TestSourceRestriction(t *testing.T) {
	p := Probe{Host: "127.0.0.1", Port: availablePort(t), Token: strings.Repeat("c", 32), Listen: true, AllowedSource: "192.0.2.1"}
	_, writer, done := runProbe(t, p)
	req, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(p.Port)+"/__webscan_preflight", nil)
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp.Status)
	}
	writer.Close()
	<-done
}
