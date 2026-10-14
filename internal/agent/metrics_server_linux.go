//go:build linux

package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
	"webscan/internal/common"
)

func (a *Agent) startMetrics(ctx context.Context) error {
	c := common.M(a.C["metrics"])
	if len(c) == 0 {
		return nil
	}
	port := common.I(c["port"])
	if port < 1024 || port > 65535 {
		return fmt.Errorf("invalid metrics port")
	}
	allowed := net.ParseIP(common.S(c["allowed_source_ip"]))
	if allowed == nil {
		return fmt.Errorf("invalid metrics source")
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	srv.Handler = a.metricsHandler(allowed)
	l, e := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if e != nil {
		return e
	}
	if common.B(c["tls_enabled"]) {
		pair, e := tls.LoadX509KeyPair(common.S(c["cert_file"]), common.S(c["key_file"]))
		if e != nil {
			l.Close()
			return e
		}
		raw, e := os.ReadFile(common.S(c["ca_file"]))
		pool := x509.NewCertPool()
		if e != nil || !pool.AppendCertsFromPEM(raw) {
			l.Close()
			return fmt.Errorf("invalid metrics CA")
		}
		l = tls.NewListener(l, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert})
	}
	a.worker.Add(1)
	go func() {
		defer a.worker.Done()
		go func() { <-ctx.Done(); srv.Close() }()
		if e := srv.Serve(l); e != nil && e != http.ErrServerClosed {
			fmt.Println("metrics_server_error")
			a.counter("metrics_server_failed", 1, true)
		}
	}()
	return nil
}

func (a *Agent) metricsHandler(allowed net.IP) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if e != nil || ip == nil || (!ip.Equal(allowed) && !ip.IsLoopback()) {
			http.Error(w, "forbidden", 403)
			return
		}
		if r.Method != "GET" || r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		raw, e := os.ReadFile(common.S(a.C["metrics_file"]))
		if e != nil {
			http.Error(w, "metrics unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.Write(raw)
	})
}
