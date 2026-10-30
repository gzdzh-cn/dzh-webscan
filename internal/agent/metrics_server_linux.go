//go:build linux

package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"golang.org/x/net/http2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/nodepki"
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"
)

func (a *Agent) startMetrics(ctx context.Context) error {
	c := common.M(a.C["metrics"])
	pc := common.M(a.C["pull"])
	if (common.B(pc["revocation_updates"]) || common.B(pc["identity_renewal"])) && (a.Pull == nil || len(c) == 0) {
		return fmt.Errorf("trust updates require a pull metrics listener")
	}
	if len(c) == 0 {
		return nil
	}
	if common.S(c["identity_file"]) != "" && (a.Pull == nil || !common.B(c["tls_enabled"]) || common.S(c["cert_file"]) != "" || common.S(c["key_file"]) != "") {
		return fmt.Errorf("managed identity requires pull TLS and cannot use split key files")
	}
	if common.B(pc["identity_renewal"]) && (!common.B(c["tls_enabled"]) || common.S(pc["revocation_state_directory"]) == "" || common.S(pc["revocation_file"]) == "" || common.S(c["identity_file"]) != filepath.Join(a.Data, "pki-identity", "active.pem")) {
		return fmt.Errorf("identity renewal requires managed pull TLS in the node data directory and persistent revocation policy")
	}
	port := common.I(c["port"])
	if port < 1024 || port > 65535 {
		return fmt.Errorf("invalid metrics port")
	}
	allowed := net.ParseIP(common.S(c["allowed_source_ip"]))
	if allowed == nil && a.Pull == nil {
		return fmt.Errorf("invalid metrics source")
	}
	if seed := common.S(c["identity_seed_directory"]); seed != "" {
		file := common.S(c["identity_file"])
		// Restrict seeded state to the node data directory shared by both
		// deployment modes. A split or unrelated identity cannot be overwritten.
		if a.Pull == nil || !common.B(c["tls_enabled"]) || file != filepath.Join(a.Data, "pki-identity", "active.pem") {
			return fmt.Errorf("seeded node identity requires managed pull TLS in the node data directory")
		}
		if _, err := nodepki.SeedNodeIdentity(ctx, common.S(c["ca_file"]), seed, filepath.Dir(file), a.Pull.NodeID, time.Now()); err != nil {
			return fmt.Errorf("node identity initialization or validation failed; existing state preserved")
		}
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	srv.Handler = a.metricsHandler(allowed)
	if a.Pull != nil {
		var policies []func(*x509.Certificate) error
		var updater pull.TrustUpdater
		var identityTrust *nodepki.FileTrust
		stateDirectory := common.S(pc["revocation_state_directory"])
		if common.B(pc["revocation_updates"]) && (stateDirectory == "" || common.S(pc["revocation_file"]) == "" || !common.B(c["tls_enabled"])) {
			return fmt.Errorf("trust updates require pull TLS and persistent revocation state")
		}
		if stateDirectory != "" && common.S(pc["revocation_file"]) == "" {
			return fmt.Errorf("persistent certificate policy requires a revocation file")
		}
		if file := common.S(pc["revocation_file"]); file != "" {
			if !common.B(c["tls_enabled"]) {
				return fmt.Errorf("certificate policy requires metrics TLS")
			}
			var trust *nodepki.FileTrust
			var err error
			if common.B(pc["revocation_updates"]) {
				var receiver *nodepki.ReceiverTrust
				receiver, err = nodepki.NewReceiverTrust(common.S(c["ca_file"]), file, stateDirectory, time.Now())
				if err == nil {
					trust = receiver.FileTrust
					updater = func(ctx context.Context, cert *x509.Certificate, raw []byte) (*agentv1.UpdateTrustResponse, error) {
						receipt, err := receiver.Publish(ctx, cert, raw, time.Now())
						if err != nil {
							return nil, err
						}
						return &agentv1.UpdateTrustResponse{NodeId: a.Pull.NodeID, CrlSha256: receipt.SHA256, CrlNumber: receipt.Number, NextUpdateUnix: receipt.NextUpdate.Unix()}, nil
					}
				}
			} else if stateDirectory != "" {
				trust, err = nodepki.NewPersistentFileTrust(common.S(c["ca_file"]), file, stateDirectory, time.Now())
			} else {
				trust, err = nodepki.NewFileTrust(common.S(c["ca_file"]), file, time.Now())
			}
			if err != nil {
				return fmt.Errorf("invalid pull certificate revocation policy")
			}
			identityTrust = trust
			policies = append(policies, func(cert *x509.Certificate) error {
				id, err := nodepki.PeerID(cert, nodepki.Collector)
				if err != nil {
					return err
				}
				return trust.Verify(cert, nodepki.Collector, id, time.Now())
			})
		}
		var renewer pull.IdentityRenewer
		if common.B(pc["identity_renewal"]) {
			renewer = &nodeIdentityRenewer{caFile: common.S(c["ca_file"]), identityFile: common.S(c["identity_file"]), node: a.Pull.NodeID, trust: identityTrust}
		}
		grpcServer := pull.NewServerWithManagedIdentity(a.Pull, common.SS(pc["collector_identities"]), updater, renewer, policies...)
		legacy := srv.Handler
		srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
				grpcServer.ServeHTTP(w, r)
				return
			}
			for _, policy := range policies {
				if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || policy(r.TLS.PeerCertificates[0]) != nil {
					http.Error(w, "certificate policy denied", http.StatusForbidden)
					return
				}
			}
			legacy.ServeHTTP(w, r)
		})
		// Long polls have individual RPC deadlines; legacy server write timeouts
		// must not abort a healthy 25-second HTTP/2 stream.
		srv.ReadTimeout, srv.WriteTimeout = 0, 0
		if e := http2.ConfigureServer(srv, &http2.Server{MaxConcurrentStreams: 16}); e != nil {
			return e
		}
		go func() { <-ctx.Done(); grpcServer.Stop() }()
	}
	l, e := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if e != nil {
		return e
	}
	if common.B(c["tls_enabled"]) {

		raw, e := os.ReadFile(common.S(c["ca_file"]))
		pool := x509.NewCertPool()
		if e != nil || !pool.AppendCertsFromPEM(raw) {
			l.Close()
			return fmt.Errorf("invalid metrics CA")
		}
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
		if file := common.S(c["identity_file"]); file != "" {
			live, err := nodepki.NewLiveIdentity(common.S(c["ca_file"]), file, nodepki.Node, a.Pull.NodeID, time.Now())
			if err != nil {
				l.Close()
				return fmt.Errorf("invalid managed node identity")
			}
			tlsConfig.GetCertificate = live.GetCertificate
		} else {
			pair, err := tls.LoadX509KeyPair(common.S(c["cert_file"]), common.S(c["key_file"]))
			if err != nil {
				l.Close()
				return err
			}
			tlsConfig.Certificates = []tls.Certificate{pair}
		}
		if a.Pull != nil {
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		}
		l = tls.NewListener(l, tlsConfig)
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
