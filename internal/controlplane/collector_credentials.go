package controlplane

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"time"

	"webscan/internal/nodepki"
)

// All provisioning/restore checks read the same active identity as transport.
// The legacy split files are retained when identity_file is absent.
func collectorIdentityMaterial(c Config, now time.Time) (nodepki.Bundle, error) {
	if c.Collector.IdentityFile != "" {
		b, _, err := nodepki.ReadIdentity(c.Collector.CAFile, c.Collector.IdentityFile, nodepki.Collector, "", now)
		return b, err
	}
	cert, key, err := configurationLocalPair(c.Collector.CertFile, c.Collector.KeyFile)
	return nodepki.Bundle{Certificate: cert, Key: key}, err
}

func CollectorTLS(c Config) (*tls.Config, error) {
	t, _, err := collectorTLSIdentity(c)
	return t, err
}

func collectorTLSIdentity(c Config) (*tls.Config, *nodepki.LiveIdentity, error) {
	raw, err := os.ReadFile(c.Collector.CAFile)
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(raw) {
		return nil, nil, errors.New("采集 CA 不正确")
	}
	t := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	if c.Collector.IdentityFile != "" {
		// Instance is a process lease ID, not necessarily the signed identity.
		live, err := nodepki.NewLiveIdentity(c.Collector.CAFile, c.Collector.IdentityFile, nodepki.Collector, "", time.Now())
		if err != nil {
			return nil, nil, errors.New("无法加载采集器受管理证书")
		}
		t.GetClientCertificate = live.GetClientCertificate
		return t, live, nil
	}
	if _, err := ReadSecret(c.Collector.KeyFile); err != nil {
		return nil, nil, err
	}
	pair, err := tls.LoadX509KeyPair(c.Collector.CertFile, c.Collector.KeyFile)
	if err != nil {
		return nil, nil, errors.New("无法加载采集器证书")
	}
	t.Certificates = []tls.Certificate{pair}
	return t, nil, nil
}
