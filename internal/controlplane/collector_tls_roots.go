package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
)

// Each handshake gets a fresh immutable config and verified root pool. Keep
// Go's built-in chain/hostname/client-certificate verification enabled; root
// changes never mutate a tls.Config already in use by an HTTP/2 connection.
type collectorRootCredentials struct {
	mu     sync.Mutex
	config *tls.Config
	roots  func(time.Time) (*x509.CertPool, error)
}

func (c *collectorRootCredentials) configuration() (*tls.Config, error) {
	c.mu.Lock()
	config := c.config.Clone()
	c.mu.Unlock()
	pool, err := c.roots(time.Now())
	if err != nil {
		return nil, err
	}
	config.RootCAs = pool
	return config, nil
}

func (c *collectorRootCredentials) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	config, err := c.configuration()
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return credentials.NewTLS(config).ClientHandshake(ctx, authority, raw)
}

func (c *collectorRootCredentials) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	config, err := c.configuration()
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	return credentials.NewTLS(config).ServerHandshake(raw)
}

func (c *collectorRootCredentials) Info() credentials.ProtocolInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return credentials.NewTLS(c.config).Info()
}

func (c *collectorRootCredentials) Clone() credentials.TransportCredentials {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &collectorRootCredentials{config: c.config.Clone(), roots: c.roots}
}

func (c *collectorRootCredentials) OverrideServerName(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	config := c.config.Clone()
	config.ServerName = name
	c.config = config
	return nil
}
