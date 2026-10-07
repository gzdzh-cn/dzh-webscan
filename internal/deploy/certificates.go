package deploy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
)

func parseKey(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid_pki_private_key")
	}
	if key, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, e := x509.ParsePKCS1PrivateKey(block.Bytes); e == nil {
		return key, nil
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	return n
}
func certificates(c *Config) error {
	dir := filepath.Join(c.CentralRoot(), "pki")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	caBytes, e := os.ReadFile(filepath.Join(dir, "ca.crt"))
	var ca *x509.Certificate
	var signer crypto.Signer
	if e == nil {
		block, _ := pem.Decode(caBytes)
		if block == nil {
			return errors.New("invalid_ca_certificate")
		}
		ca, e = x509.ParseCertificate(block.Bytes)
		if e != nil {
			return e
		}
		key, e := os.ReadFile(filepath.Join(dir, "ca.key"))
		if e != nil {
			return e
		}
		signer, e = parseKey(key)
		if e != nil {
			return e
		}
		if time.Until(ca.NotAfter) < 30*24*time.Hour {
			return errors.New("ca_certificate_requires_renewal")
		}
	} else if os.IsNotExist(e) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		signer = key
		template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Webscan-Metrics-CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		b, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			return err
		}
		ca, err = x509.ParseCertificate(b)
		if err != nil {
			return err
		}
		caBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err = common.Atomic(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
			return err
		}
		if err = common.Atomic(filepath.Join(dir, "ca.crt"), caBytes, 0600); err != nil {
			return err
		}
	} else {
		return e
	}
	issue := func(name, host string, client bool) error {
		path := filepath.Join(dir, name)
		if b, e := os.ReadFile(path + ".crt"); e == nil {
			block, _ := pem.Decode(b)
			if block == nil {
				return errors.New("invalid_existing_certificate")
			}
			cert, e := x509.ParseCertificate(block.Bytes)
			if e != nil || time.Until(cert.NotAfter) < 30*24*time.Hour {
				return errors.New("existing_certificate_requires_renewal")
			}
			if _, err := tls.LoadX509KeyPair(path+".crt", path+".key"); err != nil {
				return errors.New("existing_certificate_key_mismatch")
			}
			if err := cert.CheckSignatureFrom(ca); err != nil {
				return errors.New("existing_certificate_ca_mismatch")
			}
			if !client {
				if err := cert.VerifyHostname(host); err != nil {
					return errors.New("existing_certificate_ip_mismatch")
				}
			}
			return nil
		} else if !os.IsNotExist(e) {
			return e
		}
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if client {
			usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(825 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
		if !client {
			cert.IPAddresses = []net.IP{net.ParseIP(host)}
		}
		b, e := x509.CreateCertificate(rand.Reader, cert, ca, key.Public(), signer)
		if e != nil {
			return e
		}
		kb, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		if e = common.Atomic(path+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0600); e != nil {
			return e
		}
		return common.Atomic(path+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), 0600)
	}
	if e = issue("client", "webscan-prometheus", true); e != nil {
		return e
	}
	u, _ := url.Parse(common.S(common.M(c.Raw["central"])["public_url"]))
	if e = issue("central-"+strings.ReplaceAll(u.Hostname(), ".", "-"), u.Hostname(), false); e != nil {
		return e
	}
	for _, n := range c.Nodes {
		if !common.B(n["enabled"]) {
			continue
		}
		if e = issue(common.S(n["id"]), common.S(n["host"]), false); e != nil {
			return e
		}
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		if e = common.Atomic(filepath.Join(dir, "prometheus", name), b, 0600); e != nil {
			return e
		}
	}
	return nil
}
