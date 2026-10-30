package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

func TestManagedCollectorIdentityUsedByProvisioningAndIssuance(t *testing.T) {
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	now := time.Now().UTC().Truncate(time.Second)
	f.c.Collector.IdentityFile = filepath.Join(filepath.Dir(f.c.Collector.CAFile), "active-collector.pem")
	initial, err := nodepki.PublishIdentity(context.Background(), f.c.Collector.CAFile, f.c.Collector.IdentityFile, nodepki.Collector, "collector-a", "", f.collector, now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := f.ca.Issue(nodepki.Collector, "collector-a", nil, now, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.PublishIdentity(context.Background(), f.c.Collector.CAFile, f.c.Collector.IdentityFile, nodepki.Collector, "collector-a", initial.CertificateSHA256, next, now); err != nil {
		t.Fatal(err)
	}
	// Deliberately leave the original pair unusable. Neither the preview nor
	// registry may fall back to it when identity_file is configured.
	os.Remove(f.c.Collector.CertFile)
	os.Remove(f.c.Collector.KeyFile)
	f.c.Collector.CertFile = ""
	f.c.Collector.KeyFile = ""
	f.crl, err = f.ca.Revoke(f.crl, [][]byte{f.collector.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.c.Collector.RevocationFile, f.crl, 0600); err != nil {
		t.Fatal(err)
	}
	material := nodeconfig.Material{Node: "node-a", ServerName: "192.0.2.1", CA: f.node.CA, Certificate: f.node.Certificate, CRL: f.crl, Collectors: []string{"collector-a"}}
	if err := validateProvisioningTrust(f.c, material, now); err != nil {
		t.Fatal("preview used stale pair", err)
	}
	if _, err := CollectorTLS(f.c); err != nil {
		t.Fatal("transport disagrees", err)
	}
	for _, path := range []string{filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"), filepath.Join(f.c.NodePKI.AuthorityDirectory, "crls", "2.pem")} {
		if err := os.WriteFile(path, f.crl, 0600); err != nil {
			t.Fatal(err)
		}
	}
	issuedNode(t, f, "managed-active-collector")
	if err := os.WriteFile(f.c.Collector.IdentityFile, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateProvisioningTrust(f.c, material, now); err == nil {
		t.Fatal("preview ignored broken active identity")
	}
	if _, err := f.s.IssueNodeCertificate(context.Background(), f.c, f.t.vault, "admin", "broken-managed-identity", NodeCertificateInput{Node: "node-a", Expected: 1}); err == nil {
		t.Fatal("issuer ignored broken identity")
	}
}

func TestManagedCollectorPathConfigurationRejectsAmbiguousSources(t *testing.T) {
	base := configurationBootstrapFixture(t)
	for _, path := range []string{"relative.pem", "/var/lib/../identity.pem", "/var/lib/identity\n.pem"} {
		c := base
		c.Collector.IdentityFile = path
		if err := c.Validate(); err == nil {
			t.Fatal("unsafe identity path accepted", path)
		}
	}
	c := base
	c.Collector.IdentityFile = "/var/lib/webscan/identity.pem"
	c.Collector.CertFile = "/other.crt"
	c.Collector.KeyFile = "/other.key"
	if err := c.Validate(); err == nil {
		t.Fatal("ambiguous identity accepted")
	}
	c.Collector.CertFile = ""
	c.Collector.KeyFile = ""
	if err := c.Validate(); err != nil {
		t.Fatal("managed configuration rejected", err)
	}
}

func TestManagedCollectorRestoreInspectionReadsActivePrivateFile(t *testing.T) {
	f := newConfigurationLocalFixture(t)
	f.c.Collector.IdentityFile = filepath.Join(f.f.root, "managed-collector.pem")
	if _, err := nodepki.PublishIdentity(context.Background(), f.c.Collector.CAFile, f.c.Collector.IdentityFile, nodepki.Collector, "collector-local", "", f.collector, f.now); err != nil {
		t.Fatal(err)
	}
	os.Remove(f.c.Collector.CertFile)
	os.Remove(f.c.Collector.KeyFile)
	f.c.Collector.CertFile = ""
	f.c.Collector.KeyFile = ""
	doc := f.document(t)
	before := localTree(t, f.f.root)
	r, err := checkConfigurationLocalMaterial(context.Background(), doc, f.v, f.now)
	if err != nil || localReportCheck(t, r, "collector_tls").Status != "passed" {
		t.Fatal("restore ignored active identity", err)
	}
	after := localTree(t, f.f.root)
	if len(before) != len(after) {
		t.Fatal("inspection wrote files")
	}
	for path, sha := range before {
		if after[path] != sha {
			t.Fatal("inspection modified material")
		}
	}
	if err := os.WriteFile(f.c.Collector.IdentityFile, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err = checkConfigurationLocalMaterial(context.Background(), doc, f.v, f.now)
	if err != nil || r.LocalChecksPassed || localReportCheck(t, r, "collector_tls").Status != "failed" {
		t.Fatal("damaged active file accepted", err)
	}
}
