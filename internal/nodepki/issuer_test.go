package nodepki

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestRegisteredIssuerClearsLeafAndRejectsFailedAcceptance(t *testing.T) {
	root := commandRoot(t)
	dir := filepath.Join(root, "authority")
	if err := Command(context.Background(), Options{Action: "init", Authority: dir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	rejected := errors.New("isolated registry rejection")
	var borrowed []byte
	err := IssueRegistered(context.Background(), dir, Node, "node-a", []string{"agent.test"}, now, time.Hour, func(b Bundle, crl []byte) error {
		borrowed = b.Key
		cert, err := parseCertificate(b.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		trust, err := NewTrust(b.CA, crl, now)
		if err != nil || trust.Verify(cert, Node, "node-a", now) != nil || cert.VerifyHostname("agent.test") != nil {
			t.Fatal("invalid issued identity", err)
		}
		return rejected
	})
	if !errors.Is(err, rejected) || len(borrowed) == 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("failed callback or borrowed key cleanup incorrect")
	}
	called := false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := IssueRegistered(ctx, dir, Node, "node-a", []string{"agent.test"}, now, time.Hour, func(Bundle, []byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("cancelled request signed a leaf")
	}
}

func TestRegistryCRLFloorAllowsExpiredHistoryButRejectsRollback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := NewAuthority(now.Add(-4*time.Hour), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	old, err := ca.Revoke(nil, nil, now.Add(-3*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	current, err := ca.Revoke(old, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCRLAdvance(b.CA, old, current, now); err != nil {
		t.Fatal("expired authentic floor prevented renewal", err)
	}
	if err := ValidateCRLAdvance(b.CA, current, old, now); err == nil {
		t.Fatal("lower CRL accepted")
	}
	leaf, err := ca.Issue(Node, "node-a", []string{"agent.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(leaf.Key)
	revoked, err := ca.Revoke(current, [][]byte{leaf.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCRLAdvance(b.CA, current, revoked, now); err != nil {
		t.Fatal(err)
	}
	// Authentic, higher-numbered but incomplete history must still fail.
	unrevoked, err := ca.Revoke(current, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCRLAdvance(b.CA, revoked, unrevoked, now); err == nil {
		t.Fatal("revocation disappeared at shared floor")
	}
}
