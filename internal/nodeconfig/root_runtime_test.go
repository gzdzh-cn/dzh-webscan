package nodeconfig

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

func TestRootRuntimeAuthenticatesHistoricalPackageWithoutRevivingSeed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-48 * time.Hour)
	old, err := nodepki.NewAuthority(past.Add(-time.Hour), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	next, err := nodepki.NewAuthority(now, 2*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := old.Issue(nodepki.Node, "node-a", []string{"node.test"}, past, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed.Key)
	crl, err := old.Revoke(nil, nil, past, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCRL, _ := next.Revoke(nil, nil, now, time.Hour)
	dual, err := old.AuthorizeRootRotation(next, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	final, err := old.AuthorizeRootRotation(next, dual.Rotation, dual.MembersSHA256, &dual, strings.Repeat("c", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	roots := nodepki.RootSetSnapshot{Format: 1, Dual: dual, Final: &final, OldCRL: crl, NewCRL: newCRL}
	for _, format := range []int{2, 3} {
		m := materialFixture(t)
		m.Format, m.CA, m.CRL, m.Certificate, m.Key = format, seed.CA, crl, seed.Certificate, seed.Key
		if format == 3 {
			m.Certificate, m.Key = nil, nil
		}
		raw, _ := json.Marshal(m)
		if _, err := Decode(raw, now); err == nil {
			t.Fatal("expired installation accepted for fresh provisioning")
		}
		got, err := DecodeManagedRootRuntime(raw, now, roots)
		if err != nil || !bytes.Equal(got.CA, seed.CA) || !bytes.Equal(got.CRL, crl) || !bytes.Equal(got.Key, m.Key) || got.Format != format {
			t.Fatal("valid historical package mutated or rejected", err)
		}
		for _, change := range []func(*nodepki.RootSetSnapshot){
			func(s *nodepki.RootSetSnapshot) { s.Dual.AnchorSignature = nil },
			func(s *nodepki.RootSetSnapshot) { s.Dual.MembersSHA256 = strings.Repeat("d", 64) },
			func(s *nodepki.RootSetSnapshot) { s.NewCRL = crl },
			func(s *nodepki.RootSetSnapshot) { s.OldCRL = newCRL },
		} {
			bad := roots
			change(&bad)
			if _, err := DecodeManagedRootRuntime(raw, now, bad); err == nil {
				t.Fatal("invalid trust history accepted")
			}
		}
		if _, err := DecodeManagedRootRuntime(raw, now.Add(2*time.Hour), roots); err == nil {
			t.Fatal("expired successor CRL admitted runtime")
		}
		if _, err := DecodeManagedRootRuntime(raw, now.Add(-time.Minute), roots); err == nil {
			t.Fatal("future authorization admitted runtime")
		}
	}
}
