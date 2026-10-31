package nodepki

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests exercise live readers and restart behavior, not a completed
// administrative rollover. Privileged test writes model an atomic publisher.
func TestRootRotationLiveIdentityAndRestartRetainImmutableSeed(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	for _, role := range []string{Node, Collector} {
		t.Run(role, func(t *testing.T) {
			names := []string(nil)
			if role == Node {
				names = []string{"node.example.test"}
			}
			oldLeaf, err := old.Issue(role, "identity-a", names, now, 30*24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(oldLeaf.Key)
			newLeaf, err := next.Issue(role, "identity-a", names, now, 31*24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(newLeaf.Key)
			directory := rootRotationState(t, anchor, s.OldCRL, now)
			caFile := filepath.Join(directory, "ca.crt")
			file := filepath.Join(directory, "active.pem")
			record, err := PublishIdentity(context.Background(), caFile, file, role, "identity-a", "", oldLeaf, now)
			if err != nil {
				t.Fatal(err)
			}
			live, err := NewLiveIdentityWithRootState(caFile, file, directory, role, "identity-a", now)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := ReadIdentityWithRootState(caFile, file, directory, role, "identity-a", now); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(s)
			if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, append(append([]byte{}, newLeaf.Certificate...), newLeaf.Key...), 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := live.Certificate(now.Add(time.Second))
			if err != nil || pair.Leaf.CheckSignatureFrom(next.certificate) != nil {
				t.Fatal("live node did not load approved new-root identity", err)
			}
			restart, err := NewLiveIdentityWithRootState(caFile, file, directory, role, "identity-a", now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if got, err := restart.Record(now.Add(time.Second)); err != nil || got.CertificateSHA256 == record.CertificateSHA256 {
				t.Fatal(got, err)
			}
			b, _, err := ReadIdentityWithRootState(caFile, file, directory, role, "identity-a", now.Add(time.Second))
			defer clear(b.Key)
			if err != nil || !bytes.Equal(b.CA, newLeaf.CA) {
				t.Fatal("material must identify its actual approved issuer", err)
			}
			if seed, err := os.ReadFile(caFile); err != nil || !bytes.Equal(seed, anchor) {
				t.Fatal("immutable anchor overwritten", err)
			}
			final, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, &s.Dual, strings.Repeat("d", 64), now.Add(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			finalized := s
			finalized.Final = &final
			finalRaw, _ := json.Marshal(finalized)
			if _, err := PublishRootSet(context.Background(), directory, anchor, finalRaw, now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := live.Certificate(now.Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// A stale active pointer cannot undo the immutable final trust floor.
			if err := os.WriteFile(filepath.Join(directory, "root-rotation", "roots.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := live.Certificate(now.Add(4 * time.Second)); err != nil {
				t.Fatal("authenticated final history was not retained", err)
			}
			accepted, err := ParseRootSetSnapshot(live.rootSet.raw)
			if err != nil || accepted.Final == nil {
				t.Fatal("live root floor reverted", err)
			}
			if err := os.WriteFile(filepath.Join(directory, "root-rotation", "roots.json"), finalRaw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := live.Certificate(now.Add(5 * time.Second)); err != nil {
				t.Fatal("exact accepted state could not recover", err)
			}
			if err := os.WriteFile(file, append(append([]byte{}, oldLeaf.Certificate...), oldLeaf.Key...), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewLiveIdentityWithRootState(caFile, file, directory, role, "identity-a", now.Add(6*time.Second)); err == nil {
				t.Fatal("restart trusted retired root")
			}
		})
	}
}

func TestRootRotationSeedRestartDoesNotResurrectOldIdentity(t *testing.T) {
	old, b, caFile, seed, identityDirectory, now := seededIdentityFixture(t)
	defer clear(b.Key)
	ctx := context.Background()
	if _, err := SeedNodeIdentity(ctx, caFile, seed, identityDirectory, "node-a", now); err != nil {
		t.Fatal(err)
	}
	anchor, err := old.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(anchor.Key)
	next, err := NewAuthority(now, 2*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldCRL, err := old.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCRL, err := next.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := rootRotationState(t, anchor.CA, oldCRL, now)
	dual, err := old.AuthorizeRootRotation(next, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	s := RootSetSnapshot{Format: 1, Dual: dual, OldCRL: oldCRL, NewCRL: newCRL}
	raw, _ := json.Marshal(s)
	if _, err := PublishRootSet(ctx, roots, anchor.CA, raw, now); err != nil {
		t.Fatal(err)
	}
	newLeaf, err := next.Issue(Node, "node-a", []string{"node.test"}, now, 3*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(newLeaf.Key)
	file := filepath.Join(identityDirectory, "active.pem")
	if err := os.WriteFile(file, append(append([]byte{}, newLeaf.Certificate...), newLeaf.Key...), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := SeedNodeIdentityWithRootState(ctx, caFile, seed, identityDirectory, roots, "node-a", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	current, _ := parseCertificate(newLeaf.Certificate)
	if got.CertificateSHA256 != publicSHA(current.Raw) {
		t.Fatal("seed replaced current identity")
	}
	if err := os.Rename(identityDirectory, identityDirectory+"-lost"); err != nil {
		t.Fatal(err)
	}
	if _, err := SeedNodeIdentityWithRootState(ctx, caFile, seed, identityDirectory, roots, "node-a", now.Add(time.Second)); err == nil {
		t.Fatal("root migration silently recreated missing identity from immutable old seed")
	}
}

func TestRootRotationIdentityFailureStillObservesFinalTrustFloor(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	directory := rootRotationState(t, anchor, s.OldCRL, now)
	caFile, file := filepath.Join(directory, "ca.crt"), filepath.Join(directory, "active.pem")
	leaf, err := old.Issue(Node, "node-a", []string{"node.test"}, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(leaf.Key)
	if _, err := PublishIdentity(context.Background(), caFile, file, Node, "node-a", "", leaf, now); err != nil {
		t.Fatal(err)
	}
	live, err := NewLiveIdentityWithRootState(caFile, file, directory, Node, "node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	dual, _ := json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, dual, now); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Certificate(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	final, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, &s.Dual, strings.Repeat("d", 64), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	s.Final = &final
	raw, _ := json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Certificate(now.Add(2 * time.Second)); err == nil {
		t.Fatal("retired-root identity accepted")
	}
	if err := os.WriteFile(filepath.Join(directory, "root-rotation", "roots.json"), dual, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Certificate(now.Add(3 * time.Second)); err == nil {
		t.Fatal("failed leaf reload forgot the observed root retirement")
	}
}
