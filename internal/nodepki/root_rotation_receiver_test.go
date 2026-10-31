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

func TestRootRefreshCannotAuthorizeOrFinalizeRotation(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	directory := rootRotationState(t, anchor, s.OldCRL, now)
	caFile := filepath.Join(directory, "ca.crt")
	receiver, err := NewReceiverTrust(caFile, filepath.Join(directory, "ca.crl"), directory, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := old.Issue(Collector, "collector-a", nil, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	peer, _ := parseCertificate(b.Certificate)
	raw, _ := json.Marshal(s)
	if _, err := receiver.RefreshRoots(context.Background(), peer, raw, now); err == nil {
		t.Fatal("online refresh installed a new root")
	}
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.RefreshRoots(context.Background(), peer, raw, now); err != nil {
		t.Fatal("exact replay after local rollout", err)
	}
	final, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, &s.Dual, strings.Repeat("d", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	s.Final = &final
	finalRaw, _ := json.Marshal(s)
	if _, err := receiver.RefreshRoots(context.Background(), peer, finalRaw, now); err == nil {
		t.Fatal("online refresh retired the old root")
	}
	stored, _ := os.ReadFile(filepath.Join(directory, "root-rotation", "roots.json"))
	if !bytes.Equal(stored, raw) {
		t.Fatal("rejected finalization changed durable trust")
	}
}

func TestRootRefreshRecoversExpiredPolicyWithoutAuthorizingOrdinaryRPC(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	s.OldCRL, _ = old.Revoke(nil, nil, now, time.Hour)
	s.NewCRL, _ = next.Revoke(nil, nil, now, time.Hour)
	directory := rootRotationState(t, anchor, s.OldCRL, now)
	caFile := filepath.Join(directory, "ca.crt")
	raw, _ := json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	expired := now.Add(2 * time.Hour)
	receiver, err := NewReceiverTrust(caFile, filepath.Join(directory, "ca.crl"), directory, expired)
	if err != nil {
		t.Fatal("listener cannot restart with authentic expired policy", err)
	}
	b, err := next.Issue(Collector, "collector-a", nil, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	peer, _ := parseCertificate(b.Certificate)
	if err := receiver.Verify(peer, Collector, "collector-a", expired); err == nil {
		t.Fatal("expired policy authorized an RPC")
	}
	if pool, err := receiver.HandshakeRootPool(expired.Add(2 * time.Second)); err != nil || pool == nil {
		t.Fatal("no restricted update handshake after cache refresh", err)
	}
	s.OldCRL, _ = old.Revoke(s.OldCRL, nil, expired, time.Hour)
	s.NewCRL, _ = next.Revoke(s.NewCRL, nil, expired, time.Hour)
	fresh, _ := json.Marshal(s)
	receipt, err := receiver.RefreshRoots(context.Background(), peer, fresh, expired)
	if err != nil || receipt.SHA256 != publicSHA(fresh) {
		t.Fatal(receipt, err)
	}
	if err := receiver.Verify(peer, Collector, "collector-a", expired.Add(2*time.Second)); err != nil {
		t.Fatal("fresh policy did not resume RPC", err)
	}
	s.NewCRL, _ = next.Revoke(s.NewCRL, [][]byte{b.Certificate}, expired, time.Hour)
	revoked, _ := json.Marshal(s)
	if _, err := receiver.RefreshRoots(context.Background(), peer, revoked, expired); err == nil {
		t.Fatal("caller revoked by proposed snapshot was accepted")
	}
	if _, err := receiver.RefreshRoots(context.Background(), peer, raw, expired); err == nil {
		t.Fatal("expired/lower snapshot accepted")
	}
	if _, err := receiver.Publish(context.Background(), peer, s.OldCRL, expired); err == nil {
		t.Fatal("legacy updater modified root-set trust")
	}
}

func TestReceiverHandshakeRootsEnforceProcessFloorAndDamage(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	directory := rootRotationState(t, anchor, s.OldCRL, now)
	caFile := filepath.Join(directory, "ca.crt")
	receiver, err := NewReceiverTrust(caFile, filepath.Join(directory, "ca.crl"), directory, now)
	if err != nil {
		t.Fatal(err)
	}
	dual, _ := json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, dual, now); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.HandshakeRootPool(now); err != nil {
		t.Fatal(err)
	}
	final, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, &s.Dual, strings.Repeat("d", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	s.Final = &final
	raw, _ := json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.HandshakeRootPool(now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "root-rotation", "roots.json")
	if err := os.WriteFile(path, dual, 0600); err != nil {
		t.Fatal(err)
	}
	if pool, err := receiver.HandshakeRootPool(now); err != nil || len(pool.Subjects()) != 1 {
		t.Fatal("TLS process floor rolled back to dual roots", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.HandshakeRootPool(now); err == nil {
		t.Fatal("damaged trust silently fell back")
	}
}

func TestReceiverLegacyExpiredCRLAllowsOnlyAuthenticatedRefresh(t *testing.T) {
	old, _, anchor, _, now := rootRotationFixture(t)
	seed, err := old.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := rootRotationState(t, anchor, seed, now)
	expired := now.Add(2 * time.Hour)
	receiver, err := NewReceiverTrust(filepath.Join(directory, "ca.crt"), filepath.Join(directory, "ca.crl"), directory, expired)
	if err != nil {
		t.Fatal(err)
	}
	b, err := old.Issue(Collector, "collector-a", nil, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	peer, _ := parseCertificate(b.Certificate)
	if _, err := receiver.HandshakeRootPool(expired.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if receiver.Verify(peer, Collector, "collector-a", expired.Add(2*time.Second)) == nil {
		t.Fatal("expired CRL authorized collection")
	}
	newer, err := old.Revoke(seed, nil, expired, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Publish(context.Background(), peer, newer, expired.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if receiver.Verify(peer, Collector, "collector-a", expired.Add(3*time.Second)) != nil {
		t.Fatal("authenticated refresh failed")
	}
	// The initial root authorization is still not installed by handshake admission.
	if root, _, err := ReadRootSet(directory, anchor, expired); err != nil || root != nil {
		t.Fatal(err)
	}
}
