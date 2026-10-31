package nodepki

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func rootRotationState(t *testing.T, anchor, crl []byte, now time.Time) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "trust")
	if err := initializeTrustState(directory, anchor, crl, now); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestRootRotationPersistentFloorRejectsRollbackAndCorruption(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	directory := rootRotationState(t, anchor, s.OldCRL, now)
	if set, _, err := ReadRootSet(directory, anchor, now); err != nil || set != nil {
		t.Fatal("legacy trust changed before explicit migration", err)
	}
	raw, _ := json.Marshal(s)
	receipt, err := PublishRootSet(context.Background(), directory, anchor, raw, now)
	if err != nil || receipt.Phase != "dual" {
		t.Fatal(receipt, err)
	}
	// A restarted process observes durable dual-root trust.
	if set, r, err := ReadRootSet(directory, anchor, now.Add(time.Second)); err != nil || set == nil || r.SHA256 != receipt.SHA256 {
		t.Fatal(r, err)
	}
	final, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, &s.Dual, strings.Repeat("d", 64), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	s.Final = &final
	finalRaw, _ := json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, finalRaw, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now.Add(2*time.Second)); err == nil {
		t.Fatal("durable root removal was reverted")
	}
	if _, r, err := ReadRootSet(directory, anchor, now.Add(2*time.Second)); err != nil || r.Phase != "new-only" {
		t.Fatal(r, err)
	}
	if _, err := PublishRootSet(context.Background(), directory, anchor, finalRaw, now.Add(20*time.Minute)); err != nil {
		t.Fatal("exact committed response-loss replay required a new authorization", err)
	}
	if err := os.Remove(filepath.Join(directory, "root-rotation", "roots.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadRootSet(directory, anchor, now); err == nil {
		t.Fatal("corrupt initialized migration fell back to old trust")
	}
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now); err == nil {
		t.Fatal("missing accepted state silently reset")
	}
}

func TestRootRotationFirstPublicationPreservesRevocationsAndRejectsStaleApproval(t *testing.T) {
	old, _, anchor, s, now := rootRotationFixture(t)
	b, err := old.Issue(Collector, "collector-a", nil, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	floor, err := old.Revoke(s.OldCRL, [][]byte{b.Certificate}, now.Add(time.Second), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := rootRotationState(t, anchor, floor, now.Add(time.Second))
	raw, _ := json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now.Add(time.Second)); err == nil {
		t.Fatal("first root migration dropped original CRL floor")
	}
	s.OldCRL = floor
	raw, _ = json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now.Add(11*time.Minute)); err == nil {
		t.Fatal("stale first authorization published")
	}
	if _, err := os.Stat(filepath.Join(directory, "root-rotation")); !os.IsNotExist(err) {
		t.Fatal("rejected update initialized state")
	}
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestRootRotationConcurrentPublishKeepsOneCoherentSnapshot(t *testing.T) {
	_, _, anchor, s, now := rootRotationFixture(t)
	directory := rootRotationState(t, anchor, s.OldCRL, now)
	raw, _ := json.Marshal(s)
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := PublishRootSet(context.Background(), directory, anchor, raw, now)
			errors <- err
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	_, receipt, err := ReadRootSet(directory, anchor, now)
	if err != nil || receipt.SHA256 != publicSHA(raw) {
		t.Fatal(receipt, err)
	}
	if _, err := ParseRootSetSnapshot(append([]byte(`{"format":1,`), raw[1:]...)); err == nil {
		t.Fatal("ambiguous duplicate-field snapshot parsed")
	}
}

func TestRootRotationDurableHistorySurvivesStaleActivePointerAndCrash(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	directory := rootRotationState(t, anchor, s.OldCRL, now)
	dual, _ := json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, dual, now); err != nil {
		t.Fatal(err)
	}
	final, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, &s.Dual, strings.Repeat("d", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	s.Final = &final
	finalRaw, _ := json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, finalRaw, now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "root-rotation", "roots.json")
	if err := os.WriteFile(path, dual, 0600); err != nil {
		t.Fatal(err)
	}
	roots, receipt, err := ReadRootSet(directory, anchor, now.Add(time.Second))
	if err != nil || receipt.Phase != "new-only" || len(roots.Pool().Subjects()) != 1 {
		t.Fatal("restart lost final history floor", receipt, err)
	}
	if _, err := PublishRootSet(context.Background(), directory, anchor, dual, now.Add(time.Second)); err == nil {
		t.Fatal("stale pointer authorized root rollback")
	}
	if _, err := PublishRootSet(context.Background(), directory, anchor, finalRaw, now.Add(20*time.Minute)); err != nil {
		t.Fatal("response-loss continuation failed", err)
	}
	// Model a crash after immutable history was fsynced, before pointer replace.
	s.NewCRL, err = next.Revoke(s.NewCRL, nil, now.Add(time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	advanced, _ := json.Marshal(s)
	history := filepath.Join(directory, "root-rotation", "history", publicSHA(advanced)+".json")
	if err := os.WriteFile(history, advanced, 0600); err != nil {
		t.Fatal(err)
	}
	if _, receipt, err := ReadRootSet(directory, anchor, now.Add(time.Hour)); err != nil || receipt.SHA256 != publicSHA(advanced) {
		t.Fatal("durable pending floor not observed", receipt, err)
	}
	if _, err := PublishRootSet(context.Background(), directory, anchor, advanced, now.Add(time.Hour)); err != nil {
		t.Fatal("interrupted publication could not resume", err)
	}
}

func TestRootRotationCannotRewriteRetiredIssuerAuditOrDamagedHistory(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	leaf, err := old.Issue(Node, "node-a", []string{"node.test"}, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(leaf.Key)
	initial := append([]byte(nil), s.OldCRL...)
	s.OldCRL, err = old.Revoke(s.OldCRL, [][]byte{leaf.Certificate}, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := rootRotationState(t, anchor, s.OldCRL, now)
	raw, _ := json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	final, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, &s.Dual, strings.Repeat("d", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	s.Final = &final
	rejected := s
	rejected.OldCRL = initial
	bad, _ := json.Marshal(rejected)
	if _, err := PublishRootSet(context.Background(), directory, anchor, bad, now); err == nil {
		t.Fatal("root retirement erased historical revocation")
	}
	raw, _ = json.Marshal(s)
	if _, err := PublishRootSet(context.Background(), directory, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	history := filepath.Join(directory, "root-rotation", "history", publicSHA(raw)+".json")
	if err := os.WriteFile(history, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadRootSet(directory, anchor, now); err == nil {
		t.Fatal("damaged durable history ignored")
	}
}
