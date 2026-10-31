package nodepki

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRootDeliveryResumesStaleAuthorizationOnlyForExactFreshTarget(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	ctx := context.Background()
	later := now.Add(11 * time.Minute)
	configuration, fingerprint := strings.Repeat("c", 64), strings.Repeat("d", 64)
	raw, _ := json.Marshal(s)
	delivery, err := old.AuthorizeRootDelivery(next, s, Node, "node-a", configuration, fingerprint, later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishRootSet(ctx, rootRotationState(t, anchor, s.OldCRL, now), anchor, raw, later); err == nil {
		t.Fatal("stale bare authorization accepted")
	}
	for _, change := range []func(*RootDelivery){
		func(d *RootDelivery) { d.Task = strings.Repeat("e", 64) },
		func(d *RootDelivery) { d.ID = "node-b" },
		func(d *RootDelivery) { d.Role = Collector },
		func(d *RootDelivery) { d.Configuration = strings.Repeat("e", 64) },
		func(d *RootDelivery) { d.Certificate = strings.Repeat("e", 64) },
		func(d *RootDelivery) { d.Snapshot = strings.Repeat("e", 64) },
		func(d *RootDelivery) { d.ExpiresAt = d.ExpiresAt.Add(time.Minute) },
		func(d *RootDelivery) { d.AnchorSignature = nil },
		func(d *RootDelivery) { d.SuccessorSignature = nil },
	} {
		bad := delivery
		change(&bad)
		if VerifyRootDelivery(anchor, raw, bad, Node, "node-a", configuration, fingerprint, later) == nil {
			t.Fatal("changed delivery binding accepted")
		}
	}
	for _, at := range []time.Time{later.Add(-time.Second), later.Add(10 * time.Minute)} {
		if VerifyRootDelivery(anchor, raw, delivery, Node, "node-a", configuration, fingerprint, at) == nil {
			t.Fatal("future or expired delivery accepted")
		}
	}
	floor := rootRotationState(t, anchor, s.OldCRL, now)
	if _, err := PublishDeliveredRootSet(ctx, floor, anchor, raw, delivery, Node, "node-a", configuration, fingerprint, later); err != nil {
		t.Fatal("fresh explicit delivery did not resume initial distribution", err)
	}
	// Same task, exact signature and target remain replayable only within the
	// token window; refreshing it requires the two isolated issuer keys.
	if _, err := PublishDeliveredRootSet(ctx, floor, anchor, raw, delivery, Node, "node-a", configuration, fingerprint, later); err != nil {
		t.Fatal(err)
	}
	final, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, &s.Dual, strings.Repeat("e", 64), later)
	if err != nil {
		t.Fatal(err)
	}
	s.Final = &final
	finalRaw, _ := json.Marshal(s)
	finalAt := later.Add(11 * time.Minute)
	finalDelivery, err := old.AuthorizeRootDelivery(next, s, Node, "node-a", configuration, fingerprint, finalAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishRootSet(ctx, floor, anchor, finalRaw, finalAt); err == nil {
		t.Fatal("stale finalization applied without fresh administrator delivery")
	}
	if _, err := PublishDeliveredRootSet(ctx, floor, anchor, finalRaw, finalDelivery, Node, "node-a", configuration, fingerprint, finalAt); err != nil {
		t.Fatal("finalization continuation failed", err)
	}
	// Even fresh dual delivery cannot undo a previously persisted final floor.
	s.Final = nil
	downgrade, err := old.AuthorizeRootDelivery(next, s, Node, "node-a", configuration, fingerprint, finalAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishDeliveredRootSet(ctx, floor, anchor, raw, downgrade, Node, "node-a", configuration, fingerprint, finalAt); err == nil {
		t.Fatal("fresh delivery undid finalization")
	}
}
