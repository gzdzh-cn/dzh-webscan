package nodepki

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootIdentityLocalKeyRolloutAndResponseLoss(t *testing.T) {
	for _, role := range []string{Node, Collector} {
		t.Run(role, func(t *testing.T) {
			old, next, anchor, snapshot, now := rootRotationFixture(t)
			ctx := context.Background()
			floor := rootRotationState(t, anchor, snapshot.OldCRL, now)
			identity := privateTestDir(t)
			ca, active := filepath.Join(identity, "ca.crt"), filepath.Join(identity, "active.pem")
			if err := os.WriteFile(ca, anchor, 0600); err != nil {
				t.Fatal(err)
			}
			names := []string(nil)
			if role == Node {
				names = []string{"node.example.test", "127.0.0.1"}
			}
			before, err := old.Issue(role, "identity-a", names, now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before.Key)
			record, err := PublishIdentity(ctx, ca, active, role, "identity-a", "", before, now)
			if err != nil {
				t.Fatal(err)
			}
			authorization := RootAuthorizationSHA256(snapshot.Dual)
			if _, err := PrepareRootIdentity(ctx, ca, active, floor, role, "identity-a", authorization, record.CertificateSHA256, now); err == nil {
				t.Fatal("prepared rollover before local dual trust")
			}
			raw, _ := json.Marshal(snapshot)
			if _, err := PublishRootSet(ctx, floor, anchor, raw, now); err != nil {
				t.Fatal(err)
			}
			request, err := PrepareRootIdentity(ctx, ca, active, floor, role, "identity-a", authorization, record.CertificateSHA256, now)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := PrepareRootIdentity(ctx, ca, active, floor, role, "identity-a", authorization, record.CertificateSHA256, now)
			if err != nil || retry.SHA256() != request.SHA256() {
				t.Fatal("response loss regenerated pending key", err)
			}
			public, _ := json.Marshal(request)
			if bytes.Contains(public, []byte("PRIVATE KEY")) {
				t.Fatal("private key leaked into request")
			}
			for _, invalid := range [][]byte{append([]byte{' '}, public...), append(append([]byte{}, public[:len(public)-1]...), []byte(`,"format":1}`)...), bytes.Repeat([]byte{' '}, MaxRenewalBytes+1)} {
				if _, err := ParseRootIdentityRequest(invalid); err == nil {
					t.Fatal("noncanonical public request accepted")
				}
			}
			issuer := filepath.Join(privateTestDir(t), "authority")
			bundle, err := next.Export()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(bundle.Key)
			if err := SeedAuthority(ctx, issuer, bundle, snapshot.NewCRL, now); err != nil {
				t.Fatal(err)
			}
			changed := request
			changed.ID = "identity-b"
			if err := SignRootIdentityRegistered(ctx, issuer, anchor, snapshot, changed, now, 2*time.Hour, func(Bundle) error { return nil }); err == nil {
				t.Fatal("proof did not bind identity")
			}
			changed = request
			changed.Authorization = strings.Repeat("f", 64)
			if err := SignRootIdentityRegistered(ctx, issuer, anchor, snapshot, changed, now, 2*time.Hour, func(Bundle) error { return nil }); err == nil {
				t.Fatal("request from another rotation accepted")
			}
			commitFailure := errors.New("isolated receipt commit failure")
			if err := SignRootIdentityRegistered(ctx, issuer, anchor, snapshot, request, now, 2*time.Hour, func(Bundle) error { return commitFailure }); !errors.Is(err, commitFailure) {
				t.Fatal("issuance receipt failure swallowed", err)
			}
			var certificate []byte
			if err := SignRootIdentityRegistered(ctx, issuer, anchor, snapshot, request, now, 2*time.Hour, func(b Bundle) error {
				if len(b.Key) != 0 || !bytes.Equal(b.CA, snapshot.Dual.NewCA) {
					t.Fatal("signer returned private key or wrong issuer")
				}
				certificate = append([]byte{}, b.Certificate...)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// The exact signed receipt may arrive after the original one-hour
			// identity expired. No new issuance may use that expired proof.
			now = now.Add(61 * time.Minute)
			if _, _, err := ReadIdentityWithRootState(ca, active, floor, role, "identity-a", now); err == nil {
				t.Fatal("expired parent became a live identity")
			}
			inspected, parent, err := ReadRootActivationIdentity(ca, active, floor, role, "identity-a", snapshot, request, certificate, now)
			clear(inspected.Key)
			if err != nil || parent.CertificateSHA256 != record.CertificateSHA256 {
				t.Fatal("exact issued receipt could not inspect expired activation parent", err)
			}
			if _, _, err := ReadRootActivationIdentity(ca, active, floor, role, "identity-a", snapshot, request, before.Certificate, now); err == nil {
				t.Fatal("unissued receipt inspected expired identity")
			}
			if ValidateRootIdentityRequest(anchor, snapshot, request, now) == nil {
				t.Fatal("expired proof admitted as a new request")
			}
			called := false
			if err := SignRootIdentityRegistered(ctx, issuer, anchor, snapshot, request, now, 2*time.Hour, func(Bundle) error { called = true; return nil }); err == nil || called {
				t.Fatal("expired predecessor authorized a new issuance")
			}
			if _, err := ActivateRootIdentity(ctx, ca, active, floor, role, "identity-a", authorization, record.CertificateSHA256, strings.Repeat("e", 64), certificate, now); err == nil {
				t.Fatal("wrong issuance binding activated")
			}
			if _, err := ActivateRootIdentity(ctx, ca, active, floor, role, "identity-a", authorization, record.CertificateSHA256, request.SHA256(), before.Certificate, now); err == nil {
				t.Fatal("old issuer activated as successor")
			}
			activated, err := ActivateRootIdentity(ctx, ca, active, floor, role, "identity-a", authorization, record.CertificateSHA256, request.SHA256(), certificate, now)
			if err != nil || !activated.Changed || activated.CertificateSHA256 == record.CertificateSHA256 {
				t.Fatal("authorized rollover did not activate", err)
			}
			lost, err := ActivateRootIdentity(ctx, ca, active, floor, role, "identity-a", authorization, record.CertificateSHA256, request.SHA256(), certificate, now)
			if err != nil || lost.Changed || lost.CertificateSHA256 != activated.CertificateSHA256 {
				t.Fatal("activation response loss not replayable", err)
			}
			material, _, err := ReadIdentityWithRootState(ca, active, floor, role, "identity-a", now)
			defer clear(material.Key)
			if err != nil || bytes.Equal(material.Key, before.Key) || !bytes.Equal(material.CA, snapshot.Dual.NewCA) {
				t.Fatal("successor identity invalid or key not replaced", err)
			}
			history, err := os.ReadFile(active + ".history/" + record.CertificateSHA256 + ".pem")
			defer clear(history)
			if err != nil || !bytes.Equal(history, append(append([]byte{}, before.Certificate...), before.Key...)) {
				t.Fatal("original private recovery history missing", err)
			}
			final, err := old.AuthorizeRootRotation(next, snapshot.Dual.Rotation, snapshot.Dual.MembersSHA256, &snapshot.Dual, strings.Repeat("d", 64), now)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.Final = &final
			raw, _ = json.Marshal(snapshot)
			if _, err := PublishRootSet(ctx, floor, anchor, raw, now); err != nil {
				t.Fatal(err)
			}
			lost, err = ActivateRootIdentity(ctx, ca, active, floor, role, "identity-a", authorization, record.CertificateSHA256, request.SHA256(), certificate, now)
			if err != nil || lost.Changed || lost.CertificateSHA256 != activated.CertificateSHA256 {
				t.Fatal("finalization broke precise response-loss replay", err)
			}
			if err := SignRootIdentityRegistered(ctx, issuer, anchor, snapshot, request, now, 2*time.Hour, func(Bundle) error { return nil }); err == nil {
				t.Fatal("new root identity issuance after finalization")
			}
			if _, err := NewLiveIdentityWithRootState(ca, active, floor, role, "identity-a", now); err != nil {
				t.Fatal("rolled identity failed after restart", err)
			}
		})
	}
}

func TestRootIdentityRejectsRevokedParentBeforePreparingKey(t *testing.T) {
	old, _, anchor, snapshot, now := rootRotationFixture(t)
	floor := rootRotationState(t, anchor, snapshot.OldCRL, now)
	directory := privateTestDir(t)
	ca, file := filepath.Join(directory, "ca.crt"), filepath.Join(directory, "active.pem")
	if err := os.WriteFile(ca, anchor, 0600); err != nil {
		t.Fatal(err)
	}
	leaf, err := old.Issue(Node, "node-a", []string{"node.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(leaf.Key)
	record, err := PublishIdentity(context.Background(), ca, file, Node, "node-a", "", leaf, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.OldCRL, err = old.Revoke(snapshot.OldCRL, [][]byte{leaf.Certificate}, now.Add(time.Second), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snapshot)
	if _, err := PublishRootSet(context.Background(), floor, anchor, raw, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareRootIdentity(context.Background(), ca, file, floor, Node, "node-a", RootAuthorizationSHA256(snapshot.Dual), record.CertificateSHA256, now.Add(time.Second)); err == nil {
		t.Fatal("revoked parent prepared successor key")
	}
	if _, err := os.Stat(filepath.Join(directory, "root-identities")); !os.IsNotExist(err) {
		t.Fatal("rejected parent still created pending key", err)
	}
}

func TestRootIdentityActivationRechecksRevocationAfterIssuance(t *testing.T) {
	old, next, anchor, snapshot, now := rootRotationFixture(t)
	ctx := context.Background()
	floor := rootRotationState(t, anchor, snapshot.OldCRL, now)
	directory := privateTestDir(t)
	ca, active := filepath.Join(directory, "ca.crt"), filepath.Join(directory, "active.pem")
	if err := os.WriteFile(ca, anchor, 0600); err != nil {
		t.Fatal(err)
	}
	leaf, err := old.Issue(Node, "node-a", []string{"node.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(leaf.Key)
	initial, err := PublishIdentity(ctx, ca, active, Node, "node-a", "", leaf, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snapshot)
	if _, err := PublishRootSet(ctx, floor, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	authorization := RootAuthorizationSHA256(snapshot.Dual)
	request, err := PrepareRootIdentity(ctx, ca, active, floor, Node, "node-a", authorization, initial.CertificateSHA256, now)
	if err != nil {
		t.Fatal(err)
	}
	successor := filepath.Join(privateTestDir(t), "authority")
	b, err := next.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	if err := SeedAuthority(ctx, successor, b, snapshot.NewCRL, now); err != nil {
		t.Fatal(err)
	}
	var certificate []byte
	if err := SignRootIdentityRegistered(ctx, successor, anchor, snapshot, request, now, 2*time.Hour, func(b Bundle) error { certificate = append([]byte{}, b.Certificate...); return nil }); err != nil {
		t.Fatal(err)
	}
	snapshot.OldCRL, err = old.Revoke(snapshot.OldCRL, [][]byte{leaf.Certificate}, now.Add(time.Second), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(snapshot)
	if _, err := PublishRootSet(ctx, floor, anchor, raw, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateRootIdentity(ctx, ca, active, floor, Node, "node-a", authorization, initial.CertificateSHA256, request.SHA256(), certificate, now.Add(time.Second)); err == nil {
		t.Fatal("revoked predecessor activated a pre-issued successor")
	}
	retained, err := os.ReadFile(active)
	defer clear(retained)
	if err != nil || !bytes.Equal(retained, append(append([]byte{}, leaf.Certificate...), leaf.Key...)) {
		t.Fatal("revocation failure changed active identity", err)
	}
}
