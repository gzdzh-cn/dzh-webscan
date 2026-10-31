package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

func helperRootFixture(t *testing.T, mode string) (helperNameChangeFixture, *nodepki.Authority, RootRotationInput) {
	t.Helper()
	f := signedHelperNameChange(t, mode, true)
	now := time.Now().UTC().Truncate(time.Second)
	next, err := nodepki.NewAuthority(now, 2*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dual, err := f.ca.AuthorizeRootRotation(next, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := next.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	state := nodepki.RootSetSnapshot{Format: 1, Dual: dual, OldCRL: f.in.CRL, NewCRL: crl}
	raw, _ := json.Marshal(state)
	ca := filepath.Join(f.w.identityData, "pki-identity", "ca.crt")
	b, record, err := nodepki.ReadIdentity(ca, filepath.Join(f.w.identityData, "pki-identity", "active.pem"), nodepki.Node, f.r.Node, now)
	clear(b.Key)
	if err != nil {
		t.Fatal(err)
	}
	return f, next, RootRotationInput{Format: 1, Operation: "trust", Node: f.r.Node, Configuration: f.r.Spec.ConfigSourceSHA256, Expected: record.CertificateSHA256, Snapshot: raw}
}

func TestRootHelperRolloutPreservesInstallationAndLocalQueue(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			f, next, in := helperRootFixture(t, mode)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Second)
			ca, active := filepath.Join(f.w.identityData, "pki-identity", "ca.crt"), filepath.Join(f.w.identityData, "pki-identity", "active.pem")
			before, _ := os.ReadFile(active)
			defer clear(before)
			installation, _ := os.ReadFile(filepath.Join(f.w.root, "active.json"))
			config, _ := os.ReadFile(filepath.Join(f.w.configurationDir(f.r.Spec), "runtime.json"))
			marker := filepath.Join(f.w.identityData, "root-rollout-queue-marker")
			if err := os.WriteFile(marker, []byte("baseline and unconfirmed event unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if out, err := f.w.rootRotation(ctx, in); err != nil || out.Phase != "dual" || out.CertificateSHA256 != in.Expected || out.ResourcesVerified {
					t.Fatal("dual-root publication/replay", err)
				}
			}
			state, _ := nodepki.ParseRootSetSnapshot(in.Snapshot)
			final, err := f.ca.AuthorizeRootRotation(next, state.Dual.Rotation, state.Dual.MembersSHA256, &state.Dual, strings.Repeat("c", 64), now)
			if err != nil {
				t.Fatal(err)
			}
			premature := in
			finalState := state
			finalState.Final = &final
			premature.Snapshot, _ = json.Marshal(finalState)
			if _, err := f.w.rootRotation(ctx, premature); err == nil {
				t.Fatal("old leaf allowed final trust installation")
			}
			in.Operation = "prepare"
			prepared, err := f.w.rootRotation(ctx, in)
			if err != nil {
				t.Fatal("prepare", err)
			}
			retry, err := f.w.rootRotation(ctx, in)
			if err != nil || !bytes.Equal(retry.Request, prepared.Request) {
				t.Fatal("response loss changed node-local CSR", err)
			}
			request, err := nodepki.ParseRootIdentityRequest(prepared.Request)
			if err != nil {
				t.Fatal(err)
			}
			issuer := filepath.Join(testRoot(t), "successor")
			b, _ := next.Export()
			err = nodepki.SeedAuthority(ctx, issuer, b, state.NewCRL, now)
			clear(b.Key)
			if err != nil {
				t.Fatal(err)
			}
			if err := nodepki.SignRootIdentityRegistered(ctx, issuer, f.live.CA, state, request, now, 240*time.Hour, func(b nodepki.Bundle) error { in.Certificate = b.Certificate; return nil }); err != nil {
				t.Fatal(err)
			}
			in.Operation, in.Request = "activate", prepared.Request
			var fingerprint string
			for range 2 {
				out, err := f.w.rootRotation(ctx, in)
				if err != nil || out.CertificateSHA256 == in.Expected || out.ResourcesVerified {
					t.Fatal("activate/replay", err)
				}
				fingerprint = out.CertificateSHA256
			}
			in.Operation, in.Request, in.Certificate, in.Expected = "trust", nil, nil, fingerprint
			in.Snapshot, _ = json.Marshal(finalState)
			for range 2 {
				out, err := f.w.rootRotation(ctx, in)
				if err != nil || out.Phase != "new-only" || out.CertificateSHA256 != fingerprint {
					t.Fatal("final publication/replay", err)
				}
			}
			current, _, err := nodepki.ReadIdentityWithRootState(ca, active, filepath.Join(f.w.identityData, "pki-trust"), nodepki.Node, f.r.Node, now)
			defer clear(current.Key)
			if err != nil || bytes.Contains(before, current.Key) || !bytes.Equal(current.CA, state.Dual.NewCA) {
				t.Fatal("invalid successor identity", err)
			}
			if err := f.w.verifyConfiguration(ctx, f.r); err != nil {
				t.Fatal("root rollover stranded immutable configuration", err)
			}
			restarted := &LocalRuntime{root: f.w.root, identityData: f.w.identityData, probe: f.w.probe, rulesProbe: f.w.rulesProbe}
			if err := restarted.verifyConfiguration(ctx, f.r); err != nil {
				t.Fatal("restart lost root-aware configuration", err)
			}
			for path, expected := range map[string][]byte{filepath.Join(f.w.root, "active.json"): installation, filepath.Join(f.w.configurationDir(f.r.Spec), "runtime.json"): config, marker: []byte("baseline and unconfirmed event unchanged"), active + ".history/" + request.CertificateSHA256 + ".pem": before} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, expected) {
					t.Fatal("rollover changed installation/history/queue", err)
				}
			}
			public, _ := json.Marshal([]RootRotationOutput{prepared, retry})
			if bytes.Contains(public, []byte("PRIVATE KEY")) || bytes.Contains(public, current.Key) {
				t.Fatal("private key in helper response")
			}
		})
	}
}

func TestRootHelperRejectsChangedTargetBeforeTrustPublication(t *testing.T) {
	for _, scenario := range []string{"node", "configuration", "fingerprint", "snapshot", "duplicate", "unknown", "extra-input", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			f, _, in := helperRootFixture(t, "native")
			switch scenario {
			case "node":
				in.Node = "other-node"
			case "configuration":
				in.Configuration = strings.Repeat("e", 64)
			case "fingerprint":
				in.Expected = strings.Repeat("e", 64)
			case "snapshot":
				state, _ := nodepki.ParseRootSetSnapshot(in.Snapshot)
				state.Dual.MembersSHA256 = strings.Repeat("e", 64)
				in.Snapshot, _ = json.Marshal(state)
			}
			raw, _ := json.Marshal(in)
			switch scenario {
			case "duplicate":
				raw = append(raw[:len(raw)-1], []byte(`,"format":1}`)...)
			case "unknown":
				raw = append(raw[:len(raw)-1], []byte(`,"command":"true"}`)...)
			case "extra-input":
				raw = append(raw, []byte(` {}`)...)
			case "oversized":
				raw = bytes.Repeat([]byte{'x'}, MaxRootRotationBytes+1)
			}
			decoded, _, err := decodeRootRotation(bytes.NewReader(raw))
			if err == nil {
				_, err = f.w.rootRotation(context.Background(), decoded)
			}
			if err == nil {
				t.Fatal("unbound root operation accepted")
			}
			if _, err := os.Lstat(filepath.Join(f.w.identityData, "pki-trust", "root-rotation")); !os.IsNotExist(err) {
				t.Fatal("invalid operation published root state")
			}
		})
	}
}

func TestRootHelperExactIssuedReceiptResumesAfterParentExpiry(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			f, next, in := helperRootFixture(t, mode)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Second)
			leaf := recoveryTestCertificate(t, f.live.Certificate)
			short, err := f.ca.Issue(nodepki.Node, in.Node, leaf.DNSNames, now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(short.Key)
			active := filepath.Join(f.w.identityData, "pki-identity", "active.pem")
			// Only fixture setup replaces the initial long-lived leaf with a
			// shorter one. Ordinary publication correctly forbids shortening it.
			if err := os.WriteFile(active, append(append([]byte{}, short.Certificate...), short.Key...), 0600); err != nil {
				t.Fatal(err)
			}
			in.Expected = sha(recoveryTestCertificate(t, short.Certificate).Raw)
			state, err := nodepki.ParseRootSetSnapshot(in.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			// Keep CRLs valid independently of the deliberately short leaf.
			state.OldCRL, err = f.ca.Revoke(state.OldCRL, nil, now, 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			in.Snapshot, _ = json.Marshal(state)
			run := func(input RootRotationInput, at time.Time) (RootRotationOutput, error) {
				return f.w.rootRotationAt(ctx, input, newInstallationHost(f.w.root), nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}, at)
			}
			if _, err := run(in, now); err != nil {
				t.Fatal(err)
			}
			in.Operation = "prepare"
			prepared, err := run(in, now)
			if err != nil {
				t.Fatal(err)
			}
			request, err := nodepki.ParseRootIdentityRequest(prepared.Request)
			if err != nil {
				t.Fatal(err)
			}
			authority := filepath.Join(testRoot(t), "successor")
			bundle, _ := next.Export()
			err = nodepki.SeedAuthority(ctx, authority, bundle, state.NewCRL, now)
			clear(bundle.Key)
			if err != nil {
				t.Fatal(err)
			}
			if err := nodepki.SignRootIdentityRegistered(ctx, authority, f.live.CA, state, request, now, 2*time.Hour, func(b nodepki.Bundle) error { in.Certificate = b.Certificate; return nil }); err != nil {
				t.Fatal(err)
			}
			later := now.Add(61 * time.Minute)
			in.Operation, in.Request = "trust", prepared.Request
			// A resumed host task must freshly authorize delivery of its exact
			// immutable snapshot; the original ten-minute delivery is stale.
			delivery, err := f.ca.AuthorizeRootDelivery(next, state, nodepki.Node, in.Node, in.Configuration, in.Expected, later)
			if err != nil {
				t.Fatal(err)
			}
			in.Delivery = &delivery
			withoutReceipt := in
			withoutReceipt.Request, withoutReceipt.Certificate = nil, nil
			if _, err := run(withoutReceipt, later); err == nil {
				t.Fatal("expired parent accepted without exact successor receipt")
			}
			if _, err := run(in, later); err != nil {
				t.Fatal("issued receipt could not restore dual trust", err)
			}
			in.Operation = "activate"
			for range 2 {
				if out, err := run(in, later); err != nil || out.CertificateSHA256 == in.Expected {
					t.Fatal("issued activation/replay after expiry failed", err)
				}
			}
		})
	}
}
