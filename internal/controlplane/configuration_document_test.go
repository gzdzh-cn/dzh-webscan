package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
	"webscan/internal/common"
)

func configurationDocumentFixture(t *testing.T, nodes ...Node) configurationDocument {
	t.Helper()
	c := configurationBootstrapFixture(t)
	d, err := newConfigurationDocument(c, []byte(`{"retention":{"sqlite_events_days":60},"email":{"enabled":false,"password":"private-mail-value","recipients":["private@example.test"]},"feishu":{"enabled":false,"webhook_url":"https://open.feishu.cn/open-apis/bot/v2/hook/private-hook"},"future_private":{"opaque":"private-future-value"}}`), 7, nodes, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func configurationBootstrapFixture(t *testing.T) Config {
	t.Helper()
	c, err := LoadConfig(filepath.Join("..", "..", "webscan-v3.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfigurationDocumentPrivacyRoundtripAndIndependentIdentity(t *testing.T) {
	a, b := nodeFixture("node-b"), nodeFixture("node-a")
	a.Config = []byte(`{"metrics_source_ip":"192.0.2.8","private":{"ssh_password":"private-node-value"},"monitor":{"roots":["/srv/www"]}}`)
	b.Config = append([]byte{}, a.Config...)
	doc := configurationDocumentFixture(t, a, b)
	if len(doc.Profiles) != 1 || doc.Nodes[a.ID].Profile != "p1" || doc.Nodes[b.ID].Profile != "p1" {
		t.Fatal("shared settings not deduplicated")
	}
	full, err := marshalConfigurationDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseConfigurationDocument(full)
	if err != nil || !bytes.Contains(full, []byte("private-node-value")) {
		t.Fatal("private snapshot lost data", err)
	}
	fullAgain, err := marshalConfigurationDocument(parsed)
	if err != nil || !bytes.Equal(full, fullAgain) {
		t.Fatal("roundtrip changed document", err)
	}
	if _, err = json.Marshal(doc); err == nil {
		t.Fatal("private document serialized as API JSON")
	}
	if got := fmt.Sprintf("%v %#v", doc, doc); strings.Contains(got, "private-") {
		t.Fatal("diagnostic leak")
	}
	public, err := doc.redacted()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := marshalConfigurationDocument(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-mail-value", "private@example.test", "private-hook", "private-future-value", "private-node-value", "192.0.2.8", "192.0.2.1:19100", "monitor.example.test", "/etc/webscan-v3/postgres.dsn"} {
		if bytes.Contains(plain, []byte(secret)) {
			t.Fatalf("public backup leaked %q", secret)
		}
	}
	if len(public.Profiles) != 1 || !containsConfigurationPath(public.Profiles["p1"].Omitted, "/private") || !containsConfigurationPath(public.Omitted, "/settings/future_private") {
		t.Fatal("omissions not explicit")
	}
	// Public edits cannot mutate the private snapshot, including array values.
	common.M(public.Profiles["p1"].Config["monitor"])["roots"].([]any)[0] = "/other"
	if common.M(doc.Profiles["p1"].Config["monitor"])["roots"].([]any)[0] != "/srv/www" {
		t.Fatal("projection retained mutable aliases")
	}
	if _, err = parseConfigurationDocument(plain); err != nil {
		t.Fatal("redacted import rejected", err)
	}
}

func TestConfigurationDocumentResolvesByNodeIDWithoutBorrowingCredentials(t *testing.T) {
	a, b, added := nodeFixture("node-a"), nodeFixture("node-b"), nodeFixture("node-new")
	a.Config = []byte(`{"metrics_source_ip":"192.0.2.7","private":{"token":"token-a"}}`)
	b.Config = []byte(`{"metrics_source_ip":"192.0.2.8","private":{"token":"token-b"}}`)
	source := configurationDocumentFixture(t, a, b, added)
	public, err := source.redacted()
	if err != nil {
		t.Fatal(err)
	}
	// Both profiles have the same public projection and omission paths.
	if public.Nodes[a.ID].Profile != public.Nodes[b.ID].Profile {
		t.Fatal("redacted rules should share a profile")
	}
	a.Endpoint, b.Endpoint = "192.0.2.17:19100", "192.0.2.18:19100"
	current := configurationDocumentFixture(t, b, a)
	resolved, missing, err := resolveConfigurationOmissions(public, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 3 || missing[0] != "/nodes/node-new/name" || missing[1] != "/nodes/node-new/endpoint" || missing[2] != "/nodes/node-new/server_name" {
		t.Fatal("new node must remain incomplete", missing)
	}
	if resolved.Nodes[a.ID].Endpoint != a.Endpoint || resolved.Nodes[b.ID].Endpoint != b.Endpoint {
		t.Fatal("identity matched by order")
	}
	for _, id := range []string{a.ID, b.ID} {
		p := resolved.Profiles[resolved.Nodes[id].Profile]
		want := "token-a"
		if id == b.ID {
			want = "token-b"
		}
		if common.M(p.Config["private"])["token"] != want {
			t.Fatal("cross-node credential substitution", id)
		}
	}
	if public.Nodes[a.ID].Endpoint != "" || len(public.Omitted) == 0 || common.M(current.Settings["email"])["password"] != "private-mail-value" {
		t.Fatal("input mutated")
	}
}

func TestConfigurationDocumentRejectsAmbiguousInputAndSanitizesErrors(t *testing.T) {
	doc := configurationDocumentFixture(t, nodeFixture("node-a"))
	raw, err := marshalConfigurationDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"duplicate-top":     append([]byte("format_version: 3\n"), raw...),
		"unknown-top":       append(append([]byte{}, raw...), []byte("extra: private-input-value\n")...),
		"multi-document":    append(append([]byte{}, raw...), []byte("---\nprivate-input-value\n")...),
		"alias":             bytes.Replace(raw, []byte("settings_version: 7"), []byte("settings_version: &secret 7\nextra: *secret"), 1),
		"duplicate-nested":  bytes.Replace(raw, []byte("sqlite_events_days: 60"), []byte("sqlite_events_days: 60\n        sqlite_events_days: 10"), 1),
		"version":           bytes.Replace(raw, []byte("format_version: 3"), []byte("format_version: 2"), 1),
		"mask":              bytes.Replace(raw, []byte("private-mail-value"), []byte("<redacted>"), 1),
		"invalid-node-port": bytes.Replace(raw, []byte("192.0.2.1:19100"), []byte("192.0.2.1:99999"), 1),
		"invalid-retention": bytes.Replace(raw, []byte("sqlite_events_days: 60"), []byte("sqlite_events_days: false"), 1),
		"invalid-kind":      bytes.Replace(raw, []byte("kind: webscan-configuration"), []byte("kind: private-input-value"), 1),
		"bad-utf8":          {0xff},
		"empty":             {},
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, e := parseConfigurationDocument(in); e != errConfigurationDocument {
				t.Fatal("ambiguous/private parser error", e)
			}
		})
	}
	for name, change := range map[string]func(*configurationDocument){
		"dangling-profile": func(d *configurationDocument) { n := d.Nodes["node-a"]; n.Profile = "missing"; d.Nodes["node-a"] = n },
		"unused-profile": func(d *configurationDocument) {
			d.Profiles["unused"] = configurationDocumentRules{Config: common.Map{}, Omitted: []string{}}
		},
		"overwrite-omission": func(d *configurationDocument) { d.Omitted = []string{"/settings/email/password"} },
		"duplicate-omission": func(d *configurationDocument) { d.Omitted = []string{"/settings/missing", "/settings/missing"} },
		"list-omission":      func(d *configurationDocument) { d.Omitted = []string{"/settings/email/recipients/0"} },
		"invalid-escape":     func(d *configurationDocument) { d.Omitted = []string{"/settings/missing~2"} },
		"wrong-bootstrap": func(d *configurationDocument) {
			d.Bootstrap["extra"] = "private-input-value"
			d.Omitted = []string{"/settings/missing"}
		},
		"unsafe-profile": func(d *configurationDocument) {
			p := d.Profiles["p1"]
			p.Config["resources"] = common.Map{"agent_memory_mib": float64(1)}
			d.Profiles["p1"] = p
		},
	} {
		t.Run(name, func(t *testing.T) {
			d, e := parseConfigurationDocument(raw)
			if e != nil {
				t.Fatal(e)
			}
			change(&d)
			bad, _ := yaml.Marshal(d)
			if _, e = parseConfigurationDocument(bad); e != errConfigurationDocument {
				t.Fatal("invalid document accepted", e)
			}
		})
	}
	var object configurationValues
	if decodeConfigurationObject([]byte(`{"private":{"token":"one","token":"two"}}`), &object) == nil {
		t.Fatal("JSON duplicate collapsed before validation")
	}
	for _, yamlText := range []string{"value: !private secret", "value: !private {a: b}", "value: &v {a: b}\nother: *v", "value: {<<: {a: b}}", "value: !!binary c2VjcmV0", "value: " + strings.Repeat("[", 22) + "1" + strings.Repeat("]", 22)} {
		var tree yaml.Node
		if yaml.Unmarshal([]byte(yamlText), &tree) == nil && safeConfigurationYAML(&tree, 0) {
			t.Fatal("unsafe YAML accepted")
		}
	}
}

func TestConfigurationDocumentPreservesUnknownNumbersWithoutFloatRounding(t *testing.T) {
	n := nodeFixture("number-node")
	n.Config = []byte(`{"private":{"integer":18446744073709551615,"large_decimal":12345678901234567890.123456789,"exponent":1e999}}`)
	doc := configurationDocumentFixture(t, n)
	raw, err := marshalConfigurationDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseConfigurationDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	config := parsed.Profiles[parsed.Nodes[n.ID].Profile].Config
	for key, want := range map[string]string{"integer": "18446744073709551615", "large_decimal": "12345678901234567890.123456789", "exponent": "1e999"} {
		if got, ok := common.M(config["private"])[key].(json.Number); !ok || got.String() != want {
			t.Fatalf("numeric text changed: %s", key)
		}
	}
	again, err := marshalConfigurationDocument(parsed)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("numeric roundtrip changed", err)
	}
}

func TestConfigurationDocumentLargeMapStrictFieldsAndDuplicates(t *testing.T) {
	doc := configurationDocumentFixture(t, nodeFixture("node-a"))
	raw, err := marshalConfigurationDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"nodes", "profiles"} {
		for _, kind := range []string{"unknown-field", "duplicate-field", "duplicate-entry", "scalar-entry", "non-string-key"} {
			t.Run(section+"/"+kind, func(t *testing.T) {
				var tree yaml.Node
				if yaml.Unmarshal(raw, &tree) != nil {
					t.Fatal("invalid fixture")
				}
				var entries *yaml.Node
				root := tree.Content[0]
				for i := 0; i < len(root.Content); i += 2 {
					if root.Content[i].Value == section {
						entries = root.Content[i+1]
					}
				}
				if entries == nil || len(entries.Content) != 2 {
					t.Fatal("missing map fixture")
				}
				entry := entries.Content[1]
				switch kind {
				case "unknown-field":
					entry.Content = append(entry.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "private-unknown"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "private-value"})
				case "duplicate-field":
					entry.Content = append(entry.Content, entry.Content[0], entry.Content[1])
				case "duplicate-entry":
					entries.Content = append(entries.Content, entries.Content[0], entries.Content[1])
				case "scalar-entry":
					entries.Content[1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "private-value"}
				case "non-string-key":
					entries.Content[0] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "42"}
				}
				bad, err := yaml.Marshal(&tree)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := parseConfigurationDocument(bad); err != errConfigurationDocument {
					t.Fatal("invalid map accepted or private error exposed", err)
				}
			})
		}
	}
}

func TestConfigurationDocumentAgeIntegrityAndPasswordLimits(t *testing.T) {
	doc := configurationDocumentFixture(t, nodeFixture("node-a"))
	password := "isolated-test-password-2026"
	for _, pair := range [][2]string{{"short", "short"}, {password, password + "!"}, {strings.Repeat("x", 1025), strings.Repeat("x", 1025)}} {
		if _, err := encryptConfigurationDocument(doc, pair[0], pair[1]); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
	cipher, err := encryptConfigurationDocument(doc, password, password)
	if err != nil || !bytes.HasPrefix(cipher, []byte("age-encryption.org/v1\n")) || bytes.Contains(cipher, []byte("private-mail-value")) {
		t.Fatal("standard age encryption failed", err)
	}
	decoded, err := decryptConfigurationDocument(cipher, password)
	if err != nil || common.M(decoded.Settings["email"])["password"] != "private-mail-value" {
		t.Fatal("encrypted roundtrip lost credentials", err)
	}
	if _, err = decryptConfigurationDocument(cipher, "wrong-password-2026"); err != errConfigurationPassword {
		t.Fatal("wrong password diagnostic", err)
	}
	corrupt := append([]byte{}, cipher...)
	corrupt[len(corrupt)-1] ^= 1
	for _, invalid := range [][]byte{corrupt, cipher[:len(cipher)-1], []byte("invalid private contents"), make([]byte, configurationEncryptedLimit+1)} {
		if _, err = decryptConfigurationDocument(invalid, password); err != errConfigurationPassword {
			t.Fatal("corrupt/oversized file accepted", err)
		}
	}
	// A malicious recipient can request excessive scrypt work; reject the
	// header before allocating its requested memory or reading the payload.
	var expensive bytes.Buffer
	recipient, _ := age.NewScryptRecipient(password)
	recipient.SetWorkFactor(1)
	w, err := age.Encrypt(&expensive, recipient)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("private"))
	w.Close()
	lines := bytes.Split(expensive.Bytes(), []byte("\n"))
	fields := bytes.Fields(lines[1])
	fields[len(fields)-1] = []byte("30")
	lines[1] = bytes.Join(fields, []byte(" "))
	if _, err = decryptConfigurationDocument(bytes.Join(lines, []byte("\n")), password); err != errConfigurationPassword {
		t.Fatal("excessive work factor accepted", err)
	}
}

func TestConfigurationDocumentTwentyThousandNodeBounds(t *testing.T) {
	if testing.Short() {
		t.Skip("20,000-node codec scale check")
	}
	nodes := make([]Node, configurationNodeLimit)
	shared := []byte(`{"monitor":{"roots":["/srv/www"]},"private":{"token":"shared-private-value"}}`)
	for i := range nodes {
		nodes[i] = nodeFixture(fmt.Sprintf("node-%05d", i))
		nodes[i].Config = shared
	}
	started := time.Now()
	doc := configurationDocumentFixture(t, nodes...)
	if len(doc.Nodes) != configurationNodeLimit || len(doc.Profiles) != 1 {
		t.Fatal("scale snapshot truncated or duplicated")
	}
	raw, err := marshalConfigurationDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 2<<20 {
		t.Fatal("scale fixture no longer exercises former limit")
	}
	parsed, err := parseConfigurationDocument(raw)
	if err != nil || len(parsed.Nodes) != configurationNodeLimit {
		t.Fatal("scale roundtrip truncated", err)
	}
	redacted, err := doc.redacted()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := marshalConfigurationDocument(redacted)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte("shared-private-value")) || len(redacted.Profiles) != 1 {
		t.Fatal("scale privacy/deduplication failed")
	}
	t.Logf("20,000 nodes: private YAML %d bytes; redacted YAML %d bytes; elapsed %s (codec check, not collection/capacity acceptance)", len(raw), len(plain), time.Since(started))
	tooMany := append(nodes, nodeFixture("node-over-limit"))
	if _, err = newConfigurationDocument(configurationBootstrapFixture(t), []byte(`{}`), 1, tooMany, time.Now()); err != errConfigurationDocument {
		t.Fatal("node limit accepted", err)
	}
	if _, err = parseConfigurationDocument(make([]byte, configurationDocumentLimit+1)); err != errConfigurationDocument {
		t.Fatal("document bound accepted", err)
	}
}

func TestConfigurationDocumentCaptureIsReadOnlyAndExcludesIndependentStores(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("backup-node")
	n.Config = []byte(`{"private":{"opaque_reference":"retained-reference"}}`)
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE v3_settings SET version=9,payload='{"retention":{"sqlite_events_days":120},"email":{"enabled":false,"password":"capture-private-value"}}'`); err != nil {
		t.Fatal(err)
	}
	c := configurationBootstrapFixture(t)
	// A nonexistent DSN/PKI file is deliberately valid as a path: capture
	// must not open/bootstrap external credentials to make this snapshot.
	c.Database.DSNFile = filepath.Join(t.TempDir(), "does-not-exist.dsn")
	beforeNodes, err := s.Nodes(ctx, "", "", 200, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := s.captureConfigurationDocument(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if doc.SettingsVersion != 9 || len(doc.Nodes) != 1 || common.M(doc.Settings["email"])["password"] != "capture-private-value" {
		t.Fatal("incomplete desired snapshot")
	}
	afterNodes, err := s.Nodes(ctx, "", "", 200, nil)
	if err != nil || !reflect.DeepEqual(beforeNodes, afterNodes) {
		t.Fatal("capture mutated nodes", err)
	}
	var version int64
	var jobs, audit int
	if err = s.DB.QueryRow(`SELECT version,(SELECT count(*) FROM v3_deployment_jobs),(SELECT count(*) FROM v3_audit) FROM v3_settings WHERE id=1`).Scan(&version, &jobs, &audit); err != nil || version != 9 || jobs != 0 || audit != 0 {
		t.Fatal("read-only capture created effects", err)
	}
	if _, err = os.Stat(c.Database.DSNFile); !os.IsNotExist(err) {
		t.Fatal("credential file created")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.captureConfigurationDocument(cancelled, c); err == nil {
		t.Fatal("cancelled capture succeeded")
	}
}

func TestConfigurationDocumentCaptureUsesOneDatabaseSnapshot(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n := nodeFixture("snapshot-node")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE v3_settings SET version=9,payload='{}'`); err != nil {
		t.Fatal(err)
	}
	var oid int64
	if err := s.DB.QueryRowContext(ctx, `SELECT 'v3_nodes'::regclass::oid`).Scan(&oid); err != nil {
		t.Fatal(err)
	}
	blocker, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err = blocker.ExecContext(ctx, `LOCK TABLE v3_nodes IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	c := configurationBootstrapFixture(t)
	type result struct {
		doc configurationDocument
		err error
	}
	done := make(chan result, 1)
	go func() { d, e := s.captureConfigurationDocument(ctx, c); done <- result{d, e} }()
	// Once capture is waiting to read nodes, it has already read settings.
	// Commit both new values before unblocking that node read.
	for {
		var waiting bool
		if err = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation=$1 AND NOT granted AND mode='AccessShareLock')`, oid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("capture did not reach blocked node read")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err = blocker.ExecContext(ctx, `UPDATE v3_settings SET version=10`); err != nil {
		t.Fatal(err)
	}
	if _, err = blocker.ExecContext(ctx, `UPDATE v3_nodes SET endpoint='192.0.2.44:19100',version=version+1`); err != nil {
		t.Fatal(err)
	}
	if err = blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	captured := <-done
	if captured.err != nil || captured.doc.SettingsVersion != 9 || captured.doc.Nodes[n.ID].Endpoint != n.Endpoint || captured.doc.Nodes[n.ID].Version != 1 {
		t.Fatal("torn configuration snapshot", captured.err)
	}
	later, err := s.captureConfigurationDocument(ctx, c)
	if err != nil || later.SettingsVersion != 10 || later.Nodes[n.ID].Endpoint != "192.0.2.44:19100" || later.Nodes[n.ID].Version != 2 {
		t.Fatal("subsequent snapshot did not see committed values", err)
	}
}

func FuzzConfigurationDocumentParsing(f *testing.F) {
	c, err := LoadConfig(filepath.Join("..", "..", "webscan-v3.example.yaml"))
	if err != nil {
		f.Fatal(err)
	}
	doc, err := newConfigurationDocument(c, []byte(`{"retention":{"sqlite_events_days":30}}`), 1, []Node{nodeFixture("fuzz-node")}, time.Now())
	if err != nil {
		f.Fatal(err)
	}
	valid, err := marshalConfigurationDocument(doc)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	public, err := doc.redacted()
	if err != nil {
		f.Fatal(err)
	}
	valid, err = marshalConfigurationDocument(public)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("format_version: 3\nkind: webscan-configuration\n"))
	f.Add([]byte("a: &a [*a]\n"))
	f.Add([]byte("nodes: {node-a: {name: secret, name: different}}\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		doc, err := parseConfigurationDocument(raw)
		if err != nil {
			if err != errConfigurationDocument {
				t.Fatal("source-dependent parser error")
			}
			return
		}
		encoded, err := marshalConfigurationDocument(doc)
		if err != nil {
			t.Fatal("accepted input cannot serialize", err)
		}
		if _, err = parseConfigurationDocument(encoded); err != nil {
			t.Fatal("accepted input cannot roundtrip", err)
		}
	})
}
