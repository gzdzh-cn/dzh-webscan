package controlplane

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"

	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/nodeconfig"
)

type LegacyNodesImportReport struct {
	Session            string                            `json:"session"`
	Source             string                            `json:"source"`
	SessionVersion     int64                             `json:"session_version"`
	Nodes              int                               `json:"nodes"`
	Credentials        int                               `json:"credentials"`
	PendingCredentials int                               `json:"pending_credentials"`
	Retirements        int                               `json:"pending_retirements"`
	Conflicts          []MigrationReconciliationConflict `json:"conflicts"`
	Complete           bool                              `json:"complete"`
	Protected          bool                              `json:"protected"`
	ReadyForCutover    bool                              `json:"ready_for_cutover"`
}

// Every source path and credential remains private. A candidate ServerName is
// not a certificate identity; no import publishes an active node snapshot.
type migrationLegacyNode struct {
	Node            Node
	OriginalEnabled bool
	Credential      *SSHCredential
	CredentialState string
}
type migrationNodeImage struct {
	ID, Name, Endpoint, ServerName, Mode string
	Enabled                              bool
	Version, AppliedVersion              int64
	Shard                                int
	Config                               json.RawMessage
	Credential                           json.RawMessage
	CredentialID                         string
}
type migrationNodeChange struct {
	Before          *migrationNodeImage
	After           migrationNodeImage
	OriginalEnabled bool
	CredentialState string
	Retired         bool
}

func migrationNodeImageOf(n Node) migrationNodeImage {
	return migrationNodeImage{ID: n.ID, Name: n.Name, Endpoint: n.Endpoint, ServerName: n.ServerName, Mode: n.Mode, Enabled: n.Enabled, Version: n.Version, AppliedVersion: n.AppliedVersion, Shard: n.Shard, Config: append(json.RawMessage{}, n.Config...)}
}
func migrationNodeSame(a, b migrationNodeImage) bool {
	var ac, bc, ak, bk any
	if json.Unmarshal(a.Config, &ac) != nil || json.Unmarshal(b.Config, &bc) != nil {
		return false
	}
	if len(a.Credential) > 0 && json.Unmarshal(a.Credential, &ak) != nil || len(b.Credential) > 0 && json.Unmarshal(b.Credential, &bk) != nil {
		return false
	}
	a.Config, b.Config, a.Credential, b.Credential = nil, nil, nil, nil
	return reflect.DeepEqual(a, b) && reflect.DeepEqual(ac, bc) && reflect.DeepEqual(ak, bk)
}
func migrationNodesMAC(v *Vault, key string, raw []byte) string {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/migration-nodes-source/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func migrationNodesSeal(v *Vault, aad string, raw []byte) (string, []byte, []byte, error) {
	if v == nil || v.keys[v.active] == nil {
		return "", nil, nil, ErrCredentialUnavailable
	}
	a := v.keys[v.active]
	n := make([]byte, a.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return "", nil, nil, e
	}
	return v.active, n, a.Seal(nil, n, raw, []byte("webscan-v3/migration-nodes/v1\x00"+aad)), nil
}
func migrationNodesOpen(v *Vault, key, aad string, nonce, sealed []byte) ([]byte, error) {
	if v == nil || v.keys[key] == nil || len(nonce) != v.keys[key].NonceSize() || len(sealed) > 4<<20 {
		return nil, ErrCredentialUnavailable
	}
	return v.keys[key].Open(nil, nonce, sealed, []byte("webscan-v3/migration-nodes/v1\x00"+aad))
}

func parseMigrationLegacyNodes(raw []byte) ([]migrationLegacyNode, error) {
	c, e := configuration.Parse(raw, "")
	if e != nil {
		return nil, ErrMigrationSession
	}
	if len(c.Nodes) > 10000 {
		return nil, ErrMigrationSession
	}
	out := make([]migrationLegacyNode, 0, len(c.Nodes))
	for _, old := range c.Nodes {
		s := nodeconfig.DefaultSettings()
		groups := common.Map{"monitor": old["monitor"], "scan": old["scan"], "resources": old["resources"], "transport": old["transport"]}
		if json.Unmarshal(common.JSON(groups), &s) != nil {
			return nil, ErrMigrationSession
		}
		s.ProbeSeconds = common.I(common.M(c.Raw["health"])["filesystem_probe_seconds"])
		s.RetentionDays = common.I(common.M(c.Raw["retention"])["local_logs_days"])
		s.MetricsSourceIP = common.S(common.M(old["metrics"])["allowed_source_ip"])
		// v2's health probe could live outside monitored roots. Select a bounded
		// new probe without widening the saved monitor's coverage or exclusions.
		valid := false
		for _, root := range s.Monitor.Roots {
			s.ProbeDirectory = filepath.Join(root, ".webscan-probe")
			if s.Validate() == nil {
				valid = true
				break
			}
		}
		if !valid {
			return nil, ErrMigrationSession
		}
		config := common.M(mustMigrationNodeJSON(s))
		config["monitoring_policy"] = common.Map{"source": "independent", "rules_version": "0"}
		config["migration_pending"] = true
		mode := common.S(common.M(old["deployment"])["mode"])
		// v2.0.46 schema's omitted deployment mode was native. The current
		// install default is Docker and must not reinterpret an old YAML.
		if !common.B(old["_deployment_explicit"]) {
			mode = "native"
		}
		n := Node{ID: common.S(old["id"]), Name: common.S(old["name"]), Endpoint: net.JoinHostPort(common.S(old["host"]), strconv.Itoa(common.I(common.M(old["metrics"])["port"]))), ServerName: common.S(old["id"]), Mode: mode, Enabled: false, Config: common.JSON(config)}
		if n.Validate() != nil {
			return nil, ErrMigrationSession
		}
		ssh := common.M(old["ssh"])
		candidate := migrationLegacyNode{Node: n, OriginalEnabled: common.B(old["enabled"]), CredentialState: "fingerprint_confirmation_required"}
		if common.S(ssh["auth_method"]) == "key" {
			candidate.CredentialState = "private_key_import_required"
		} else {
			credential := SSHCredential{Host: common.S(old["host"]), Port: common.I(ssh["port"]), Fingerprint: common.S(ssh["host_key_sha256"]), Password: common.S(ssh["password"])}
			if credential.validate() == nil {
				candidate.Credential = &credential
				candidate.CredentialState = "stored"
			} else if credential.Fingerprint != "" {
				return nil, ErrMigrationSession
			}
		}
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node.ID < out[j].Node.ID })
	return out, nil
}
func mustMigrationNodeJSON(v any) any {
	raw, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

func migrationNodeCurrentTx(ctx context.Context, tx *sql.Tx, id string) (migrationNodeImage, error) {
	n, e := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR UPDATE`, id))
	if e != nil {
		return migrationNodeImage{}, e
	}
	out := migrationNodeImageOf(n)
	e = tx.QueryRowContext(ctx, `SELECT c.id,to_jsonb(c) FROM v3_web_node_credentials w JOIN v3_credentials c ON c.id=w.credential WHERE w.node=$1`, id).Scan(&out.CredentialID, &out.Credential)
	if e == sql.ErrNoRows {
		e = nil
	}
	return out, e
}

func migrationNodeChangesTx(ctx context.Context, tx *sql.Tx, v *Vault, source string) (map[string]migrationNodeChange, error) {
	rows, e := tx.QueryContext(ctx, `SELECT node,key_id,nonce,ciphertext FROM v3_migration_node_rows WHERE source=$1 ORDER BY node`, source)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]migrationNodeChange{}
	for rows.Next() {
		var id, key string
		var nonce, sealed []byte
		var change migrationNodeChange
		if e = rows.Scan(&id, &key, &nonce, &sealed); e != nil {
			return nil, e
		}
		raw, e := migrationNodesOpen(v, key, source+":"+id, nonce, sealed)
		if e != nil {
			return nil, e
		}
		e = singleDecode(raw, &change)
		clear(raw)
		if e != nil || change.After.ID != id {
			return nil, ErrMigrationSession
		}
		out[id] = change
	}
	return out, rows.Err()
}

// MapLegacyNodes is a private migration operation. It never reads referenced
// host keys, connects to SSH, signs certificates, queues deployments or enables
// a node. Conflict reports contain aggregate categories only.
func (s *Store) MapLegacyNodes(ctx context.Context, session string, expected int64, sourceYAML, sourceID string, v *Vault) (report LegacyNodesImportReport, err error) {
	defer func() {
		if err != nil {
			report = LegacyNodesImportReport{}
			err = safeMigrationSessionError(err)
		}
	}()
	if !validArchiveSource(session) || !validArchiveSource(sourceID) || expected < 1 || v == nil {
		return report, ErrMigrationSession
	}
	raw, e := readLegacySettings(sourceYAML)
	if e != nil {
		return report, ErrMigrationSession
	}
	defer clear(raw)
	candidates, e := parseMigrationLegacyNodes(raw)
	if e != nil {
		return report, e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return report, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); e != nil {
		return report, e
	}
	if e = migrationSessionLock(ctx, tx, session); e != nil {
		return report, e
	}
	state, e := migrationSessionTx(ctx, tx, session)
	if e != nil || state.RecoveryHold {
		return report, ErrMigrationSession
	}
	var revision string
	// A YAML cannot invent a new source identity. It belongs to a ready,
	// independently indexed host-manager/central source in this session.
	e = tx.QueryRowContext(ctx, `SELECT id FROM v3_migration_revisions WHERE session=$1 AND source_id=$2 AND state='ready' AND role IN ('host-manager','central') ORDER BY (role='host-manager') DESC,sequence DESC LIMIT 1`, session, sourceID).Scan(&revision)
	if e != nil || verifyMigrationRevisionIndex(ctx, tx, revision) != nil {
		return report, ErrMigrationSession
	}
	var busy bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_revisions WHERE session=$1 AND state='indexing') OR EXISTS(SELECT 1 FROM v3_migration_deltas WHERE session=$1 AND state='comparing')`, session).Scan(&busy); e != nil || busy {
		return report, ErrMigrationSession
	}
	var latest string
	e = tx.QueryRowContext(ctx, `SELECT id FROM v3_migration_node_sources WHERE session=$1 AND source_id=$2 ORDER BY sequence DESC LIMIT 1`, session, sourceID).Scan(&latest)
	if e != nil && e != sql.ErrNoRows {
		return report, e
	}
	var existing, key string
	var original, finished int64
	var reportRaw []byte
	var nonce, sealed []byte
	// Look up via every retained receipt key so key rotation does not remap a
	// previously fixed source. The stored ciphertext rechecks exact bytes.
	for kid := range v.receiptKeys {
		proof := migrationNodesMAC(v, kid, raw)
		e = tx.QueryRowContext(ctx, `SELECT id,key_id,nonce,ciphertext,request_version,finished_version,report FROM v3_migration_node_sources WHERE session=$1 AND source_id=$2 AND content_hmac=$3`, session, sourceID, proof).Scan(&existing, &key, &nonce, &sealed, &original, &finished, &reportRaw)
		if e == nil {
			break
		}
		if e != sql.ErrNoRows {
			return report, e
		}
	}
	if existing != "" {
		if existing != latest {
			return report, ErrConflict
		}
		if expected != state.Version && (expected != original || state.Version != finished) {
			return report, ErrConflict
		}
		saved, e := migrationNodesOpen(v, key, existing, nonce, sealed)
		if e != nil || !bytes.Equal(saved, raw) {
			clear(saved)
			return report, ErrMigrationSession
		}
		clear(saved)
		changes, e := migrationNodeChangesTx(ctx, tx, v, existing)
		if e != nil {
			return report, e
		}
		for id, change := range changes {
			now, e := migrationNodeCurrentTx(ctx, tx, id)
			if e != nil || !migrationNodeSame(now, change.After) {
				return report, ErrConflict
			}
		}
		if singleDecode(reportRaw, &report) != nil {
			return report, ErrMigrationSession
		}
		report.SessionVersion = state.Version
		return report, tx.Commit()
	}
	if state.Version != expected {
		return report, ErrConflict
	}
	if state.Phase != "indexed" && state.Phase != "collecting" {
		return report, ErrMigrationSession
	}
	var cluster struct {
		Shards int `json:"shards"`
	}
	var clusterRaw []byte
	if len(candidates) > 0 {
		if e = tx.QueryRowContext(ctx, `SELECT payload FROM v3_cluster WHERE id=1`).Scan(&clusterRaw); e != nil || json.Unmarshal(clusterRaw, &cluster) != nil || cluster.Shards < 1 || cluster.Shards > 4096 {
			return report, ErrMigrationSession
		}
	}
	var previous string
	var sequence int64
	e = tx.QueryRowContext(ctx, `SELECT id,sequence FROM v3_migration_node_sources WHERE session=$1 AND source_id=$2 ORDER BY sequence DESC LIMIT 1`, session, sourceID).Scan(&previous, &sequence)
	if e != nil && e != sql.ErrNoRows {
		return report, e
	}
	prior := map[string]migrationNodeChange{}
	if previous != "" {
		prior, e = migrationNodeChangesTx(ctx, tx, v, previous)
		if e != nil {
			return report, e
		}
	}
	report = LegacyNodesImportReport{Session: session, SessionVersion: state.Version, Nodes: len(candidates), Protected: true, Conflicts: []MigrationReconciliationConflict{}}
	conflicts := map[string]int64{}
	for _, candidate := range candidates {
		current, e := migrationNodeCurrentTx(ctx, tx, candidate.Node.ID)
		before, owned := prior[candidate.Node.ID]
		if e == nil && (!owned || !migrationNodeSame(current, before.After)) {
			conflicts["node_target_conflict"]++
		} else if e != nil && e != sql.ErrNoRows {
			return report, e
		} else if e == sql.ErrNoRows && owned {
			conflicts["mapped_node_missing"]++
		}
		if !owned {
			var has bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_credentials WHERE node=$1) OR EXISTS(SELECT 1 FROM v3_nodes WHERE id=$1)`, candidate.Node.ID).Scan(&has); e != nil {
				return report, e
			}
			if has {
				conflicts["credential_target_conflict"]++
			}
		}
	}
	for id, change := range prior {
		current, e := migrationNodeCurrentTx(ctx, tx, id)
		if e != nil || !migrationNodeSame(current, change.After) {
			conflicts["mapped_node_changed"]++
		}
	}
	if len(conflicts) > 0 {
		for category, count := range conflicts {
			report.Conflicts = append(report.Conflicts, MigrationReconciliationConflict{category, count})
		}
		sort.Slice(report.Conflicts, func(i, j int) bool { return report.Conflicts[i].Category < report.Conflicts[j].Category })
		return report, tx.Commit()
	}
	if e = bindMigrationDomain(ctx, tx, "nodes", session, "", nil); e != nil {
		return report, e
	}
	proof := migrationNodesMAC(v, v.active, raw)
	source := digest([]byte(session + ":" + sourceID + ":" + proof))
	report.Source = source
	report.SessionVersion = expected + 1
	key, nonce, sealed, e = migrationNodesSeal(v, source, raw)
	if e != nil {
		return report, e
	}
	// The source row and all business mappings commit together; no partial
	// source can be mistaken for a completed resume checkpoint.
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_node_sources(id,session,source_id,revision,sequence,content_hmac,key_id,nonce,ciphertext,request_version,finished_version,report) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'{}')`, source, session, sourceID, revision, sequence+1, proof, key, nonce, sealed, expected, expected+1); e != nil {
		return report, e
	}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		id := candidate.Node.ID
		seen[id] = true
		change := migrationNodeChange{OriginalEnabled: candidate.OriginalEnabled, CredentialState: candidate.CredentialState}
		old, owned := prior[id]
		version := int64(0)
		if owned {
			before := old.After
			change.Before = &before
			version = before.Version
		}
		if e = putNode(ctx, tx, candidate.Node, version, cluster.Shards); e != nil {
			return report, e
		}
		if candidate.Credential != nil {
			credential := token()
			kid, n, cipher, e := v.seal(credential, id, 1, *candidate.Credential)
			if e != nil {
				return report, e
			}
			if _, e = tx.ExecContext(ctx, `INSERT INTO v3_credentials(id,node,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5)`, credential, id, kid, n, cipher); e != nil {
				return report, e
			}
			if _, e = tx.ExecContext(ctx, `INSERT INTO v3_web_node_credentials(node,credential) VALUES($1,$2) ON CONFLICT(node) DO UPDATE SET credential=excluded.credential,updated_at=clock_timestamp()`, id, credential); e != nil {
				return report, e
			}
			report.Credentials++
		} else {
			if _, e = tx.ExecContext(ctx, `DELETE FROM v3_web_node_credentials WHERE node=$1`, id); e != nil {
				return report, e
			}
			report.PendingCredentials++
		}
		change.After, e = migrationNodeCurrentTx(ctx, tx, id)
		if e != nil {
			return report, e
		}
		if e = saveMigrationNodeChangeTx(ctx, tx, v, source, id, change); e != nil {
			return report, e
		}
	}
	for id, old := range prior {
		if seen[id] {
			continue
		}
		before := old.After
		change := old
		change.Before = &before
		change.Retired = true
		report.Retirements++
		if e = saveMigrationNodeChangeTx(ctx, tx, v, source, id, change); e != nil {
			return report, e
		}
	}
	report.Complete = true
	reportRaw, _ = json.Marshal(report)
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_node_sources SET report=$2 WHERE id=$1`, source, reportRaw); e != nil {
		return report, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,updated_at=clock_timestamp() WHERE id=$1`, session); e != nil {
		return report, e
	}
	return report, tx.Commit()
}
func saveMigrationNodeChangeTx(ctx context.Context, tx *sql.Tx, v *Vault, source, id string, change migrationNodeChange) error {
	raw, e := json.Marshal(change)
	if e != nil {
		return e
	}
	defer clear(raw)
	key, nonce, sealed, e := migrationNodesSeal(v, source+":"+id, raw)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_node_rows(source,node,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5)`, source, id, key, nonce, sealed)
	return e
}
