package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"

	"webscan/internal/common"
)

// The encrypted exact images authorize only the mechanical restoration of
// imported intent. They cannot authorize an arbitrary subsequent node edit.
const migrationCutoverNodesSchema = `
CREATE TABLE v3_migration_node_activations(
 session text NOT NULL REFERENCES v3_migration_sessions(id),node text NOT NULL,
 source text NOT NULL REFERENCES v3_migration_node_sources(id),
 key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL,
 PRIMARY KEY(session,node)
);
`

type migrationNodeActivation struct {
	Source, Node  string
	Before, After migrationNodeImage
	Images        map[string]string
	Evidence      MigrationShadowEvidence
}
type migrationCutoverNode struct {
	source string
	change migrationNodeChange
}

// Call under the migration and session locks, before releasing any domain.
// Network calls are read-only and bounded; no ACK or remote write is possible.
func verifyMigrationNodesCutoverTx(ctx context.Context, tx *sql.Tx, state MigrationSession, v *Vault, c Config, activate bool, freezeManifests ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	rows, e := tx.QueryContext(ctx, `SELECT DISTINCT ON(source_id) id,source_id,key_id,nonce,ciphertext,content_hmac FROM v3_migration_node_sources WHERE session=$1 ORDER BY source_id,sequence DESC`, state.ID)
	if e != nil {
		return e
	}
	type source struct {
		id, origin, key, mac string
		nonce, sealed        []byte
	}
	sources := []source{}
	for rows.Next() {
		var s source
		if e = rows.Scan(&s.id, &s.origin, &s.key, &s.nonce, &s.sealed, &s.mac); e != nil {
			rows.Close()
			return e
		}
		sources = append(sources, s)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	// An unbound nodes domain cannot silently become ready for an old YAML that
	// was never imported. A genuinely empty source has an authenticated mapping.
	var held bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_domains WHERE domain='nodes' AND pending AND source=$1)`, state.ID).Scan(&held); e != nil {
		return e
	}
	if len(sources) == 0 {
		if held {
			return ErrMigrationCutoverProtected
		}
		return nil
	}
	var manifest MigrationFreezeManifest
	var manifestSHA string
	if len(freezeManifests) != 1 {
		return ErrMigrationCutoverProtected
	}
	manifest, manifestSHA, e = readMigrationFreezeManifest(freezeManifests[0], state.ID)
	if e != nil || !releaseDigest(state.FreezeDigest) {
		return ErrMigrationCutoverProtected
	}
	targets := map[string]migrationCutoverNode{}
	for _, s := range sources {
		var indexed bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_freezes f JOIN v3_migration_revisions r ON r.id=f.revision WHERE f.session=$1 AND r.source_id=$2 AND r.state='ready')`, state.ID, s.origin).Scan(&indexed); e != nil || !indexed {
			return ErrMigrationCutoverProtected
		}
		raw, e := migrationNodesOpen(v, s.key, s.id, s.nonce, s.sealed)
		if e != nil {
			return e
		}
		if migrationNodesMAC(v, s.key, raw) != s.mac || digest([]byte(state.ID+":"+s.origin+":"+s.mac)) != s.id {
			clear(raw)
			return ErrMigrationSession
		}
		expectedConfig := digest(raw)
		matched := false
		for _, frozen := range manifest.Sources {
			if frozen.SourceID != s.origin {
				continue
			}
			var bound bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_freezes f JOIN v3_migration_revisions r ON r.id=f.revision WHERE f.session=$1 AND f.role=$2 AND f.manifest_digest=$3 AND r.source_id=$4 AND r.role=f.role)`, state.ID, frozen.Role, manifestSHA, s.origin).Scan(&bound); e != nil || !bound {
				clear(raw)
				return ErrMigrationCutoverProtected
			}
			matched = true
			for _, writer := range frozen.Writers {
				fixed, e := readTrustData(writer.ConfigFile, true, 2<<20)
				valid := e == nil && writer.ConfigSHA256 == expectedConfig && digest(fixed) == expectedConfig
				clear(fixed)
				if !valid {
					clear(raw)
					return ErrMigrationCutoverProtected
				}
			}
		}
		if !matched {
			clear(raw)
			return ErrMigrationCutoverProtected
		}
		parsed, e := parseMigrationLegacyNodes(raw)
		clear(raw)
		if e != nil {
			return e
		}
		changes, e := migrationNodeChangesTx(ctx, tx, v, s.id)
		if e != nil {
			return e
		}
		seen := map[string]bool{}
		for _, p := range parsed {
			ch, ok := changes[p.Node.ID]
			if !ok || ch.Retired || ch.OriginalEnabled != p.OriginalEnabled {
				return ErrMigrationSession
			}
			// The parser and fixed source must agree on the whole saved intent.
			candidate := migrationNodeImageOf(p.Node)
			candidate.Version = ch.After.Version
			candidate.AppliedVersion = ch.After.AppliedVersion
			candidate.Shard = ch.After.Shard
			candidate.Credential = ch.After.Credential
			candidate.CredentialID = ch.After.CredentialID
			if !migrationNodeSame(candidate, ch.After) {
				return ErrMigrationSession
			}
			if previous, exists := targets[p.Node.ID]; exists && previous.source != s.id {
				return ErrMigrationSession
			}
			targets[p.Node.ID] = migrationCutoverNode{s.id, ch}
			seen[p.Node.ID] = true
		}
		for id, ch := range changes {
			if !seen[id] && !ch.Retired {
				return ErrMigrationSession
			}
			if ch.Retired {
				return ErrMigrationCutoverProtected
			}
		}
	}
	ids := make([]string, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var baseNeeded bool
	for _, target := range targets {
		baseNeeded = baseNeeded || target.change.OriginalEnabled
	}
	var observe func(migrationShadowTarget) MigrationShadowEvidence
	if baseNeeded {
		base, e := migrationShadowTLS(c)
		if e != nil {
			return ErrMigrationCutoverProtected
		}
		observe = func(t migrationShadowTarget) MigrationShadowEvidence {
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return migrationShadowObserve(bounded, c, base, t)
		}
	}
	var oldestSample int64
	for _, id := range ids {
		target := targets[id]
		current, e := migrationNodeCurrentTx(ctx, tx, id)
		if e != nil || !migrationNodeSame(current, target.change.After) {
			return ErrMigrationCutoverProtected
		}
		var dirty bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_node_runtime WHERE node=$1) OR EXISTS(SELECT 1 FROM v3_node_configurations WHERE node=$1) OR EXISTS(SELECT 1 FROM v3_node_status WHERE node=$1) OR EXISTS(SELECT 1 FROM v3_node_readiness WHERE node=$1) OR EXISTS(SELECT 1 FROM v3_health_samples WHERE node=$1)`, id).Scan(&dirty); e != nil || dirty {
			return ErrMigrationCutoverProtected
		}
		if !target.change.OriginalEnabled {
			continue
		}
		if _, e = nodeRuntimeSettings(current.Config); e != nil {
			return ErrMigrationCutoverProtected
		}
		evidence := observe(migrationShadowTarget{Node: id, Version: current.Version, ConfigSHA: digest(current.Config), Endpoint: current.Endpoint, ServerName: current.ServerName, Mode: current.Mode})
		now := time.Now()
		if evidence.Status != "observed" || !evidence.MatchesSaved || !releaseDigest(evidence.PeerCertificate) || evidence.LastSample < now.Add(-2*time.Minute).UnixMilli() || evidence.LastSample > now.Add(30*time.Second).UnixMilli() {
			return ErrMigrationCutoverProtected
		}
		if oldestSample == 0 || evidence.LastSample < oldestSample {
			oldestSample = evidence.LastSample
		}
		if !activate {
			continue
		}
		proof := migrationNodeActivation{Source: target.source, Node: id, Before: current, Images: map[string]string{}, Evidence: evidence}
		if e = migrationNodeActivationImageTx(ctx, tx, &proof, "v3_nodes", common.Map{"id": id}); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE v3_nodes SET enabled=true,applied_version=version,updated_at=clock_timestamp() WHERE id=$1`, id); e != nil {
			return e
		}
		snapshot, e := captureSavedNodeTx(ctx, tx, id)
		if e != nil {
			return e
		}
		if e = publishNodeRuntimeTx(ctx, tx, id, snapshot, current.Version); e != nil {
			return e
		}
		proof.After, e = migrationNodeCurrentTx(ctx, tx, id)
		if e != nil {
			return e
		}
		for _, row := range []struct {
			table string
			key   common.Map
		}{{"v3_nodes", common.Map{"id": id}}, {"v3_node_configurations", common.Map{"id": snapshot}}, {"v3_node_runtime", common.Map{"node": id}}} {
			if e = migrationNodeActivationImageTx(ctx, tx, &proof, row.table, row.key); e != nil {
				return e
			}
		}
		raw, _ := json.Marshal(proof)
		key, nonce, sealed, e := migrationNodesSeal(v, "activation:"+state.ID+":"+id, raw)
		clear(raw)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_node_activations(session,node,source,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5,$6)`, state.ID, id, target.source, key, nonce, sealed); e != nil {
			return e
		}
	}
	if oldestSample > 0 && oldestSample < time.Now().Add(-2*time.Minute).UnixMilli() {
		return ErrMigrationCutoverProtected
	}
	return nil
}
func migrationNodeActivationImageTx(ctx context.Context, tx *sql.Tx, proof *migrationNodeActivation, table string, key common.Map) error {
	column := "node"
	if table == "v3_nodes" || table == "v3_node_configurations" {
		column = "id"
	}
	var raw []byte
	if e := tx.QueryRowContext(ctx, `SELECT to_jsonb(t) FROM `+quotePG(table)+` t WHERE `+quotePG(column)+`=$1`, common.S(key[column])).Scan(&raw); e != nil {
		return e
	}
	decoded, e := common.Decode(raw)
	if e != nil {
		return e
	}
	identity := migrationLegacySourceKey(table, key)
	// More than one image for the same key is necessary for before/after nodes.
	proof.Images[identity+":"+digest(common.JSON(decoded))] = table
	return nil
}
