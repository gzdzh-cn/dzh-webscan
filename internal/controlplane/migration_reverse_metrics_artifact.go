package controlplane

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
)

const migrationReverseMetricsManifestLimit = 32 << 20

func migrationReverseMetricsDirectory(s *MigrationLegacySink, create bool) (*os.File, error) {
	if s == nil {
		return nil, ErrMigrationSession
	}
	parent, e := trustDirectory(s.output, true)
	if e != nil {
		return nil, ErrMigrationSession
	}
	defer parent.Close()
	if create {
		if e = unix.Mkdirat(int(parent.Fd()), "metrics-history", 0700); e != nil && e != unix.EEXIST {
			return nil, ErrMigrationSession
		}
	}
	return trustDirectory(filepath.Join(s.output, "metrics-history"), true)
}
func migrationReverseMetricsWriteFile(s *MigrationLegacySink, name string, raw []byte) error {
	if name != "manifest.json" && (len(name) != len("chunk-")+64+len(".jsonl") || name != "chunk-"+digest(raw)+".jsonl") || len(raw) == 0 {
		return ErrMigrationSession
	}
	d, e := migrationReverseMetricsDirectory(s, true)
	if e != nil {
		return e
	}
	defer d.Close()
	temporary := ".pending-" + token()
	fd, e := unix.Openat(int(d.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrMigrationSession
	}
	f := os.NewFile(uintptr(fd), temporary)
	defer unix.Unlinkat(int(d.Fd()), temporary, 0)
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return ErrMigrationSession
	}
	e = publishTrustDirectory(int(d.Fd()), temporary, name)
	if e == unix.EEXIST {
		actual, err := readTrustData(filepath.Join(s.output, "metrics-history", name), true, migrationReverseMetricsManifestLimit)
		if err != nil || string(actual) != string(raw) {
			return ErrMigrationSession
		}
	} else if e != nil {
		return ErrMigrationSession
	}
	if d.Sync() != nil {
		return ErrMigrationSession
	}
	return nil
}
func migrationReverseMetricsReadManifest(s *MigrationLegacySink) (migrationReverseMetricsManifest, bool, error) {
	var m migrationReverseMetricsManifest
	file := filepath.Join(s.output, "metrics-history", "manifest.json")
	_, e := os.Lstat(file)
	if os.IsNotExist(e) {
		return m, false, nil
	}
	if e != nil {
		return m, false, ErrMigrationSession
	}
	raw, e := readTrustData(file, true, migrationReverseMetricsManifestLimit)
	if e != nil || singleDecode(raw, &m) != nil || string(raw) != string(common.JSON(m)) {
		return m, false, ErrMigrationSession
	}
	return m, true, nil
}
func migrationReverseMetricsSameState(want, actual migrationReverseMetricsManifest) error {
	if actual.Format != 1 || actual.Session != want.Session || actual.Version != want.Version || actual.Seal != want.Seal || actual.Target != want.Target || actual.Plan != want.Plan || actual.Source != want.Source || !reflect.DeepEqual(actual.Original, want.Original) || !actual.Began.Equal(want.Began) || !actual.Sealed.Equal(want.Sealed) || actual.End != want.End || !reflect.DeepEqual(actual.Nodes, want.Nodes) {
		return ErrMigrationSession
	}
	return nil
}
func migrationReverseMetricsVerifyManifest(ctx context.Context, s *MigrationLegacySink, v *Vault, m migrationReverseMetricsManifest) error {
	if v == nil {
		return ErrMigrationSession
	}
	mac := migrationReverseMetricsMAC(v, m)
	if mac == "" || subtle.ConstantTimeCompare([]byte(mac), []byte(m.MAC)) != 1 {
		return ErrMigrationSession
	}
	return migrationReverseMetricsVerifyFiles(ctx, s, m)
}
func migrationReverseMetricsVerifyFiles(ctx context.Context, s *MigrationLegacySink, m migrationReverseMetricsManifest) error {
	if m.Format != 1 || m.Session != s.session || len(m.Nodes) > 20000 || len(m.Layers) < 1 || len(m.Layers) > 2 || !releaseDigest(m.IsolationBefore) || !releaseDigest(m.IsolationAfter) || m.End < 1 || m.End != m.Sealed.Add(5*time.Minute).UnixMilli() {
		return ErrMigrationSession
	}
	known := map[string]bool{}
	for i, node := range m.Nodes {
		if !identifier.MatchString(node) || i > 0 && m.Nodes[i-1] >= node {
			return ErrMigrationSession
		}
		known[node] = true
	}
	var total int64
	chunks := 0
	for i, layer := range m.Layers {
		if i == 0 && layer.Name != "history" || i == 1 && layer.Name != "raw" || len(layer.Nodes) > 20000 {
			return ErrMigrationSession
		}
		for j, node := range layer.Nodes {
			if !known[node] || j > 0 && layer.Nodes[j-1] >= node {
				return ErrMigrationSession
			}
		}
		at, index := int64(1), 0
		for _, chunk := range layer.Chunks {
			if ctx.Err() != nil || index >= len(layer.Nodes) || chunk.Node != layer.Nodes[index] || chunk.Start != at || chunk.End < chunk.Start || chunk.End > m.End || chunk.Bytes < 1 || chunk.Bytes > 16<<20 || chunk.Fragments < 0 || chunk.Points < 0 || chunk.Points > 240000 || !releaseDigest(chunk.SHA256) || chunk.File != "chunk-"+chunk.SHA256+".jsonl" {
				return ErrMigrationSession
			}
			raw, e := readTrustData(filepath.Join(s.output, "metrics-history", chunk.File), true, 16<<20)
			if e != nil || len(raw) != chunk.Bytes || digest(raw) != chunk.SHA256 {
				return ErrMigrationSession
			}
			var lines []migrationMetricLine
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			for {
				var line migrationMetricLine
				e = decoder.Decode(&line)
				if errors.Is(e, io.EOF) {
					break
				}
				if e != nil {
					return ErrMigrationSession
				}
				lines = append(lines, line)
				if len(lines) > 20000 {
					return ErrMigrationSession
				}
			}
			encoded, fragments, points, e := migrationReverseMetricsEncode(lines, chunk.Node, chunk.Start, chunk.End)
			if e != nil || string(encoded) != string(raw) || fragments != chunk.Fragments || points != chunk.Points {
				return ErrMigrationSession
			}
			total += int64(chunk.Bytes)
			chunks++
			if total > migrationReverseMetricsMaxBytes || chunks > migrationReverseMetricsMaxChunks {
				return ErrMigrationSession
			}
			at = chunk.End + 1
			if chunk.End == m.End {
				index++
				at = 1
			}
		}
		if index != len(layer.Nodes) || at != 1 {
			return ErrMigrationSession
		}
	}
	return nil
}

// The baseline has no VM artifact yet. Once present, every authenticated file
// becomes part of the sink digest, including labels v2 cannot display.
func (s *MigrationLegacySink) migrationReverseMetricsArtifactDigest(ctx context.Context) (string, error) {
	m, exists, e := migrationReverseMetricsReadManifest(s)
	if e != nil {
		return "", e
	}
	if !exists {
		return "", nil
	}
	if e = migrationReverseMetricsVerifyFiles(ctx, s, m); e != nil {
		return "", e
	}
	return digest(common.JSON(m)), nil
}
func verifyMigrationReverseMetricsTx(ctx context.Context, tx *sql.Tx, c Config, session string, sink *MigrationLegacySink, v *Vault, r migrationReverseMetricsRuntime) (string, error) {
	if v == nil || sink == nil {
		return "", ErrMigrationSession
	}
	want, e := migrationReverseMetricsStateTx(ctx, tx, session, sink)
	if e != nil {
		return "", e
	}
	m, exists, e := migrationReverseMetricsReadManifest(sink)
	if e != nil || !exists {
		return "", ErrMigrationSession
	}
	var version int64
	var seal, target, hash string
	var raw []byte
	if tx.QueryRowContext(ctx, `SELECT session_version,seal_digest,target_digest,manifest_digest,manifest FROM v3_migration_reverse_metric_receipts WHERE session=$1`, session).Scan(&version, &seal, &target, &hash, &raw) != nil {
		return "", ErrMigrationSession
	}
	var recorded migrationReverseMetricsManifest
	if singleDecode(raw, &recorded) != nil || !reflect.DeepEqual(recorded, m) || version != m.Version || seal != m.Seal || target != m.Target || hash != digest(common.JSON(m)) || migrationReverseMetricsVerifyManifest(ctx, sink, v, m) != nil {
		return "", ErrMigrationSession
	}
	p, binding, source, e := migrationReverseMetricsPlan(ctx, tx, c, sink, m.Original, r)
	if e != nil {
		return "", e
	}
	want.Original, want.Target, want.Source, want.Plan = m.Original, binding, source, migrationReverseMetricsBinding(p)
	if want.Version != m.Version {
		if migrationReverseMetricsLostReplyTx(ctx, tx, v, session, m.Version, want.Version, hash) != nil {
			return "", ErrMigrationSession
		}
		want.Version = m.Version
	}
	if migrationReverseMetricsSameState(want, m) != nil {
		return "", ErrMigrationSession
	}
	if _, e = r.host.isolation(ctx, p); e != nil {
		return "", ErrMigrationSession
	}
	if e = migrationReverseMetricsVerifyActual(ctx, c, m); e != nil {
		return "", e
	}
	after, afterTarget, afterSource, e := migrationReverseMetricsPlan(ctx, tx, c, sink, m.Original, r)
	if e != nil || migrationReverseMetricsBinding(after) != m.Plan || afterTarget != m.Target || afterSource != m.Source {
		return "", ErrMigrationSession
	}
	if _, e = r.host.isolation(ctx, after); e != nil {
		return "", ErrMigrationSession
	}
	return hash, nil
}

// A repeated final rollback may follow a lost response. The only permitted
// version change is the one authenticated rollback receipt, never a blanket
// exception for an older archive or an administrator-supplied version.
func migrationReverseMetricsLostReplyTx(ctx context.Context, tx *sql.Tx, v *Vault, session string, archived, current int64, hash string) error {
	var phase, key, proof string
	var request, finished int64
	var raw []byte
	if current != archived+1 || tx.QueryRowContext(ctx, `SELECT phase FROM v3_migration_sessions WHERE id=$1`, session).Scan(&phase) != nil || phase != "rolled_back" {
		return ErrMigrationSession
	}
	if tx.QueryRowContext(ctx, `SELECT request_version,finished_version,evidence,key_id,proof FROM v3_migration_cutovers WHERE session=$1 AND action='rollback'`, session).Scan(&request, &finished, &raw, &key, &proof) != nil || request != archived || finished != current {
		return ErrMigrationSession
	}
	mac := migrationCutoverProof(v, key, session, "rollback", request, finished, raw)
	var evidence MigrationLegacyProjectionEvidence
	if mac == "" || subtle.ConstantTimeCompare([]byte(mac), []byte(proof)) != 1 || singleDecode(raw, &evidence) != nil || evidence.Session != session || evidence.Phase != "rollback" || !evidence.Verified || len(evidence.Pending) != 0 || evidence.Coverage != "legacy-business-and-metric-archive" || evidence.MetricsSHA256 != hash {
		return ErrMigrationSession
	}
	mac = migrationLegacyEvidenceMAC(v, evidence)
	if mac == "" || subtle.ConstantTimeCompare([]byte(mac), []byte(evidence.SHA256)) != 1 {
		return ErrMigrationSession
	}
	return nil
}
