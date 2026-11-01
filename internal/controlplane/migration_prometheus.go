package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/persist"
	"webscan/internal/telemetry"
)

var ErrMigrationPrometheus = errors.New("旧 Prometheus 归档来源、节点、检查点或响应校验失败；未修改源数据库、当前采集和通知")

type MigrationPrometheusReport struct {
	Session               string `json:"session"`
	Job                   string `json:"job"`
	HealthRevision        string `json:"health_revision"`
	Nodes                 int    `json:"nodes"`
	CompletedQueries      int64  `json:"completed_queries"`
	MissingValues         int64  `json:"missing_values"`
	ReturnedValues        int64  `json:"returned_values"`
	SourceSHA256          string `json:"source_sha256"`
	ArchiveSHA256         string `json:"archive_sha256,omitempty"`
	Complete              bool   `json:"complete"`
	ReadyForCutover       bool   `json:"ready_for_cutover"`
	EvaluationStepSeconds int    `json:"evaluation_step_seconds"`
	RateWindowSeconds     int    `json:"rate_window_seconds"`
	ArchivePath           string `json:"-"`
}

type migrationPrometheusBinding struct {
	Purpose        string   `json:"purpose"`
	Session        string   `json:"session"`
	NodeSource     string   `json:"node_source"`
	ConfigProof    string   `json:"config_proof"`
	HealthRevision string   `json:"health_revision"`
	HealthSource   string   `json:"health_source"`
	SnapshotSHA256 string   `json:"snapshot_sha256"`
	RevisionDigest string   `json:"revision_digest"`
	From           int64    `json:"from"`
	Until          int64    `json:"until"`
	Nodes          []string `json:"nodes"`
	QueriesSHA256  string   `json:"queries_sha256"`
}

type migrationPrometheusReceipt struct {
	Task           migrationPrometheusTask `json:"task"`
	State          string                  `json:"state"`
	ResponseSHA256 string                  `json:"response_sha256,omitempty"`
	Returned       int64                   `json:"returned"`
	Missing        int64                   `json:"missing"`
	Meaning        string                  `json:"meaning"`
}

type migrationPrometheusManifest struct {
	Binding migrationPrometheusBinding `json:"binding"`
	Report  MigrationPrometheusReport  `json:"report"`
	KeyID   string                     `json:"key_id"`
	Proof   string                     `json:"proof"`
}

func migrationPrometheusProof(v *Vault, key string, raw []byte) string {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/prometheus-archive/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func migrationPrometheusManifestProof(v *Vault, manifest migrationPrometheusManifest) string {
	manifest.Proof = ""
	raw, _ := json.Marshal(manifest)
	return migrationPrometheusProof(v, manifest.KeyID, raw)
}

func migrationPrometheusBindingTx(ctx context.Context, tx *sql.Tx, v *Vault, session string, expected int64, nodeSource, healthRevision string, start, end time.Time) (migrationPrometheusBinding, string, error) {
	out := migrationPrometheusBinding{Purpose: "legacy-prometheus-evaluations-v1", Session: session, NodeSource: nodeSource, HealthRevision: healthRevision, From: start.Unix(), Until: end.Unix()}
	if v == nil || out.From < 1 || out.Until <= out.From || out.Until-out.From > 31*86400 || out.From%30 != 0 || out.Until%30 != 0 || out.Until > time.Now().Unix() || !validArchiveSource(nodeSource) {
		return out, "", ErrMigrationPrometheus
	}
	if migrationMetricSessionTx(ctx, tx, session, expected) != nil {
		return out, "", ErrMigrationPrometheus
	}
	r, _, err := migrationMetricRevisionTx(ctx, tx, session, healthRevision)
	if err != nil || verifyMigrationRevisionIndex(ctx, tx, healthRevision) != nil {
		return out, "", ErrMigrationPrometheus
	}
	out.HealthSource, out.RevisionDigest = r.Source, r.Digest
	var key, revision, sourceID string
	var nonce, sealed []byte
	if tx.QueryRowContext(ctx, "SELECT key_id,nonce,ciphertext,content_hmac,revision,source_id FROM v3_migration_node_sources WHERE id=$1 AND session=$2", nodeSource, session).Scan(&key, &nonce, &sealed, &out.ConfigProof, &revision, &sourceID) != nil {
		return out, "", ErrMigrationPrometheus
	}
	var latest string
	if tx.QueryRowContext(ctx, "SELECT id FROM v3_migration_node_sources WHERE session=$1 AND source_id=$2 ORDER BY sequence DESC LIMIT 1", session, sourceID).Scan(&latest) != nil || latest != nodeSource || verifyMigrationRevisionIndex(ctx, tx, revision) != nil {
		return out, "", ErrMigrationPrometheus
	}
	raw, err := migrationNodesOpen(v, key, nodeSource, nonce, sealed)
	if err != nil {
		return out, "", ErrMigrationPrometheus
	}
	defer clear(raw)
	if proof := migrationNodesMAC(v, key, raw); proof == "" || !hmac.Equal([]byte(proof), []byte(out.ConfigProof)) {
		return out, "", ErrMigrationPrometheus
	}
	parsed, err := configuration.Parse(raw, "")
	if err != nil || common.S(common.M(common.M(parsed.Raw["central"])["monitoring"])["mode"]) != "legacy" {
		return out, "", ErrMigrationPrometheus
	}
	out.Nodes = []string{"central"}
	known := map[string]bool{"central": true}
	for _, node := range parsed.Nodes {
		id := common.S(node["id"])
		if !identifier.MatchString(id) || known[id] {
			return out, "", ErrMigrationPrometheus
		}
		known[id] = true
		out.Nodes = append(out.Nodes, id)
	}
	if len(out.Nodes) > 10001 {
		return out, "", ErrMigrationPrometheus
	}
	sort.Strings(out.Nodes)
	queries, _ := json.Marshal(telemetry.HistoricalQueries)
	out.QueriesSHA256 = digest(queries)
	var snapshot string
	if tx.QueryRowContext(ctx, "SELECT snapshot,snapshot_sha256 FROM v3_migration_revisions WHERE id=$1", healthRevision).Scan(&snapshot, &out.SnapshotSHA256) != nil {
		return out, "", ErrMigrationPrometheus
	}
	return out, snapshot, nil
}

// Public host CLI accepts only identities, a bounded time window and a private
// output root. The legacy project fixes its Prometheus listener to loopback
// 19190; there is intentionally no address or query argument.
func (s *Store) ArchiveMigrationPrometheus(ctx context.Context, v *Vault, session string, expected int64, nodeSource, healthRevision string, start, end time.Time, directory string) (MigrationPrometheusReport, error) {
	return s.archiveMigrationPrometheus(ctx, v, session, expected, nodeSource, healthRevision, start, end, directory, migrationPrometheusClient())
}

func (s *Store) archiveMigrationPrometheus(ctx context.Context, v *Vault, session string, expected int64, nodeSource, healthRevision string, start, end time.Time, directory string, client *http.Client) (MigrationPrometheusReport, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return MigrationPrometheusReport{}, ErrMigrationPrometheus
	}
	defer tx.Rollback()
	binding, sourcePath, err := migrationPrometheusBindingTx(ctx, tx, v, session, expected, nodeSource, healthRevision, start, end)
	if err != nil {
		return MigrationPrometheusReport{}, err
	}
	raw, _ := json.Marshal(binding)
	job := digest(raw)
	report := MigrationPrometheusReport{Session: session, Job: job, HealthRevision: healthRevision, SourceSHA256: binding.SnapshotSHA256, Nodes: len(binding.Nodes), EvaluationStepSeconds: 30, RateWindowSeconds: 300}
	parent, err := trustDirectory(directory, true)
	if err != nil {
		return report, ErrMigrationPrometheus
	}
	defer parent.Close()
	name := "prometheus-" + job
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil && err != unix.EEXIST {
		return report, ErrMigrationPrometheus
	}
	root := filepath.Join(directory, name)
	dir, err := trustDirectory(root, true)
	if err != nil {
		return report, ErrMigrationPrometheus
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), "archive.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return report, ErrMigrationPrometheus
	}
	lock := os.NewFile(uintptr(fd), "archive.lock")
	defer lock.Close()
	if !singlePrivateFile(lock) || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return report, ErrMigrationPrometheus
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if manifestRaw, err := readTrustData(filepath.Join(root, "manifest.json"), true, 64<<10); err == nil {
		var manifest migrationPrometheusManifest
		if singleDecode(manifestRaw, &manifest) != nil || !migrationPrometheusBindingEqual(manifest.Binding, binding) || manifest.Proof == "" || !hmac.Equal([]byte(manifest.Proof), []byte(migrationPrometheusManifestProof(v, manifest))) {
			return report, ErrMigrationPrometheus
		}
		snapshot, err := openMigrationSnapshot(ctx, filepath.Join(root, "archive.sqlite3"))
		if err != nil {
			return report, ErrMigrationPrometheus
		}
		defer snapshot.close()
		if snapshot.sha != manifest.Report.ArchiveSHA256 || !manifest.Report.Complete {
			return report, ErrMigrationPrometheus
		}
		out := manifest.Report
		out.ArchivePath = filepath.Join(root, "archive.sqlite3")
		return out, nil
	} else if !os.IsNotExist(err) {
		// readTrustData deliberately hides errno; distinguish absence without ever
		// following an existing symlink or accepting an invalid private manifest.
		if _, statErr := os.Lstat(filepath.Join(root, "manifest.json")); !os.IsNotExist(statErr) {
			return report, ErrMigrationPrometheus
		}
	}
	working := filepath.Join(root, "working.sqlite3")
	if _, err := os.Lstat(working); os.IsNotExist(err) {
		source, err := openMigrationSnapshot(ctx, sourcePath)
		if err != nil {
			return report, ErrMigrationPrometheus
		}
		if source.sha != binding.SnapshotSHA256 {
			source.close()
			return report, ErrMigrationPrometheus
		}
		err = persist.BackupDB(source.db, working)
		source.close()
		if err != nil {
			return report, ErrMigrationPrometheus
		}
	}
	file, err := openTrustFile(working, true, 1<<40)
	if err != nil {
		return report, ErrMigrationPrometheus
	}
	file.Close()
	db, err := persist.OpenDB(working)
	if err != nil {
		return report, ErrMigrationPrometheus
	}
	defer db.Close()
	if err := migrationPrometheusBindWorking(ctx, db, binding, job, sourcePath); err != nil {
		return report, err
	}
	for requests := 0; requests < 16; requests++ {
		task, found, err := migrationPrometheusNext(ctx, db, binding, job)
		if err != nil {
			return report, err
		}
		if !found {
			if err := migrationPrometheusComplete(ctx, db, job); err != nil {
				return report, err
			}
			report, err = migrationPrometheusProgress(ctx, db, report)
			if err != nil {
				return report, err
			}
			archive := filepath.Join(root, "archive.sqlite3")
			if _, err := os.Lstat(archive); os.IsNotExist(err) {
				if err := persist.BackupDB(db, archive); err != nil {
					return report, ErrMigrationPrometheus
				}
			}
			fixed, err := openMigrationSnapshot(ctx, archive)
			if err != nil {
				return report, ErrMigrationPrometheus
			}
			defer fixed.close()
			if same, err := migrationPrometheusLogicalEqual(ctx, db, fixed.db); err != nil || !same {
				return report, ErrMigrationPrometheus
			}
			report.Complete, report.ArchiveSHA256, report.ArchivePath = true, fixed.sha, archive
			manifest := migrationPrometheusManifest{Binding: binding, Report: report, KeyID: v.active}
			manifest.Proof = migrationPrometheusManifestProof(v, manifest)
			if manifest.Proof == "" {
				return report, ErrMigrationPrometheus
			}
			manifestBytes, _ := json.Marshal(manifest)
			if err := migrationPrometheusPublishManifest(dir, manifestBytes); err != nil {
				return report, err
			}
			return report, nil
		}
		response, err := migrationPrometheusFetch(ctx, client, task, binding.Nodes)
		if errors.Is(err, telemetry.ErrQueryTooLarge) {
			if err := migrationPrometheusSaveTask(ctx, db, job, migrationPrometheusReceipt{Task: task, State: "split"}); err != nil {
				return report, err
			}
			continue
		}
		if err != nil {
			return report, ErrMigrationPrometheus
		}
		if err := migrationPrometheusImportTask(ctx, db, job, task, response); err != nil {
			return report, err
		}
	}
	return migrationPrometheusProgress(ctx, db, report)
}

// Compare the complete immutable binding, including the sorted fixed node map.
func migrationPrometheusBindingEqual(a, b migrationPrometheusBinding) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return hmac.Equal(aa, bb)
}
