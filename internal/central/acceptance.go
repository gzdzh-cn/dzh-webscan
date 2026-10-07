package central

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"

	"webscan/internal/common"
)

func acceptanceKey(node, path string) string {
	return "deployment-acceptance:" + common.Hash(common.JSON([]string{node, path}))
}

func acceptanceSignature(e common.Map) string {
	status := ""
	if common.S(e["operation"]) == "scan" {
		status = common.S(common.M(e["scan"])["status"])
	}
	return common.Hash(common.JSON([]string{common.S(e["operation"]), common.S(e["sha256"]), status}))
}

// Only an authenticated local deployer registers exact expected test events.
// Unregistered content, scan errors and expired fixtures retain normal alerts.
func (s *Store) registerAcceptance(w http.ResponseWriter, r *http.Request, value common.Map) {
	node := common.S(value["node"])
	items := common.A(value["events"])
	if !common.Contains(common.SS(s.Config["active_nodes"]), node) || len(items) == 0 || len(items) > 32 {
		write(w, 400, common.Map{"error": "invalid_acceptance_registration"})
		return
	}
	byPath := common.Map{}
	for _, v := range items {
		e := common.M(v)
		path, hash, op, scan := common.S(e["path"]), common.S(e["sha256"]), common.S(e["operation"]), common.S(common.M(e["scan"])["status"])
		if !common.DeploymentPHPTest(path) || filepath.Clean(path) != path || !filepath.IsAbs(path) || !common.Contains([]string{"create", "modify", "move", "delete", "scan"}, op) || (op != "delete" && (len(hash) != 64 || strings.Trim(hash, "0123456789abcdef") != "")) || (op == "scan" && !common.Contains([]string{"no_match", "matched"}, scan)) {
			write(w, 400, common.Map{"error": "invalid_acceptance_registration"})
			return
		}
		byPath[path] = append(common.SS(byPath[path]), acceptanceSignature(e))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		write(w, 503, common.Map{})
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM kv WHERE key LIKE 'deployment-acceptance:%' AND json_extract(value,'$.expires')<?", common.Now()); err != nil {
		write(w, 503, common.Map{})
		return
	}
	for path, signatures := range byPath {
		data := common.Map{"expires": common.Now() + 900, "signatures": signatures}
		if _, err = tx.ExecContext(r.Context(), "INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", acceptanceKey(node, path), string(common.JSON(data))); err != nil {
			write(w, 503, common.Map{})
			return
		}
	}
	if err = tx.Commit(); err != nil {
		write(w, 503, common.Map{})
		return
	}
	write(w, 200, common.Map{"registered": true})
}

func acceptanceEvent(ctx context.Context, tx *sql.Tx, node string, e common.Map) (bool, error) {
	if !common.DeploymentPHPTest(common.S(e["path"])) {
		return false, nil
	}
	var raw string
	err := tx.QueryRowContext(ctx, "SELECT value FROM kv WHERE key=?", acceptanceKey(node, common.S(e["path"]))).Scan(&raw)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	v, err := common.Decode([]byte(raw))
	if err != nil {
		return false, err
	}
	m := common.M(v)
	return common.F(m["expires"]) > common.Now() && common.Contains(common.SS(m["signatures"]), acceptanceSignature(e)), nil
}
