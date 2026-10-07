package central

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"webscan/internal/common"
)

func (s *Store) deliveryDone(ctx context.Context, node, id, target string) (bool, error) {
	var done sql.NullFloat64
	var result sql.NullString
	err := s.DB.QueryRowContext(ctx, "SELECT done,result FROM tasks WHERE node=? AND event_id=? AND target=?", node, id, target).Scan(&done, &result)
	if err == sql.ErrNoRows {
		return false, nil
	}
	want := "http=200,business=0"
	if target == "loki" {
		want = "http=204"
	}
	return done.Valid && result.String == want, err
}

// Only the main server's authenticated deployment tool can enqueue these jobs.
// They share the normal durable queue, retry and Feishu rate limiter.
func (s *Store) deploymentRequest(w http.ResponseWriter, r *http.Request, path string, value common.Map) {
	if path == "/deployment-acceptance" {
		s.registerAcceptance(w, r, value)
		return
	}
	if !common.B(common.M(s.Config["feishu"])["enabled"]) {
		write(w, 409, common.Map{"error": "deployment_feishu_disabled"})
		return
	}
	id := common.S(value["id"])
	if !eventID.MatchString(id) || !strings.HasPrefix(id, "deployment:") {
		write(w, 400, common.Map{"error": "invalid_deployment_notice"})
		return
	}
	ctx := r.Context()
	if path == "/deployment-notices" {
		message := common.S(value["message"])
		if len(message) == 0 || len(message) > 8192 {
			write(w, 400, common.Map{"error": "invalid_deployment_notice"})
			return
		}
		if err := s.Notice(ctx, id, message); err != nil {
			write(w, 503, common.Map{"error": "persistence_unavailable"})
			return
		}
		done, err := s.deliveryDone(ctx, "central", id, "feishu")
		if err != nil {
			write(w, 503, common.Map{})
			return
		}
		write(w, 200, common.Map{"done": done})
		return
	}
	node, fixture, hash := common.S(value["node"]), common.S(value["path"]), common.S(value["sha256"])
	if !common.Contains(common.SS(s.Config["active_nodes"]), node) || !common.DeploymentPHPTest(fixture) || len(hash) != 64 || strings.Trim(hash, "0123456789abcdef") != "" {
		write(w, 400, common.Map{"error": "invalid_deployment_test"})
		return
	}
	key := deploymentTestKey(node, fixture)
	err := s.registerDeploymentTest(ctx, key, common.Map{"id": id, "node": node, "path": fixture, "sha256": hash})
	if err != nil {
		if errors.Is(err, errEvent) {
			write(w, 409, common.Map{"error": "conflicting_deployment_test"})
		} else {
			write(w, 503, common.Map{})
		}
		return
	}
	var raw string
	if err = s.DB.QueryRowContext(ctx, "SELECT value FROM kv WHERE key=?", key).Scan(&raw); err != nil {
		write(w, 503, common.Map{})
		return
	}
	v, _ := common.Decode([]byte(raw))
	event := common.S(common.M(v)["event_id"])
	feishu, err := s.deliveryDone(ctx, node, event, "feishu")
	if err != nil {
		write(w, 503, common.Map{})
		return
	}
	loki, err := s.deliveryDone(ctx, node, event, "loki")
	if err != nil {
		write(w, 503, common.Map{})
		return
	}
	write(w, 200, common.Map{"event_id": event, "done": event != "" && feishu && loki})
}

func deploymentTestKey(node, path string) string {
	return "deployment-test:" + common.Hash(common.JSON([]string{node, path}))
}

func (s *Store) registerDeploymentTest(ctx context.Context, key string, test common.Map) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw string
	err := s.DB.QueryRowContext(ctx, "SELECT value FROM kv WHERE key=?", key).Scan(&raw)
	if err == nil {
		v, err := common.Decode([]byte(raw))
		if err != nil {
			return err
		}
		old := common.M(v)
		for _, field := range []string{"id", "node", "path", "sha256"} {
			if common.S(old[field]) != common.S(test[field]) {
				return errEvent
			}
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	_, err = s.DB.ExecContext(ctx, "INSERT INTO kv(key,value) VALUES(?,?)", key, string(common.JSON(test)))
	return err
}

// Select the first real modify event matching a registered fixture and content.
// Registration and its event pointer survive process restarts. The canonical
// event and its legacy digest are left unchanged.
func deploymentModify(ctx context.Context, tx *sql.Tx, node string, e common.Map) (bool, error) {
	path := common.S(e["path"])
	if !common.DeploymentPHPTest(path) || common.S(e["operation"]) != "modify" {
		return false, nil
	}
	key := deploymentTestKey(node, path)
	var raw string
	err := tx.QueryRowContext(ctx, "SELECT value FROM kv WHERE key=?", key).Scan(&raw)
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
	test := common.M(v)
	if common.S(test["sha256"]) != common.S(e["sha256"]) || common.S(test["event_id"]) != "" {
		return false, nil
	}
	test["event_id"] = e["event_id"]
	_, err = tx.ExecContext(ctx, "UPDATE kv SET value=? WHERE key=?", string(common.JSON(test)), key)
	return true, err
}
