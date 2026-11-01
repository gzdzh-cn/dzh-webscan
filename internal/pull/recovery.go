package pull

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	agentv1 "webscan/sdk/agent/v1"
)

var ErrRecoveryRead = errors.New("恢复清单已变化、过期或不可读取；请重新获取只读恢复状态")

// This watermark starts at the actual installation, never at epoch zero. A
// trigger captures every deletion in the original writer's own transaction.
const recoverySchema = `CREATE TABLE IF NOT EXISTS pull_recovery_retention(id INTEGER PRIMARY KEY CHECK(id=1),started INTEGER NOT NULL,last_deleted INTEGER NOT NULL DEFAULT 0,deleted INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO pull_recovery_retention(id,started) VALUES(1,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER));
CREATE TRIGGER IF NOT EXISTS pull_recovery_event_deleted AFTER DELETE ON events BEGIN
 UPDATE pull_recovery_retention SET last_deleted=MAX(last_deleted,CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)),deleted=deleted+1 WHERE id=1;
END;`

type recoveryCursor struct {
	Snapshot string `json:"snapshot"`
	After    int64  `json:"after"`
	Read     int64  `json:"read"`
	Expires  int64  `json:"expires"`
	Proof    string `json:"proof"`
}

func (s *Source) recoveryProof(c recoveryCursor) string {
	c.Proof = ""
	raw, _ := json.Marshal(c)
	h := hmac.New(sha256.New, s.recoveryKey[:])
	h.Write([]byte("webscan-node-recovery/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Source) recoveryEncode(c recoveryCursor) string {
	c.Proof = s.recoveryProof(c)
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}
func (s *Source) recoveryDecode(raw string) (recoveryCursor, error) {
	var c recoveryCursor
	if len(raw) > 2048 {
		return c, ErrRecoveryRead
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(data, &c) != nil || c.After < 0 || c.Read < 0 || c.Expires <= time.Now().Unix() || c.Expires > time.Now().Add(11*time.Minute).Unix() || len(c.Snapshot) != 64 || !hmac.Equal([]byte(c.Proof), []byte(s.recoveryProof(c))) {
		return c, ErrRecoveryRead
	}
	return c, nil
}

// recoveryInventory pins one SQLite read snapshot. It does not acquire the
// writer lock, create receipts, prune failures or advance the collector epoch.
func (s *Source) recoveryInventory(ctx context.Context) (*sql.Tx, *agentv1.RecoveryStateResponse, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, nil, ErrRecoveryRead
	}
	fail := func() (*sql.Tx, *agentv1.RecoveryStateResponse, error) {
		tx.Rollback()
		return nil, nil, ErrRecoveryRead
	}
	state := &agentv1.RecoveryStateResponse{NodeId: s.NodeID, ConfigurationVersion: s.configuration.Version, ConfigurationSha256: s.configuration.SHA256, RetentionReason: "backup_window_not_compared"}
	if tx.QueryRowContext(ctx, "SELECT epoch FROM pull_state WHERE id=1").Scan(&state.Epoch) != nil || state.Epoch > math.MaxInt64 {
		return fail()
	}
	if tx.QueryRowContext(ctx, "SELECT started,last_deleted,deleted FROM pull_recovery_retention WHERE id=1").Scan(&state.RetentionSinceUnixMillis, &state.LastDeletedUnixMillis, &state.DeletedEvents) != nil || state.RetentionSinceUnixMillis < 1 {
		return fail()
	}
	if tx.QueryRowContext(ctx, "SELECT COALESCE(min(sampled),0),COALESCE(max(sampled),0) FROM pull_metrics").Scan(&state.EarliestMetricsUnixMillis, &state.LatestMetricsUnixMillis) != nil {
		return fail()
	}
	rows, err := tx.QueryContext(ctx, "SELECT rowid,id,payload,created,accepted FROM events ORDER BY rowid")
	if err != nil {
		return fail()
	}
	hash := sha256.New()
	fmt.Fprintf(hash, "node=%s;epoch=%d;configuration=%d/%s;retention=%d/%d/%d;", s.NodeID, state.Epoch, s.configuration.Version, s.configuration.SHA256, state.RetentionSinceUnixMillis, state.LastDeletedUnixMillis, state.DeletedEvents)
	bytes := 0
	for rows.Next() {
		var rowid int64
		var id string
		var payload []byte
		var created float64
		var accepted sql.NullFloat64
		if rows.Scan(&rowid, &id, &payload, &created, &accepted) != nil || rowid < 1 || id == "" || len(id) > 512 || len(payload) > MaxBytes-4096 || !json.Valid(payload) || math.IsNaN(created) || math.IsInf(created, 0) || created <= 0 || created > float64(math.MaxInt64)/1000 || accepted.Valid && (math.IsNaN(accepted.Float64) || math.IsInf(accepted.Float64, 0) || accepted.Float64 <= 0 || accepted.Float64 > float64(math.MaxInt64)/1000) {
			rows.Close()
			return fail()
		}
		state.RetainedEvents++
		if state.RetainedEvents > 1000000 {
			rows.Close()
			return fail()
		}
		bytes += len(payload)
		if bytes > 512<<20 {
			rows.Close()
			return fail()
		}
		at := int64(created * 1000)
		if state.EarliestCreatedUnixMillis == 0 || at < state.EarliestCreatedUnixMillis {
			state.EarliestCreatedUnixMillis = at
		}
		state.LatestCreatedUnixMillis = max(state.LatestCreatedUnixMillis, at)
		if accepted.Valid {
			state.AcceptedEvents++
		} else {
			state.PendingEvents++
		}
		raw, _ := json.Marshal([]any{rowid, id, string(payload), strconv.FormatFloat(created, 'g', -1, 64), accepted.Valid, strconv.FormatFloat(accepted.Float64, 'g', -1, 64)})
		fmt.Fprintf(hash, "%d:", len(raw))
		hash.Write(raw)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fail()
	}
	state.SnapshotSha256 = hex.EncodeToString(hash.Sum(nil))
	return tx, state, nil
}
func (s *Source) RecoveryState(ctx context.Context, node string) (*agentv1.RecoveryStateResponse, error) {
	if node != s.NodeID {
		return nil, ErrRecoveryRead
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, state, err := s.recoveryInventory(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	state.Cursor = s.recoveryEncode(recoveryCursor{Snapshot: state.SnapshotSha256, Expires: time.Now().Add(10 * time.Minute).Unix()})
	return state, nil
}
func (s *Source) ReadRecoveryEvents(ctx context.Context, node, raw string, limit int) (*agentv1.RecoveryEventsBatch, error) {
	if node != s.NodeID || limit < 1 || limit > MaxEvents {
		return nil, ErrRecoveryRead
	}
	cursor, err := s.recoveryDecode(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, state, err := s.recoveryInventory(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if cursor.Snapshot != state.SnapshotSha256 || cursor.Read > state.RetainedEvents {
		return nil, ErrRecoveryRead
	}
	batch := &agentv1.RecoveryEventsBatch{NodeId: s.NodeID, SnapshotSha256: state.SnapshotSha256, Epoch: state.Epoch, ReadEvents: cursor.Read}
	rows, err := tx.QueryContext(ctx, "SELECT rowid,id,payload,created,accepted FROM events WHERE rowid>? ORDER BY rowid LIMIT ?", cursor.After, limit)
	if err != nil {
		return nil, ErrRecoveryRead
	}
	defer rows.Close()
	size := 0
	after := cursor.After
	for rows.Next() {
		var rowid int64
		event := new(agentv1.RecoveryEvent)
		var created float64
		var accepted sql.NullFloat64
		if rows.Scan(&rowid, &event.Id, &event.Json, &created, &accepted) != nil {
			return nil, ErrRecoveryRead
		}
		n := len(event.Json) + len(event.Id) + 64
		if size+n > MaxBytes-4096 {
			break
		}
		size += n
		after = rowid
		event.CreatedUnixMillis = int64(created * 1000)
		event.Accepted = accepted.Valid
		if accepted.Valid {
			event.AcceptedUnixMillis = int64(accepted.Float64 * 1000)
		}
		batch.Events = append(batch.Events, event)
		batch.ReadEvents++
	}
	if rows.Err() != nil || len(batch.Events) == 0 && batch.ReadEvents < state.RetainedEvents {
		return nil, ErrRecoveryRead
	}
	batch.Complete = batch.ReadEvents == state.RetainedEvents
	if !batch.Complete {
		batch.NextCursor = s.recoveryEncode(recoveryCursor{Snapshot: cursor.Snapshot, After: after, Read: batch.ReadEvents, Expires: cursor.Expires})
	}
	return batch, nil
}
