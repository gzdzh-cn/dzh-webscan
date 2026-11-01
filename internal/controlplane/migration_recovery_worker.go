package controlplane

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"webscan/internal/common"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

var errMigrationRecoveryUnsupported = errors.New("node-recovery-read-unsupported")

func migrationRecoveryClient(ctx context.Context, c Config, target migrationRecoveryTarget) (*grpc.ClientConn, agentv1.AgentServiceClient, error) {
	t, err := migrationShadowTLS(c)
	if err != nil {
		return nil, nil, ErrMigrationRecovery
	}
	t.ServerName = target.ServerName
	t.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 {
			return ErrMigrationRecovery
		}
		trust, err := migrationShadowTrust(c, time.Now())
		if err != nil {
			return err
		}
		return trust.Verify(state.PeerCertificates[0], nodepki.Node, target.Node, time.Now())
	}
	conn, err := grpc.NewClient(target.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(t)), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(agentv1.MaxBytes), grpc.MaxCallSendMsgSize(agentv1.MaxBytes)), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, connection *grpc.ClientConn, invoke grpc.UnaryInvoker, options ...grpc.CallOption) error {
		if method != agentv1.AgentService_Capabilities_FullMethodName && method != agentv1.AgentService_RecoveryState_FullMethodName && method != agentv1.AgentService_ReadRecoveryEvents_FullMethodName && method != agentv1.AgentService_ReadMetrics_FullMethodName {
			return ErrMigrationRecovery
		}
		return invoke(ctx, method, req, reply, connection, options...)
	}))
	if err != nil {
		return nil, nil, ErrMigrationRecovery
	}
	client := agentv1.NewAgentServiceClient(conn)
	var p peer.Peer
	capabilities, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{}, grpc.Peer(&p))
	if err != nil || !validCapabilities(Node{ID: target.Node}, capabilities) || capabilities.ConfigurationVersion != target.Version || capabilities.ConfigurationSha256 != target.ConfigSHA {
		conn.Close()
		return nil, nil, ErrMigrationRecovery
	}
	if _, err := migrationShadowVerifyPeer(c, target.migrationShadowTarget, p); err != nil {
		conn.Close()
		return nil, nil, ErrMigrationRecovery
	}
	if !capabilities.RecoveryRead {
		conn.Close()
		return nil, nil, errMigrationRecoveryUnsupported
	}
	return conn, client, nil
}
func migrationRecoveryTargetEqual(a, b migrationRecoveryTarget) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(aa) == string(bb)
}
func (s *Store) migrationRecoverySaved(ctx context.Context, generation, node string) (migrationRecoveryTarget, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return migrationRecoveryTarget{}, ErrMigrationRecovery
	}
	defer tx.Rollback()
	if _, err := migrationRecoveryLock(ctx, tx, generation); err != nil {
		return migrationRecoveryTarget{}, err
	}
	var raw []byte
	var sha string
	var target migrationRecoveryTarget
	if tx.QueryRowContext(ctx, "SELECT target,target_sha256 FROM v3_migration_recovery_nodes WHERE generation=$1 AND node=$2", generation, node).Scan(&raw, &sha) != nil || json.Unmarshal(raw, &target) != nil {
		return target, ErrMigrationRecovery
	}
	encoded, _ := json.Marshal(target)
	if sha != digest(encoded) {
		return target, ErrMigrationRecovery
	}
	current, err := migrationRecoveryTargetTx(ctx, tx, node)
	if err != nil || !migrationRecoveryTargetEqual(current, target) {
		return target, ErrMigrationRecovery
	}
	return target, nil
}
func (s *Store) migrationRecoveryObserve(ctx context.Context, c Config, generation, node string) error {
	target, err := s.migrationRecoverySaved(ctx, generation, node)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	connection, client, err := migrationRecoveryClient(ctx, c, target)
	if err != nil {
		return err
	}
	defer connection.Close()
	state, err := client.RecoveryState(ctx, &agentv1.RecoveryStateRequest{NodeId: node})
	if err != nil || state == nil || state.NodeId != node || state.Epoch > math.MaxInt64 || !releaseDigest(state.SnapshotSha256) || state.ConfigurationVersion != target.Version || state.ConfigurationSha256 != target.ConfigSHA || state.RetainedEvents < 0 || state.AcceptedEvents < 0 || state.PendingEvents < 0 || state.AcceptedEvents+state.PendingEvents != state.RetainedEvents || state.RetainedEvents > 1000000 || state.RetentionSinceUnixMillis < 1 || state.LastDeletedUnixMillis < 0 || state.DeletedEvents < 0 {
		return ErrMigrationRecovery
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrMigrationRecovery
	}
	defer tx.Rollback()
	backupAt, err := migrationRecoveryLock(ctx, tx, generation)
	if err != nil {
		return err
	}
	current, err := migrationRecoveryTargetTx(ctx, tx, node)
	if err != nil || !migrationRecoveryTargetEqual(current, target) {
		return ErrMigrationRecovery
	}
	var previous, cursor string
	var read int64
	if tx.QueryRowContext(ctx, "SELECT snapshot_sha256,cursor,read_events FROM v3_migration_recovery_nodes WHERE generation=$1 AND node=$2 FOR UPDATE", generation, node).Scan(&previous, &cursor, &read) != nil {
		return ErrMigrationRecovery
	}
	if previous != state.SnapshotSha256 || cursor == "" {
		if _, err := tx.ExecContext(ctx, "DELETE FROM v3_migration_recovery_events WHERE generation=$1 AND node=$2 AND NOT published", generation, node); err != nil {
			return ErrMigrationRecovery
		}
		cursor = state.Cursor
		read = 0
	}
	complete := backupAt != nil && backupAt.UnixMilli() >= state.RetentionSinceUnixMillis && (state.LastDeletedUnixMillis == 0 || state.LastDeletedUnixMillis <= backupAt.UnixMilli())
	reason := ""
	if !complete {
		reason = "event-retention-window-unproven"
	}
	evidence, _ := json.Marshal(state)
	if _, err := tx.ExecContext(ctx, "UPDATE v3_migration_recovery_nodes SET state='reading',reason=$3,remote_epoch=$4,snapshot_sha256=$5,cursor=$6,read_events=$7,retained_events=$8,retention_complete=$9,evidence=$10,updated_at=clock_timestamp() WHERE generation=$1 AND node=$2", generation, node, reason, int64(state.Epoch), state.SnapshotSha256, cursor, read, state.RetainedEvents, complete, evidence); err != nil {
		return ErrMigrationRecovery
	}
	if err := tx.Commit(); err != nil {
		return ErrMigrationRecovery
	}
	for page := 0; page < 16; page++ {
		batch, err := client.ReadRecoveryEvents(ctx, &agentv1.ReadRecoveryEventsRequest{NodeId: node, Cursor: cursor, Limit: 100})
		if err != nil {
			return ErrMigrationRecovery
		}
		if batch == nil || batch.NodeId != node || batch.SnapshotSha256 != state.SnapshotSha256 || batch.Epoch != state.Epoch || len(batch.Events) > 100 || batch.ReadEvents != read+int64(len(batch.Events)) || batch.ReadEvents > state.RetainedEvents || batch.Complete != (batch.ReadEvents == state.RetainedEvents) || !batch.Complete && (len(batch.Events) == 0 || batch.NextCursor == "") {
			return ErrMigrationRecovery
		}
		if err := s.migrationRecoveryPage(ctx, generation, target, state, batch, read); err != nil {
			return err
		}
		read = batch.ReadEvents
		cursor = batch.NextCursor
		if batch.Complete {
			return nil
		}
	}
	return nil
}
func (s *Store) migrationRecoveryPage(ctx context.Context, generation string, target migrationRecoveryTarget, state *agentv1.RecoveryStateResponse, batch *agentv1.RecoveryEventsBatch, prior int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrMigrationRecovery
	}
	defer tx.Rollback()
	if _, err = migrationRecoveryLock(ctx, tx, generation); err != nil {
		return err
	}
	current, err := migrationRecoveryTargetTx(ctx, tx, target.Node)
	if err != nil || !migrationRecoveryTargetEqual(target, current) {
		return ErrMigrationRecovery
	}
	var read int64
	var snapshot string
	if tx.QueryRowContext(ctx, "SELECT read_events,snapshot_sha256 FROM v3_migration_recovery_nodes WHERE generation=$1 AND node=$2 FOR UPDATE", generation, target.Node).Scan(&read, &snapshot) != nil || read != prior || snapshot != state.SnapshotSha256 {
		return ErrMigrationRecovery
	}
	for _, event := range batch.Events {
		if event == nil || !eventText(event.Id, 256) || event.CreatedUnixMillis < 1 || event.Accepted && event.AcceptedUnixMillis < 1 || !event.Accepted && event.AcceptedUnixMillis != 0 {
			return ErrMigrationRecovery
		}
		decoded, err := common.Decode(event.Json)
		p, ok := decoded.(common.Map)
		if err != nil || !ok || common.S(p["event_id"]) != event.Id || common.S(p["node_id"]) != target.Node || common.S(p["operation"]) == "" {
			return ErrMigrationRecovery
		}
		canonical, hash, err := canonicalEvent(p)
		if err != nil {
			return ErrMigrationRecovery
		}
		var existing string
		err = tx.QueryRowContext(ctx, "SELECT digest FROM v3_event_keys WHERE node=$1 AND id=$2", target.Node, event.Id).Scan(&existing)
		if err != nil && err != sql.ErrNoRows || err == nil && existing != hash {
			return ErrMigrationRecovery
		}
		notificationState := "unknown"
		if err == nil || category(canonical) == "skip" {
			notificationState = "not_required"
		}
		var accepted any
		if event.Accepted {
			accepted = time.UnixMilli(event.AcceptedUnixMillis).UTC()
		}
		rawSHA := digest(event.Json)
		result, err := tx.ExecContext(ctx, `INSERT INTO v3_migration_recovery_events(generation,node,id,payload,raw_sha256,canonical_sha256,created_at,accepted_at,notification_state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, generation, target.Node, event.Id, common.JSON(canonical), rawSHA, hash, time.UnixMilli(event.CreatedUnixMillis).UTC(), accepted, notificationState)
		if err != nil {
			return ErrMigrationRecovery
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return ErrMigrationRecovery
		}
	}
	status := "reading"
	if batch.Complete {
		status = "complete"
	}
	if _, err := tx.ExecContext(ctx, "UPDATE v3_migration_recovery_nodes SET state=$3,cursor=$4,read_events=$5,updated_at=clock_timestamp() WHERE generation=$1 AND node=$2", generation, target.Node, status, batch.NextCursor, batch.ReadEvents); err != nil {
		return ErrMigrationRecovery
	}
	if err := tx.Commit(); err != nil {
		return ErrMigrationRecovery
	}
	return nil
}
func (s *Store) RunMigrationRecovery(ctx context.Context, c Config, generation string) (MigrationRecoveryReport, error) {
	guard, lockErr := s.DB.BeginTx(ctx, nil)
	if lockErr != nil {
		return MigrationRecoveryReport{}, ErrMigrationRecovery
	}
	defer guard.Rollback()
	var locked bool
	if guard.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1,773376049))", generation).Scan(&locked) != nil || !locked {
		return MigrationRecoveryReport{}, ErrMigrationRecovery
	}
	report, err := s.MigrationRecoveryReport(ctx, generation)
	if err != nil || report.Phase == "held" || report.Phase == "complete" {
		return report, ErrMigrationRecovery
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for _, node := range report.Nodes {
		if node.State == "complete" {
			continue
		}
		err := s.migrationRecoveryObserve(ctx, c, generation, node.Node)
		if err != nil {
			reason := "identity-network-snapshot-or-retention-evidence-unavailable"
			if errors.Is(err, errMigrationRecoveryUnsupported) {
				reason = "node-recovery-read-unsupported"
			}
			_, _ = s.DB.ExecContext(ctx, "UPDATE v3_migration_recovery_nodes SET state='failed',cursor='',reason=$3,updated_at=clock_timestamp() WHERE generation=$1 AND node=$2", generation, node.Node, reason)
		}
	}
	return s.MigrationRecoveryReport(ctx, generation)
}
