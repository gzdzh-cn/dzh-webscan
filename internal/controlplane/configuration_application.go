package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"webscan/internal/common"
)

var errConfigurationApplication = errors.New("配置应用任务或授权已变化，请重新读取；未跳过运行验收")
var errConfigurationApplicationBusy = errors.New("存在未完成配置应用，请先继续、取消或回退原任务")

var configurationApplicationForward = []string{"environment", "nodes", "bootstrap", "settings", "verify", "finalize"}
var configurationApplicationRollback = []string{"restore-settings", "restore-bootstrap", "restore-nodes", "verify-rollback"}

// This projection is deliberately incapable of authorizing work. It contains
// no configuration digests, addresses, vault IDs or runtime checkpoint secrets.
type configurationApplicationJob struct {
	ID               string     `json:"id"`
	Stage            string     `json:"stage"`
	Username         string     `json:"username"`
	Controller       string     `json:"controller"`
	Generation       int64      `json:"generation,string"`
	Status           string     `json:"status"`
	Direction        string     `json:"direction"`
	Phase            string     `json:"phase"`
	RecoveryRequired bool       `json:"recovery_required"`
	ErrorCode        string     `json:"error_code"`
	LogCursor        int64      `json:"log_cursor,string"`
	RecoveryHold     bool       `json:"recovery_hold"`
	Created          time.Time  `json:"created_at"`
	Updated          time.Time  `json:"updated_at"`
	Finished         *time.Time `json:"finished_at"`
}

type privateConfigurationApplication struct {
	configurationApplicationJob
	member, sourceProof, planProof, stateProof string
	accountRevision, controllerRevision        int64
	step, rollbackStep                         int
	owner                                      sql.NullString
	epoch                                      int64
	leaseUntil                                 sql.NullTime
}

func (privateConfigurationApplication) String() string { return "[private configuration application]" }
func (privateConfigurationApplication) GoString() string {
	return "[private configuration application]"
}
func (privateConfigurationApplication) MarshalJSON() ([]byte, error) {
	return nil, errConfigurationApplication
}

func (j privateConfigurationApplication) phase() string {
	if j.Direction == "rollback" {
		if j.rollbackStep < len(configurationApplicationRollback) {
			return configurationApplicationRollback[j.rollbackStep]
		}
	} else if j.step < len(configurationApplicationForward) {
		return configurationApplicationForward[j.step]
	}
	return "complete"
}
func (j privateConfigurationApplication) public() configurationApplicationJob {
	p := j.configurationApplicationJob
	p.Phase = j.phase()
	return p
}

func configurationApplicationAvailableTx(ctx context.Context, tx *sql.Tx) error {
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_configuration_applications WHERE status IN ('queued','running') OR recovery_required)`).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return errConfigurationApplicationBusy
	}
	return nil
}

// Both the immutable intent and each mutable checkpoint are authenticated. A
// forged SQL status, step, controller, epoch or recovery flag is not executable.
// lease_until is a scheduling deadline, not authority; current ownership also
// requires an exact authenticated epoch. recovery_hold is a fail-closed disaster
// recovery revocation and is checked independently before every execution.
func applicationProof(v *Vault, key, domain string, parts ...any) (string, error) {
	if v == nil || len(v.receiptKeys[key]) == 0 || domain != "plan" && domain != "state" {
		return "", errConfigurationApplication
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/configuration-application/" + domain + "/v1\x00"))
	h.Write(common.JSON(parts))
	return key + ":" + hex.EncodeToString(h.Sum(nil)), nil
}
func applicationPlanProof(v *Vault, key string, j privateConfigurationApplication) (string, error) {
	return applicationProof(v, key, "plan", j.ID, j.Stage, j.member, j.Username, j.accountRevision, j.Generation, j.sourceProof)
}
func applicationStateProof(v *Vault, key string, j privateConfigurationApplication) (string, error) {
	return applicationProof(v, key, "state", j.planProof, j.Controller, j.controllerRevision, j.Status, j.Direction, j.step, j.rollbackStep, j.RecoveryRequired, j.ErrorCode, j.LogCursor, j.owner.String, j.owner.Valid, j.epoch)
}
func validateApplicationProof(v *Vault, j privateConfigurationApplication) error {
	if !validArchiveSource(j.ID) || !validArchiveSource(j.Stage) || !identifier.MatchString(j.member) || !identifier.MatchString(j.Username) || !identifier.MatchString(j.Controller) || j.Generation < 1 || j.accountRevision < 1 || j.controllerRevision < 1 || j.step < 0 || j.step > len(configurationApplicationForward) || j.rollbackStep < 0 || j.rollbackStep > len(configurationApplicationRollback) || j.epoch < 0 {
		return errConfigurationApplication
	}
	k, _, ok := strings.Cut(j.planProof, ":")
	p, e := applicationPlanProof(v, k, j)
	if !ok || e != nil || !hmac.Equal([]byte(p), []byte(j.planProof)) {
		return errConfigurationApplication
	}
	k, _, ok = strings.Cut(j.stateProof, ":")
	p, e = applicationStateProof(v, k, j)
	if !ok || e != nil || !hmac.Equal([]byte(p), []byte(j.stateProof)) {
		return errConfigurationApplication
	}
	return nil
}

const configurationApplicationColumns = `id,stage,member,username,account_revision,generation,source_proof,plan_proof,controller,controller_revision,status,direction,step,rollback_step,recovery_required,error_code,lease_owner,lease_epoch,lease_until,log_cursor,state_proof,recovery_hold,created_at,updated_at,finished_at`

func scanApplication(row interface{ Scan(...any) error }) (j privateConfigurationApplication, err error) {
	err = row.Scan(&j.ID, &j.Stage, &j.member, &j.Username, &j.accountRevision, &j.Generation, &j.sourceProof, &j.planProof, &j.Controller, &j.controllerRevision, &j.Status, &j.Direction, &j.step, &j.rollbackStep, &j.RecoveryRequired, &j.ErrorCode, &j.owner, &j.epoch, &j.leaseUntil, &j.LogCursor, &j.stateProof, &j.RecoveryHold, &j.Created, &j.Updated, &j.Finished)
	return
}

func readApplicationTx(ctx context.Context, tx *sql.Tx, v *Vault, id string, update bool) (privateConfigurationApplication, error) {
	var j privateConfigurationApplication
	if !validArchiveSource(id) {
		return j, errConfigurationApplication
	}
	lock := " FOR SHARE"
	if update {
		lock = " FOR UPDATE"
	}
	j, e := scanApplication(tx.QueryRowContext(ctx, `SELECT `+configurationApplicationColumns+` FROM v3_configuration_applications WHERE id=$1`+lock, id))
	if e == nil {
		e = validateApplicationProof(v, j)
	}
	return j, e
}

// A state update and its bounded progress entry share one short transaction.
// Raw remote errors and runtime receipts never enter the progress channel.
func writeApplicationTx(ctx context.Context, tx *sql.Tx, v *Vault, j *privateConfigurationApplication, code string) error {
	switch code {
	case "queued", "claimed", "takeover", "phase-complete", "recovery-armed", "resumed", "rollback-requested", "cancelled", "succeeded", "rolled-back", "environment-failed", "deployment-failed", "bootstrap-failed", "settings-failed", "verification-failed", "state-conflict", "runtime-unavailable", "interrupted":
	default:
		return errConfigurationApplication
	}
	if err := advanceConfigurationOperationTx(ctx, tx); err != nil {
		return err
	}
	j.LogCursor++
	proof, e := applicationStateProof(v, v.active, *j)
	if e != nil {
		return e
	}
	j.stateProof = proof
	e = tx.QueryRowContext(ctx, `UPDATE v3_configuration_applications SET controller=$2,controller_revision=$3,status=$4,direction=$5,step=$6,rollback_step=$7,recovery_required=$8,error_code=$9,lease_owner=$10,lease_epoch=$11,lease_until=$12,log_cursor=$13,state_proof=$14,recovery_hold=$15,updated_at=clock_timestamp(),finished_at=CASE WHEN $4 IN ('succeeded','rolled_back','cancelled') THEN clock_timestamp() ELSE NULL END WHERE id=$1 RETURNING updated_at,finished_at`, j.ID, j.Controller, j.controllerRevision, j.Status, j.Direction, j.step, j.rollbackStep, j.RecoveryRequired, j.ErrorCode, j.owner, j.epoch, j.leaseUntil, j.LogCursor, j.stateProof, j.RecoveryHold).Scan(&j.Updated, &j.Finished)
	if e != nil {
		return e
	}
	phase := j.phase()
	if code == "phase-complete" {
		previous := *j
		if j.Direction == "forward" {
			previous.step--
		} else {
			previous.rollbackStep--
		}
		phase = previous.phase()
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO v3_configuration_application_logs(job,cursor,direction,phase,code) VALUES($1,$2,$3,$4,$5)`, j.ID, j.LogCursor, j.Direction, phase, code)
	return e
}

func applicationActorTx(ctx context.Context, tx *sql.Tx, j privateConfigurationApplication) error {
	rev, e := configurationRestoreAccount(ctx, tx, j.Controller)
	if e != nil || rev != j.controllerRevision || j.Direction == "forward" && (j.Controller != j.Username || rev != j.accountRevision) {
		return errConfigurationApplication
	}
	return nil
}

// Reauthenticate immutable source and rollback archives after verifying the
// current controller. Historical signatures are evidence, not permission for
// the former account. Runtime adapters additionally validate live state and
// their phase receipts; an archive cannot prove an effect has succeeded.
func applicationSourceTx(ctx context.Context, tx *sql.Tx, v *Vault, j privateConfigurationApplication) error {
	_, _, err := applicationSavedEvidenceTx(ctx, tx, v, j)
	return err
}

// Caller has authenticated the journal plan and current actor under the
// relation gate. A replacement administrator can authenticate the historical
// baseline without reauthorizing the former account. All candidate/commit
// signatures and both rollback pins remain required in either direction.
func applicationSavedEvidenceTx(ctx context.Context, tx *sql.Tx, v *Vault, j privateConfigurationApplication) (configurationSavedReceipt, configurationDocument, error) {
	out, doc, err := authenticateSavedConfigurationTx(ctx, tx, v, Config{}, j.Username, j.Stage, j.accountRevision, false)
	if err != nil || out.Generation != j.Generation {
		return out, doc, errConfigurationApplication
	}
	var proof string
	var archives, deployments []byte
	if err = tx.QueryRowContext(ctx, `SELECT proof,archives,deployments FROM v3_configuration_restore_commits WHERE stage=$1`, j.Stage).Scan(&proof, &archives, &deployments); err != nil || !hmac.Equal([]byte(proof), []byte(j.sourceProof)) {
		return out, doc, errConfigurationApplication
	}
	r, _, err := loadConfigurationRevisionTx(ctx, tx, v, j.Stage)
	if err != nil {
		return out, doc, err
	}
	options, err := readConfigurationStageOptions(ctx, tx, j.Stage)
	if err == nil {
		err = validateSavedConfigurationArchivesTx(ctx, tx, v, r, options, archives, deployments)
	}
	return out, doc, err
}

// Enqueue from a genuinely committed saved restore, never a caller's diagnostic
// report or arbitrary configuration. The real environment phase runs after the
// durable task exists so failures remain visible without arming recovery.
func (s *Store) queueConfigurationApplication(ctx context.Context, v *Vault, c Config, user, key, stage string, generation int64) (json.RawMessage, error) {
	if !validArchiveSource(stage) || generation < 1 || c.Validate() != nil {
		return nil, errConfigurationApplication
	}
	op, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.guardedMutationOptions(op, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, user, key, "configuration-application-queue", stage, []any{stage, generation}, func(tx *sql.Tx) error {
		if e := lockConfigurationRestoreRelationsTx(op, tx); e != nil {
			return e
		}
		_, _, e := loadSavedConfigurationTx(op, tx, v, c, user, stage, false)
		return e
	}, func(tx *sql.Tx) (any, error) {
		if e := monitoringApplicationsAvailableTx(op, tx); e != nil {
			return nil, e
		}
		if e := configurationApplicationAvailableTx(op, tx); e != nil {
			return nil, e
		}
		r, _, e := loadSavedConfigurationTx(op, tx, v, c, user, stage, true)
		if e != nil {
			return nil, e
		}
		if r.Generation != generation {
			return nil, ErrConflict
		}
		var existing string
		e = tx.QueryRowContext(op, `SELECT id FROM v3_configuration_applications WHERE stage=$1`, stage).Scan(&existing)
		if e == nil {
			j, e := readApplicationTx(op, tx, v, existing, false)
			return j.public(), e
		}
		if e != sql.ErrNoRows {
			return nil, e
		}
		j := privateConfigurationApplication{configurationApplicationJob: configurationApplicationJob{ID: token(), Stage: stage, Username: user, Controller: user, Generation: generation, Status: "queued", Direction: "forward"}, member: c.Central.Instance}
		j.accountRevision, e = configurationRestoreAccount(op, tx, user)
		if e != nil {
			return nil, e
		}
		j.controllerRevision = j.accountRevision
		if e = tx.QueryRowContext(op, `SELECT proof FROM v3_configuration_restore_commits WHERE stage=$1`, stage).Scan(&j.sourceProof); e != nil {
			return nil, e
		}
		j.planProof, e = applicationPlanProof(v, v.active, j)
		if e != nil {
			return nil, e
		}
		j.stateProof, e = applicationStateProof(v, v.active, j)
		if e != nil {
			return nil, e
		}
		e = tx.QueryRowContext(op, `INSERT INTO v3_configuration_applications(id,stage,member,username,account_revision,generation,source_proof,plan_proof,controller,controller_revision,status,direction,state_proof) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$4,$5,'queued','forward',$9) RETURNING created_at`, j.ID, j.Stage, j.member, j.Username, j.accountRevision, j.Generation, j.sourceProof, j.planProof, j.stateProof).Scan(&j.Created)
		if e != nil {
			return nil, e
		}
		if e = writeApplicationTx(op, tx, v, &j, "queued"); e != nil {
			return nil, e
		}
		return j.public(), nil
	})
}

func (s *Store) configurationApplication(ctx context.Context, v *Vault, user, id string) (configurationApplicationJob, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return configurationApplicationJob{}, e
	}
	defer tx.Rollback()
	if e = configurationBackupAdmin(ctx, tx, user); e != nil {
		return configurationApplicationJob{}, e
	}
	j, e := readApplicationTx(ctx, tx, v, id, false)
	if e != nil {
		return configurationApplicationJob{}, e
	}
	return j.public(), tx.Commit()
}

func (s *Store) claimConfigurationApplication(ctx context.Context, v *Vault, member, owner string) (privateConfigurationApplication, error) {
	var empty privateConfigurationApplication
	if !identifier.MatchString(member) || !identifier.MatchString(owner) {
		return empty, errConfigurationApplication
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	if held, e := migrationHeld(ctx, tx); e != nil {
		return empty, e
	} else if held {
		return empty, ErrMigrationPending
	}
	if e = lockConfigurationRestoreRelationsTx(ctx, tx); e != nil {
		return empty, e
	}
	j, e := scanApplication(tx.QueryRowContext(ctx, `SELECT `+configurationApplicationColumns+` FROM v3_configuration_applications WHERE member=$1 AND NOT recovery_hold AND (status='queued' OR (status='running' AND lease_until<=clock_timestamp())) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, member))
	if e != nil {
		return empty, e
	}
	if e = validateApplicationProof(v, j); e != nil {
		return empty, e
	}
	if e = applicationActorTx(ctx, tx, j); e != nil {
		return empty, e
	}
	if e = applicationSourceTx(ctx, tx, v, j); e != nil {
		return empty, e
	}
	code := "claimed"
	if j.Status == "running" {
		code = "takeover"
	}
	j.Status = "running"
	j.owner = sql.NullString{String: owner, Valid: true}
	j.epoch++
	if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()+interval '45 seconds'`).Scan(&j.leaseUntil); e != nil {
		return empty, e
	}
	if e = writeApplicationTx(ctx, tx, v, &j, code); e != nil {
		return empty, e
	}
	return j, tx.Commit()
}

func lockedApplication(ctx context.Context, tx *sql.Tx, v *Vault, expected privateConfigurationApplication) (privateConfigurationApplication, error) {
	if e := lockConfigurationRestoreRelationsTx(ctx, tx); e != nil {
		return privateConfigurationApplication{}, e
	}
	j, e := readApplicationTx(ctx, tx, v, expected.ID, true)
	if e != nil {
		return j, e
	}
	var alive bool
	if e = tx.QueryRowContext(ctx, `SELECT $1::timestamptz>clock_timestamp()`, j.leaseUntil).Scan(&alive); e != nil {
		return j, e
	}
	if j.RecoveryHold || j.Status != "running" || !alive || !j.owner.Valid || j.owner.String != expected.owner.String || j.epoch != expected.epoch || j.Direction != expected.Direction || j.step != expected.step || j.rollbackStep != expected.rollbackStep || !hmac.Equal([]byte(j.planProof), []byte(expected.planProof)) {
		return j, ErrLeaseLost
	}
	if e = applicationActorTx(ctx, tx, j); e != nil {
		return j, e
	}
	return j, nil
}

func (s *Store) renewConfigurationApplication(ctx context.Context, v *Vault, expected privateConfigurationApplication) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	j, e := lockedApplication(ctx, tx, v, expected)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()+interval '45 seconds' WHERE id=$1`, j.ID)
	if e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Store) armConfigurationApplication(ctx context.Context, v *Vault, expected privateConfigurationApplication) (privateConfigurationApplication, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return expected, e
	}
	defer tx.Rollback()
	j, e := lockedApplication(ctx, tx, v, expected)
	if e != nil {
		return expected, e
	}
	if j.Direction != "forward" || j.step == 0 {
		return expected, errConfigurationApplication
	}
	if !j.RecoveryRequired {
		j.RecoveryRequired = true
		if e = writeApplicationTx(ctx, tx, v, &j, "recovery-armed"); e != nil {
			return expected, e
		}
	}
	return j, tx.Commit()
}

// Only a trusted runtime's exact phase receipt may advance the journal. The
// real adapters must prove remote fencing, fresh runtime evidence and commit
// semantics. There is no HTTP or CLI endpoint accepting these checkpoints.
type configurationApplicationCheckpoint struct {
	Job, Plan, Phase, State string
	Epoch                   int64
}

func (p configurationApplicationCheckpoint) matches(j privateConfigurationApplication) bool {
	return p.Job == j.ID && p.Plan == j.planProof && p.Phase == j.phase() && p.Epoch == j.epoch && p.State == "complete"
}

func (s *Store) checkpointConfigurationApplication(ctx context.Context, v *Vault, expected privateConfigurationApplication, p configurationApplicationCheckpoint) (privateConfigurationApplication, error) {
	if !p.matches(expected) {
		return expected, errConfigurationApplication
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return expected, e
	}
	defer tx.Rollback()
	j, e := lockedApplication(ctx, tx, v, expected)
	if e != nil {
		return expected, e
	}
	next, e := s.checkpointConfigurationApplicationTx(ctx, tx, v, j)
	if e != nil {
		return expected, e
	}
	return next, tx.Commit()
}

// The final verifier calls this under the same transaction as the actual
// runtime checks. Phase proof validation and live-parent locking belong to the
// caller; there is no API accepting these internal checkpoints.
func (s *Store) checkpointConfigurationApplicationTx(ctx context.Context, tx *sql.Tx, v *Vault, j privateConfigurationApplication) (privateConfigurationApplication, error) {
	var e error
	code := "phase-complete"
	if e = applicationSourceTx(ctx, tx, v, j); e != nil {
		return j, e
	}
	if j.phase() == "nodes" || j.phase() == "restore-nodes" {
		if e = s.verifyApplicationNodeOutcomesTx(ctx, tx, v, j); e != nil {
			return j, e
		}
	}
	if j.Direction == "forward" {
		if j.step > 0 && !j.RecoveryRequired {
			return j, errConfigurationApplication
		}
		j.step++
		if j.step == len(configurationApplicationForward) {
			j.Status = "succeeded"
			code = "succeeded"
		}
	} else {
		j.rollbackStep++
		if j.rollbackStep == len(configurationApplicationRollback) {
			j.Status = "rolled_back"
			code = "rolled-back"
		}
	}
	if j.Status == "running" {
		j.Status = "queued"
	}
	if j.Status != "queued" {
		j.RecoveryRequired = false
		if e = releaseApplicationNodeConfigurationsTx(ctx, tx, v, j); e != nil {
			return j, e
		}
	}
	j.owner = sql.NullString{}
	j.leaseUntil = sql.NullTime{}
	if e = writeApplicationTx(ctx, tx, v, &j, code); e != nil {
		return j, e
	}
	return j, nil
}

func (s *Store) failConfigurationApplication(ctx context.Context, v *Vault, expected privateConfigurationApplication, code string) error {
	switch code {
	case "environment-failed", "deployment-failed", "bootstrap-failed", "settings-failed", "verification-failed", "state-conflict", "runtime-unavailable", "interrupted":
	default:
		return errConfigurationApplication
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	j, e := lockedApplication(ctx, tx, v, expected)
	if e != nil {
		return e
	}
	j.Status = "failed"
	j.ErrorCode = code
	j.owner = sql.NullString{}
	j.leaseUntil = sql.NullTime{}
	if e = writeApplicationTx(ctx, tx, v, &j, code); e != nil {
		return e
	}
	return tx.Commit()
}

// A current administrator may cancel harmless work or request rollback; only
// the original, still-current account may resume forward application. Repeated
// user actions are idempotent, but never bypass current administrator checks.
func (s *Store) controlConfigurationApplication(ctx context.Context, v *Vault, user, key, id, action string) (json.RawMessage, error) {
	return s.controlConfigurationApplicationRequest(ctx, v, user, key, id, action, nil, "")
}

// Public controls bind the exact journal cursor the administrator confirmed.
// Legacy local callers retain their original request digest and replay format.
func (s *Store) controlConfigurationApplicationRequest(ctx context.Context, v *Vault, user, key, id, action string, expected *int64, member string) (json.RawMessage, error) {
	if action != "resume" && action != "rollback" && action != "cancel" || !validArchiveSource(id) {
		return nil, errConfigurationApplication
	}
	input := []any{id, action}
	if expected != nil {
		if *expected < 1 || !identifier.MatchString(member) {
			return nil, errApplicationCursor
		}
		input = append(input, *expected, member)
	}
	conflict := func() error {
		if expected != nil {
			return ErrConflict
		}
		return errConfigurationApplication
	}
	return s.guardedMutation(ctx, user, key, "configuration-application-"+action, id, input, func(tx *sql.Tx) error {
		if e := lockConfigurationRestoreRelationsTx(ctx, tx); e != nil {
			return e
		}
		return configurationBackupAdmin(ctx, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		j, e := readApplicationTx(ctx, tx, v, id, true)
		if e != nil {
			return nil, e
		}
		if expected != nil && (j.LogCursor != *expected || j.member != member) {
			return nil, ErrConflict
		}
		var busy bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_configuration_applications WHERE id<>$1 AND (status IN ('queued','running') OR recovery_required))`, j.ID).Scan(&busy); e != nil || busy {
			return nil, errConfigurationApplicationBusy
		}
		var live bool
		if e = tx.QueryRowContext(ctx, `SELECT COALESCE($1::timestamptz>clock_timestamp(),false)`, j.leaseUntil).Scan(&live); e != nil {
			return nil, e
		}
		if j.Finished != nil || j.Status == "running" && live && !j.RecoveryHold {
			return nil, conflict()
		}
		rev, e := configurationRestoreAccount(ctx, tx, user)
		if e != nil {
			return nil, e
		}
		code := "resumed"
		switch action {
		case "cancel":
			if j.RecoveryRequired {
				return nil, conflict()
			}
			j.Status = "cancelled"
			code = "cancelled"
		case "rollback":
			if !j.RecoveryRequired {
				return nil, conflict()
			}
			if j.Direction != "rollback" {
				j.rollbackStep = 0
			}
			j.Direction = "rollback"
			j.Status = "queued"
			code = "rollback-requested"
		case "resume":
			if expected != nil && j.Status == "queued" && !j.RecoveryHold {
				return nil, ErrConflict
			}
			if j.Direction == "forward" && (user != j.Username || rev != j.accountRevision) {
				if expected != nil {
					return nil, errApplicationActor
				}
				return nil, errConfigurationApplication
			}
			j.Status = "queued"
		}
		j.Controller = user
		j.controllerRevision = rev
		j.RecoveryHold = false
		j.ErrorCode = ""
		j.owner = sql.NullString{}
		j.leaseUntil = sql.NullTime{}
		j.epoch++
		if e = writeApplicationTx(ctx, tx, v, &j, code); e != nil {
			return nil, e
		}
		return j.public(), nil
	})
}
