package controlplane

import (
	"context"
	"database/sql"
	"errors"
)

// The row is locked before relation/record locks. A shared lock keeps ordinary
// deployments on different nodes concurrent; configuration application takes
// the exclusive lock. Updating generation with every application state write
// also invalidates an older REPEATABLE READ snapshot after it waits for us.
// Table locks alone do not advance such a snapshot.
const configurationOperationGateSchema = `
CREATE TABLE v3_configuration_operation_gate(
 singleton boolean PRIMARY KEY CHECK(singleton),
 generation bigint NOT NULL CHECK(generation>=0)
);
INSERT INTO v3_configuration_operation_gate(singleton,generation) VALUES(true,0);
CREATE TABLE v3_configuration_application_targets(
 application text PRIMARY KEY REFERENCES v3_configuration_applications(id),
 release text NOT NULL,manifest_sha256 text NOT NULL,proof text NOT NULL
);
CREATE TABLE v3_configuration_application_nodes(
 application text NOT NULL REFERENCES v3_configuration_applications(id),
 node text NOT NULL REFERENCES v3_nodes(id),
 child text NOT NULL UNIQUE REFERENCES v3_deployment_jobs(id),
 ordinal integer NOT NULL CHECK(ordinal>=0),
 parent_epoch bigint NOT NULL CHECK(parent_epoch>0),
 plan_digest text NOT NULL,proof text NOT NULL,
 PRIMARY KEY(application,node),UNIQUE(application,ordinal)
);
INSERT INTO v3_schema(version) VALUES(25);
`

func lockConfigurationOperationTx(ctx context.Context, tx *sql.Tx, exclusive bool) error {
	lock := " FOR SHARE"
	if exclusive {
		lock = " FOR UPDATE"
	}
	var generation int64
	err := tx.QueryRowContext(ctx, `SELECT generation FROM v3_configuration_operation_gate WHERE singleton`+lock).Scan(&generation)
	if err == sql.ErrNoRows {
		return errors.New("配置操作互斥记录缺失，已停止修改")
	}
	if err != nil {
		return err
	}
	return rootRotationAvailableTx(ctx, tx)
}

func advanceConfigurationOperationTx(ctx context.Context, tx *sql.Tx) error {
	result, err := tx.ExecContext(ctx, `UPDATE v3_configuration_operation_gate SET generation=generation+1 WHERE singleton`)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("配置操作互斥记录缺失，已停止修改")
	}
	return nil
}
