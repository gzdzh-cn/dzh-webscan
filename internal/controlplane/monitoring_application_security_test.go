package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// A signed parent must derive its member set and terminal evidence from the
// immutable plan. Mutable scheduler columns cannot certify remote success.
// These tests use real isolated PostgreSQL and local runtime adapters only.
func TestMonitoringApplicationSecurityRejectsForgedNodeCheckpoints(t *testing.T) {
	for _, scenario := range []string{"succeeded-without-child", "reservation-cleared", "member-row-missing", "forged-child-link"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMonitoringApplicationFixture(t)
			p := f.confirmed(t)
			if len(p.Plan.Nodes) != 1 || configurationJSONEqual(p.Plan.Nodes[0].Before, p.Plan.Nodes[0].Target) {
				t.Fatal("security fixture must require an actual configuration change")
			}
			before := publicMonitoringNode(t, f.s, f.in.Node)
			active := runtimeNodeForTest(t, f.s, f.in.Node)
			jobs := tableCount(t, f.s, "v3_deployment_jobs")
			backups := tableCount(t, f.s, "v3_configuration_backups")
			switch scenario {
			case "succeeded-without-child":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_application_nodes SET state='succeeded',child=NULL WHERE application=$1`, p.ID)
			case "reservation-cleared":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_application_nodes SET reserved=false WHERE application=$1`, p.ID)
			case "member-row-missing":
				mustHistoryExec(t, f.s.DB, `DELETE FROM v3_monitoring_application_nodes WHERE application=$1`, p.ID)
			case "forged-child-link":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_monitoring_application_nodes SET state='succeeded',child=(SELECT id FROM v3_deployment_jobs WHERE node=$2 ORDER BY created_at LIMIT 1) WHERE application=$1`, p.ID, f.in.Node)
			}
			remote := &fakeDeploymentRuntime{}
			f.worker.runtime = readinessFixtureRuntime{remote, t, f.s}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			f.worker.execute(ctx, p)
			var status string
			if e := f.s.DB.QueryRow(`SELECT status FROM v3_monitoring_applications WHERE id=$1`, p.ID).Scan(&status); e != nil {
				t.Fatal(e)
			}
			if status == "succeeded" || status == "rolled_back" {
				t.Error("forged mutable checkpoint certified terminal parent success", scenario, status)
			}
			if len(remote.calls) != 0 || tableCount(t, f.s, "v3_deployment_jobs") != jobs || tableCount(t, f.s, "v3_configuration_backups") != backups {
				t.Error("corrupted checkpoint started remote work or changed recovery material")
			}
			after := publicMonitoringNode(t, f.s, f.in.Node)
			if after.Version != before.Version || !configurationJSONEqual(after.Config, before.Config) || !reflect.DeepEqual(runtimeNodeForTest(t, f.s, f.in.Node), active) {
				t.Error("corrupted checkpoint changed desired or runtime configuration")
			}
			if scenario == "succeeded-without-child" || scenario == "forged-child-link" {
				var reserved bool
				if e := f.s.DB.QueryRow(`SELECT reserved FROM v3_monitoring_application_nodes WHERE application=$1`, p.ID).Scan(&reserved); e != nil || !reserved {
					t.Error("forged terminal evidence released the real reservation", e)
				}
			}
		})
	}
}

// guardedMutationOptions reads migrationHeld before taking its relation gate.
// Under REPEATABLE READ this establishes a snapshot. A monitoring confirmation
// committed in that window must invalidate the snapshot or remain visible to
// the following ordinary-deployment reservation check.
func TestMonitoringApplicationSecurityRepeatableReadCannotBypassReservation(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	p, capability := f.preview(t)
	ctx := context.Background()
	stale, e := f.s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer stale.Rollback()
	if held, e := migrationHeld(ctx, stale); e != nil || held {
		t.Fatal("cannot establish ordinary deployment snapshot", e)
	}
	if _, e = f.s.confirmMonitoringApplication(ctx, f.t, "admin", "confirm-after-old-snapshot", p.ID, capability); e != nil {
		t.Fatal("monitoring confirmation", e)
	}
	var actual bool
	if e = f.s.DB.QueryRow(`SELECT reserved FROM v3_monitoring_application_nodes WHERE application=$1`, p.ID).Scan(&actual); e != nil || !actual {
		t.Fatal("monitoring confirmation did not reserve real node", e)
	}
	if e = lockDeploymentWriteRelationsTx(ctx, stale); e != nil {
		var pg *pgconn.PgError
		if !errors.As(e, &pg) || pg.Code != "40001" {
			t.Fatal("unexpected deployment gate failure", e)
		}
		return // The ordinary queue's existing retry starts a fresh snapshot.
	}
	if e = checkMonitoringNodeReservationTx(ctx, stale, f.in.Node); !errors.Is(e, ErrDeploymentBusy) {
		t.Fatal("ordinary deployment's stale repeatable-read snapshot bypassed committed node reservation", e)
	}
}
