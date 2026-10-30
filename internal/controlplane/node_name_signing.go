package controlplane

import (
	"context"
	"database/sql"
	"time"

	"webscan/internal/nodepki"
)

// A private administrator guard is the only route from a name operation into
// the ordinary parent-successor ledger. RPC renewal input cannot construct it.
// Each operation retains its own proof domain, authorization and certificate
// scope validation; only the transaction/fencing/issuance machinery is shared.
type nodeNameSigningGuard interface {
	binding() nodeNameSigningBinding
	failure() error
	actor(context.Context, *sql.Tx) error
	check(context.Context, *sql.Tx) error
	validateRequest([]byte, []byte, time.Time) error
	validateCertificate([]byte, []byte, []byte, time.Time) error
	issue(context.Context, Config, time.Time, func(nodepki.Bundle, []byte) error) error
	markSigned(context.Context, *sql.Tx) error
}

type nodeNameSigningBinding struct {
	ID, Node, User, AuthoritySHA256, ParentSHA256, Snapshot string
	RequestSHA256, Kind, AuditKind                          string
	RuntimeEpoch                                            int64
	LifetimeHours                                           int
	Certificate, Continuation                               []byte
}

func (g *nodeNameChangeSigningGuard) binding() nodeNameSigningBinding {
	j := g.job
	return nodeNameSigningBinding{ID: j.ID, Node: j.Node, User: j.User, AuthoritySHA256: j.AuthoritySHA256, ParentSHA256: j.ParentSHA256, Snapshot: j.Snapshot, RequestSHA256: g.request.IssuanceSHA256(), Kind: "name-change", AuditKind: "change-node-certificate-name", RuntimeEpoch: j.RuntimeEpoch, LifetimeHours: j.LifetimeHours, Certificate: g.request.Certificate, Continuation: g.request.ContinuationCertificate}
}
func (g *nodeNameChangeSigningGuard) failure() error { return errNodeNameChange }
func (g *nodeNameChangeSigningGuard) actor(ctx context.Context, tx *sql.Tx) error {
	return nameChangeActorTx(ctx, tx, g.job)
}
func (g *nodeNameChangeSigningGuard) validateRequest(ca, crl []byte, now time.Time) error {
	return nodepki.ValidateNodeNameChangeRequest(ca, crl, g.request, g.job.Intent, now)
}
func (g *nodeNameChangeSigningGuard) validateCertificate(ca, crl, certificate []byte, now time.Time) error {
	return nodepki.ValidateNodeNameChangeCertificate(ca, crl, g.request, g.job.Intent, certificate, now)
}
func (g *nodeNameChangeSigningGuard) issue(ctx context.Context, c Config, now time.Time, accept func(nodepki.Bundle, []byte) error) error {
	return nodepki.SignNodeNameChangeRegistered(ctx, c.NodePKI.AuthorityDirectory, g.request, g.job.Intent, now, time.Duration(g.job.LifetimeHours)*time.Hour, accept)
}
func (g *nodeNameChangeSigningGuard) markSigned(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `UPDATE v3_node_name_changes SET status='signed',updated_at=clock_timestamp() WHERE id=$1 AND status='requested'`, g.job.ID)
	return err
}
