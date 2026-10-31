package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"slices"

	"webscan/internal/nodepki"
)

// Reauthorization replays an existing issuance only. Unlike a name change it
// must retain the exact applied configuration and epoch that justified removal.
func namePruningPriorIssuance(ctx context.Context, q nameChangeQueryer, p nodeNamePruningPlan) (nodepki.NodeNamePruningRequest, []byte, int, error) {
	var empty nodepki.NodeNamePruningRequest
	var certificate, raw []byte
	var authority, sha, kind, snapshot string
	var epoch int64
	var hours int
	err := q.QueryRowContext(ctx, `SELECT certificate,authority,request_sha256,request_kind,snapshot,runtime_epoch,lifetime_hours FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2`, p.Node, p.ParentSHA256).Scan(&certificate, &authority, &sha, &kind, &snapshot, &epoch, &hours)
	if err != nil {
		return empty, nil, 0, err
	}
	if kind != "name-pruning" || authority != p.AuthoritySHA256 || snapshot != p.Snapshot || epoch != p.RuntimeEpoch {
		return empty, nil, 0, errNodeNamePruning
	}
	err = q.QueryRowContext(ctx, `SELECT request FROM v3_node_name_prunings WHERE node=$1 AND authority=$2 AND parent_sha256=$3 AND request_sha256=$4 ORDER BY created_at,id LIMIT 1`, p.Node, authority, p.ParentSHA256, sha).Scan(&raw)
	if err != nil {
		return empty, nil, 0, errNodeNamePruning
	}
	r, err := nodepki.ParseNodeNamePruningRequest(raw)
	if err != nil || len(r.OriginalRequest) != 0 || len(r.ContinuationCertificate) != 0 || r.SHA256() != sha || r.Intent.Node != p.Node || r.Intent.AuthoritySHA256 != authority || r.Intent.CertificateSHA256 != p.ParentSHA256 || r.Intent.ConfigurationSHA256 != p.ConfigurationSHA256 || r.Intent.RuntimeEpoch != p.RuntimeEpoch || r.Intent.ActiveName != p.ActiveName || !slices.Equal(r.Intent.Names, p.Names) {
		return empty, nil, 0, errNodeNamePruning
	}
	return r, certificate, hours, nil
}

func checkNamePruningContinuationIssuance(ctx context.Context, q nameChangeQueryer, j nodeNamePruningJob, r nodepki.NodeNamePruningRequest) error {
	original, certificate, hours, err := namePruningPriorIssuance(ctx, q, j.Plan)
	if len(r.ContinuationCertificate) == 0 && err == sql.ErrNoRows {
		return nil
	}
	if err != nil || hours != j.LifetimeHours || original.SHA256() != r.IssuanceSHA256() || len(r.ContinuationCertificate) != 0 && !bytes.Equal(certificate, r.ContinuationCertificate) {
		return errNodeNamePruning
	}
	return nil
}
