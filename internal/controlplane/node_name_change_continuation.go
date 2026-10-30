package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"webscan/internal/nodepki"
)

type nameChangeQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// An original public request must be retained alongside the exact immutable
// issuance. A new intent is never a reason to rewrite its hash or certificate.
func nameChangePriorIssuance(ctx context.Context, q nameChangeQueryer, node, authority, parent, target string, hours int) (nodepki.NodeNameChangeRequest, []byte, error) {
	var empty nodepki.NodeNameChangeRequest
	var certificate, raw []byte
	var knownAuthority, requestSHA, kind string
	var knownHours int
	err := q.QueryRowContext(ctx, `SELECT certificate,authority,request_sha256,request_kind,lifetime_hours FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2`, node, parent).Scan(&certificate, &knownAuthority, &requestSHA, &kind, &knownHours)
	if err != nil {
		return empty, nil, err
	}
	if kind != "name-change" || knownAuthority != authority || knownHours != hours {
		return empty, nil, errNodeNameChange
	}
	err = q.QueryRowContext(ctx, `SELECT request FROM v3_node_name_changes WHERE node=$1 AND authority=$2 AND parent_sha256=$3 AND request_sha256=$4 ORDER BY created_at,id LIMIT 1`, node, authority, parent, requestSHA).Scan(&raw)
	if err != nil {
		return empty, nil, errNodeNameChange
	}
	original, err := nodepki.ParseNodeNameChangeRequest(raw)
	if err != nil || len(original.OriginalRequest) != 0 || len(original.ContinuationCertificate) != 0 || original.SHA256() != requestSHA || original.Intent.Node != node || original.Intent.AuthoritySHA256 != authority || original.Intent.CertificateSHA256 != parent || original.Intent.ServerName != target {
		return empty, nil, errNodeNameChange
	}
	return original, certificate, nil
}

func checkNameChangeContinuationIssuance(ctx context.Context, q nameChangeQueryer, j nodeNameChangeJob, r nodepki.NodeNameChangeRequest) error {
	if len(r.ContinuationCertificate) == 0 {
		original, _, err := nameChangePriorIssuance(ctx, q, j.Node, j.AuthoritySHA256, j.ParentSHA256, j.TargetName, j.LifetimeHours)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil || original.SHA256() != r.SHA256() {
			return errNodeNameChange
		}
		return nil
	}
	original, certificate, err := nameChangePriorIssuance(ctx, q, j.Node, j.AuthoritySHA256, j.ParentSHA256, j.TargetName, j.LifetimeHours)
	if err != nil || !bytes.Equal(certificate, r.ContinuationCertificate) || original.SHA256() != r.IssuanceSHA256() {
		return errNodeNameChange
	}
	return nil
}
