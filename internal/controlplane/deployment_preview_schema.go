package controlplane

const deploymentPreviewSchema = `
CREATE INDEX v3_deployment_node_history ON v3_deployment_jobs(node,created_at DESC,id DESC);
CREATE TABLE v3_deployment_previews(
 token_hash text PRIMARY KEY,
 username text NOT NULL REFERENCES v3_accounts(username),
 account_revision bigint NOT NULL,
 node text NOT NULL REFERENCES v3_nodes(id),
 request jsonb NOT NULL,
 request_digest text NOT NULL,
 state_digest text NOT NULL,
 credential_revision bigint NOT NULL,
 job text REFERENCES v3_deployment_jobs(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes'
);
CREATE INDEX v3_deployment_previews_expiry ON v3_deployment_previews(expires_at) WHERE job IS NULL;
CREATE INDEX v3_deployment_previews_user ON v3_deployment_previews(username,expires_at) WHERE job IS NULL;
INSERT INTO v3_schema(version) VALUES(13);
`
