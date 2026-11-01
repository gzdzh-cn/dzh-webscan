package controlplane

// Independent, bounded administrator tests. No delivery configuration or secret
// is persisted here; immutable authorization is bound with the shared Vault.
const notificationTestSchema = `
CREATE TABLE v3_notification_test_previews(
 id text PRIMARY KEY,username text NOT NULL REFERENCES v3_accounts(username),
 account_revision bigint NOT NULL CHECK(account_revision>0),
 channel text NOT NULL CHECK(channel IN ('email','feishu')),
 runtime_version bigint NOT NULL CHECK(runtime_version>0),targets jsonb NOT NULL,
 key_id text NOT NULL,proof text NOT NULL CHECK(length(proof)=64),used boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
 CHECK(jsonb_typeof(targets)='array' AND jsonb_array_length(targets) BETWEEN 1 AND 20),CHECK(expires_at>created_at)
);
CREATE INDEX v3_notification_test_preview_owner ON v3_notification_test_previews(username,expires_at) WHERE NOT used;
CREATE TABLE v3_notification_test_jobs(
 id text PRIMARY KEY,preview text NOT NULL UNIQUE REFERENCES v3_notification_test_previews(id),
 username text NOT NULL REFERENCES v3_accounts(username),account_revision bigint NOT NULL CHECK(account_revision>0),
 channel text NOT NULL CHECK(channel IN ('email','feishu')),runtime_version bigint NOT NULL CHECK(runtime_version>0),
 targets jsonb NOT NULL,key_id text NOT NULL,proof text NOT NULL CHECK(length(proof)=64),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','partial','failed','unknown','cancelled')),
 message text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,finished_at timestamptz,
 CHECK(jsonb_typeof(targets)='array' AND jsonb_array_length(targets) BETWEEN 1 AND 20),
 CHECK((status IN ('succeeded','partial','failed','unknown','cancelled'))=(finished_at IS NOT NULL))
);
CREATE INDEX v3_notification_test_job_pending ON v3_notification_test_jobs(created_at,id) WHERE status IN ('queued','running');
CREATE TABLE v3_notification_test_deliveries(
 job text NOT NULL REFERENCES v3_notification_test_jobs(id) ON DELETE CASCADE,
 ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 20),recipient text NOT NULL CHECK(octet_length(recipient)<=320),
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sending','accepted','unknown','cancelled')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts IN (0,1)),lease_owner text,lease_epoch bigint NOT NULL DEFAULT 0 CHECK(lease_epoch>=0),lease_until timestamptz,
 started_at timestamptz,finished_at timestamptz,outcome text NOT NULL DEFAULT '',message text NOT NULL DEFAULT '',
 PRIMARY KEY(job,ordinal),UNIQUE(job,recipient),
 CHECK((state='sending')=(lease_owner IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK((state IN ('accepted','unknown','cancelled'))=(finished_at IS NOT NULL)),
 CHECK((attempts=0 AND state IN ('queued','cancelled') AND started_at IS NULL) OR (attempts=1 AND state IN ('sending','accepted','unknown') AND started_at IS NOT NULL)),
 CHECK(outcome IN ('','accepted','unconfirmed','authorization_changed','expired','restored'))
);
CREATE INDEX v3_notification_test_delivery_expired ON v3_notification_test_deliveries(lease_until) WHERE state='sending';
CREATE TABLE v3_notification_test_cooldowns(channel text PRIMARY KEY CHECK(channel IN ('email','feishu')),next_allowed_at timestamptz NOT NULL);
`
