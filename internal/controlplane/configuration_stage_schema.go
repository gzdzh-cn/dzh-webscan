package controlplane

// Pending intents are private workflow state, not applied configuration. Backup
// references are protected by durable pins, not permanent historical FKs: once
// cancelled, an otherwise unreferenced archive may still be explicitly deleted.
const configurationStageSchema = `
CREATE TABLE v3_configuration_restore_stages(
 id text PRIMARY KEY,username text NOT NULL,account_revision bigint NOT NULL,
 preview_hash text NOT NULL UNIQUE,backup text NOT NULL,before_backup text NOT NULL,
 options jsonb NOT NULL,archive_proof text NOT NULL,state_proof text NOT NULL,
 summary jsonb NOT NULL,settings_version bigint NOT NULL,
 status text NOT NULL DEFAULT 'pending_validation' CHECK(status IN ('pending_validation','cancelled')),
 message text NOT NULL DEFAULT '恢复意图已保存，待本地验证；运行配置未修改',
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 finished_at timestamptz,cancelled_by text NOT NULL DEFAULT '',
 CHECK(account_revision>0 AND settings_version>0),
 CHECK((status='pending_validation' AND finished_at IS NULL) OR (status='cancelled' AND finished_at IS NOT NULL))
);
CREATE UNIQUE INDEX v3_configuration_restore_one_pending ON v3_configuration_restore_stages((true)) WHERE status='pending_validation';
CREATE INDEX v3_configuration_restore_stages_history ON v3_configuration_restore_stages(created_at DESC,id DESC);
CREATE INDEX v3_configuration_restore_stages_expiry ON v3_configuration_restore_stages(finished_at,id) WHERE status='cancelled';
INSERT INTO v3_schema(version) VALUES(17);
`
