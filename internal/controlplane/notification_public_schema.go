package controlplane

// Public text is deliberately separate from the delivery payload and receipt.
// Existing notices have no trusted renderer provenance; never infer it from a
// user-controlled payload.source during this upgrade.
const notificationPublicSchema = `
CREATE TABLE v3_notification_public(
 notification bigint PRIMARY KEY REFERENCES v3_notifications(id) ON DELETE CASCADE,
 projection_version integer NOT NULL DEFAULT 1 CHECK(projection_version=1),
 source text NOT NULL CHECK(source IN ('event','server_health','website','test','legacy','unknown')),
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[0-9a-f]{64}$'),
 subject text NOT NULL CHECK(octet_length(subject)<=1024),
 summary text NOT NULL CHECK(octet_length(summary)<=4096),
 body text NOT NULL CHECK(octet_length(body)<=32768),
 content_state text NOT NULL CHECK(content_state IN ('available','unsupported')),
 content_reason text NOT NULL,
 truncated boolean NOT NULL DEFAULT false,
 projected_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(content_state='available' OR body='')
);
CREATE INDEX v3_notification_public_source ON v3_notification_public(source,notification);
`
