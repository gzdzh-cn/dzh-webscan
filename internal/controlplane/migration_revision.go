package controlplane

// Only opaque identities, aggregate counts and hashes leave the private CLI.
type MigrationRevisionInput struct {
	Role     string `json:"role"`
	SourceID string `json:"source_id"`
	Snapshot string `json:"-"`
}
type MigrationRevisionReport struct {
	ID             string `json:"id"`
	Role           string `json:"role"`
	Source         string `json:"source"`
	Sequence       int64  `json:"sequence"`
	State          string `json:"state"`
	Records        int64  `json:"records"`
	Digest         string `json:"digest"`
	SessionVersion int64  `json:"session_version"`
}
type MigrationDeltaReport struct {
	ID             string `json:"id"`
	Role           string `json:"role"`
	Base           string `json:"base"`
	Target         string `json:"target"`
	State          string `json:"state"`
	Added          int64  `json:"added"`
	Modified       int64  `json:"modified"`
	Deleted        int64  `json:"deleted"`
	Unchanged      int64  `json:"unchanged"`
	SchemaChanges  int64  `json:"schema_changes"`
	Digest         string `json:"digest"`
	SessionVersion int64  `json:"session_version"`
}
