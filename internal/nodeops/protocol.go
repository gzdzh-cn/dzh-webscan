// Package nodeops implements the durable, node-local side of v3 deployment
// coordination. It is independent of the control-plane database and v2 journal.
package nodeops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"webscan/internal/nodeconfig"
)

const Protocol = 1
const Root = "/var/lib/webscan-deploy/v3/node"
const DeploymentRoot = "/var/lib/webscan-deploy/v3"
const MaxRequestBytes = 512 << 10

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var forward = []string{"preflight", "stage", "backup", "activate", "verify", "finalize"}
var rollback = []string{"restore", "verify-rollback"}

type Spec struct {
	Action             string   `json:"action,omitempty"`
	Mode               string   `json:"mode"`
	MetricsPort        int      `json:"metrics_port"`
	MonitorDirectories []string `json:"monitor_directories"`
	ArtifactBytes      uint64   `json:"artifact_bytes"`
	ClamAV             bool     `json:"clamav"`
	Release            string   `json:"release,omitempty"`
	BundleSHA256       string   `json:"bundle_sha256,omitempty"`
	AgentImage         string   `json:"agent_image,omitempty"`
	ImageArchiveSHA256 string   `json:"image_archive_sha256,omitempty"`
	ImageArchiveBytes  uint64   `json:"image_archive_bytes,omitempty"`
	ImageConfigSHA256  string   `json:"image_config_sha256,omitempty"`
	RuntimeSHA256      string   `json:"runtime_sha256,omitempty"`
	RuntimeBytes       uint64   `json:"runtime_bytes,omitempty"`
	ConfigVersion      int64    `json:"config_version,omitempty"`
	ConfigSourceSHA256 string   `json:"config_source_sha256,omitempty"`
	ServerName         string   `json:"server_name,omitempty"`
}

func (s Spec) Validate() error {
	if s.Action != "" && s.Action != "uninstall" {
		return errors.New("invalid-spec")
	}
	if s.Mode != "native" && s.Mode != "docker" || s.MetricsPort < 1024 || s.MetricsPort > 65535 || len(s.MonitorDirectories) < 1 || len(s.MonitorDirectories) > 64 || s.ArtifactBytes > 4<<30 {
		return errors.New("invalid-spec")
	}
	if (s.Release != "" || s.BundleSHA256 != "") && !s.bundleValid() {
		return errors.New("invalid-spec")
	}
	if s.AgentImage != "" && !AgentImageMatchesRelease(s.AgentImage, s.Release) {
		return errors.New("invalid-spec")
	}
	if s.ImageArchiveSHA256 != "" || s.ImageArchiveBytes != 0 || s.ImageConfigSHA256 != "" {
		if !s.imageArchiveValid() {
			return errors.New("invalid-spec")
		}
	}
	if s.RuntimeSHA256 != "" || s.RuntimeBytes != 0 || s.ConfigVersion != 0 || s.ConfigSourceSHA256 != "" || s.ServerName != "" {
		if !s.configurationValid() {
			return errors.New("invalid-spec")
		}
	}
	seen := map[string]bool{}
	for _, p := range s.MonitorDirectories {
		clean := filepath.Clean(p)
		if !filepath.IsAbs(p) || len(p) > 4096 || strings.ContainsAny(p, "\x00\r\n") || seen[clean] {
			return errors.New("invalid-spec")
		}
		seen[clean] = true
	}
	return nil
}

func (s Spec) configurationValid() bool {
	return s.bundleValid() && validDigest(s.RuntimeSHA256) && s.RuntimeBytes > 0 && s.RuntimeBytes <= nodeconfig.MaxBytes && s.ConfigVersion > 0 && validDigest(s.ConfigSourceSHA256) && s.ServerName != "" && len(s.ServerName) <= 253 && !strings.ContainsAny(s.ServerName, "/\\\x00\r\n \t")
}
func (s Spec) digest() string { raw, _ := json.Marshal(s); return sha(raw) }

var releasePattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?$`)
var immutableAgentImage = regexp.MustCompile(`^(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?/)?(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*(?::v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?)?@sha256:[a-f0-9]{64}$`)

func ValidAgentImage(s string) bool {
	return len(s) <= 512 && immutableAgentImage.MatchString(s)
}

// A version is display metadata; the signed digest still identifies the image.
// Untagged references remain valid for existing releases and recovery records.
func AgentImageMatchesRelease(image, release string) bool {
	if !ValidAgentImage(image) {
		return false
	}
	_, tag := agentImageName(image)
	return tag == "" || tag == release
}

func agentImageName(image string) (repository, tag string) {
	repository, _, _ = strings.Cut(image, "@")
	if colon := strings.LastIndex(repository, ":"); colon > strings.LastIndex(repository, "/") {
		tag, repository = repository[colon+1:], repository[:colon]
	}
	return repository, tag
}

func (s Spec) imageArchiveValid() bool {
	return s.Mode == "docker" && ValidAgentImage(s.AgentImage) && validDigest(s.ImageArchiveSHA256) && validDigest(s.ImageConfigSHA256) && s.ImageArchiveBytes > 0 && s.ImageArchiveBytes <= 4<<30
}

func (s Spec) bundleValid() bool {
	return releasePattern.MatchString(s.Release) && len(s.Release) <= 128 && validDigest(s.BundleSHA256) && s.ArtifactBytes > 0 && s.ArtifactBytes <= 4<<30
}
func sha(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

type Request struct {
	Protocol   int                 `json:"protocol"`
	Operation  string              `json:"operation"`
	Job        string              `json:"job"`
	Node       string              `json:"node"`
	PlanDigest string              `json:"plan_digest"`
	Epoch      int64               `json:"epoch"`
	Phase      string              `json:"phase"`
	Spec       Spec                `json:"spec"`
	Recovery   *RecoveryReference  `json:"recovery,omitempty"`
	Uninstall  *UninstallReference `json:"uninstall,omitempty"`
	Reinstall  *ReinstallReference `json:"reinstall,omitempty"`
}

// Uninstall binds the actual installation, not an editable desired config.
// A restored installation also names the independently verified replacement.
type UninstallReference struct {
	SourceJob             string `json:"source_job"`
	SourcePlanDigest      string `json:"source_plan_digest"`
	CaptureSHA256         string `json:"capture_sha256"`
	ActiveSHA256          string `json:"active_sha256"`
	RestorationJob        string `json:"restoration_job,omitempty"`
	RestorationPlanDigest string `json:"restoration_plan_digest,omitempty"`
	RestorationSHA256     string `json:"restoration_sha256,omitempty"`
}

type ReinstallReference struct {
	SourceJob        string `json:"source_job"`
	SourcePlanDigest string `json:"source_plan_digest"`
	TombstoneSHA256  string `json:"tombstone_sha256"`
}

// Recovery uses a new task identity and bounded private evidence references.
// A caller cannot supply filesystem paths or commands.
type RecoveryReference struct {
	SourceJob        string `json:"source_job"`
	SourcePlanDigest string `json:"source_plan_digest"`
	CaptureSHA256    string `json:"capture_sha256"`
	HeadJob          string `json:"head_job"`
	HeadPlanDigest   string `json:"head_plan_digest"`
	ActiveSHA256     string `json:"active_sha256"`
}

func (r Request) identityDigest() string {
	if r.Uninstall != nil || r.Reinstall != nil {
		raw, _ := json.Marshal(struct {
			Spec      Spec
			Uninstall *UninstallReference `json:",omitempty"`
			Reinstall *ReinstallReference `json:",omitempty"`
		}{r.Spec, r.Uninstall, r.Reinstall})
		return sha(append([]byte("webscan-v3/node-lifecycle/v1\x00"), raw...))
	}
	if r.Recovery == nil {
		return r.Spec.digest()
	}
	raw, _ := json.Marshal(struct {
		Spec     Spec
		Recovery *RecoveryReference
	}{r.Spec, r.Recovery})
	return sha(raw)
}

func (r Request) sourceRequest() Request {
	q := r
	q.Job, q.PlanDigest, q.Recovery, q.Operation = r.Recovery.SourceJob, r.Recovery.SourcePlanDigest, nil, "apply"
	return q
}

func (r Request) Validate() error {
	if r.Protocol != Protocol || (r.Operation != "inspect" && r.Operation != "apply") || !idPattern.MatchString(r.Job) || !idPattern.MatchString(r.Node) || !validDigest(r.PlanDigest) || r.Epoch < 1 || phaseIndex(r.Phase) < 0 {
		return errors.New("invalid-request")
	}
	if (r.Spec.Action == "uninstall") != (r.Uninstall != nil) || r.Uninstall != nil && (r.Recovery != nil || r.Reinstall != nil) || r.Reinstall != nil && r.Recovery != nil {
		return errors.New("invalid-action")
	}
	if q := r.Uninstall; q != nil {
		if !r.Spec.configurationValid() || !idPattern.MatchString(q.SourceJob) || q.SourceJob == r.Job || !validDigest(q.SourcePlanDigest) || !validDigest(q.CaptureSHA256) || !validDigest(q.ActiveSHA256) {
			return errors.New("invalid-uninstall-reference")
		}
		if q.RestorationJob != "" || q.RestorationPlanDigest != "" || q.RestorationSHA256 != "" {
			if !idPattern.MatchString(q.RestorationJob) || q.RestorationJob == r.Job || q.RestorationJob == q.SourceJob || !validDigest(q.RestorationPlanDigest) || !validDigest(q.RestorationSHA256) {
				return errors.New("invalid-uninstall-reference")
			}
		}
	}
	if q := r.Reinstall; q != nil {
		if !r.Spec.configurationValid() || !idPattern.MatchString(q.SourceJob) || q.SourceJob == r.Job || !validDigest(q.SourcePlanDigest) || !validDigest(q.TombstoneSHA256) {
			return errors.New("invalid-reinstall-reference")
		}
	}
	if q := r.Recovery; q != nil {
		if (r.Phase != "restore" && r.Phase != "verify-rollback") || !r.Spec.configurationValid() || !idPattern.MatchString(q.SourceJob) || !idPattern.MatchString(q.HeadJob) || q.SourceJob == q.HeadJob || q.SourceJob == r.Job || q.HeadJob == r.Job || !validDigest(q.SourcePlanDigest) || !validDigest(q.HeadPlanDigest) || !validDigest(q.CaptureSHA256) || !validDigest(q.ActiveSHA256) {
			return errors.New("invalid-recovery-reference")
		}
	}
	return r.Spec.Validate()
}
func phaseIndex(phase string) int {
	for i, p := range forward {
		if p == phase {
			return i
		}
	}
	for i, p := range rollback {
		if p == phase {
			return len(forward) + i
		}
	}
	return -1
}

type Check struct {
	ID       string `json:"id"`
	Status   string `json:"status"` // passed, failed, unknown, warning
	Code     string `json:"code"`
	Actual   uint64 `json:"actual,omitempty"`
	Required uint64 `json:"required,omitempty"`
}
type Outcome struct {
	Checks []Check `json:"checks,omitempty"`
}
type Result struct {
	Protocol     int                   `json:"protocol"`
	Job          string                `json:"job"`
	Node         string                `json:"node"`
	PlanDigest   string                `json:"plan_digest"`
	Epoch        int64                 `json:"epoch"`
	Phase        string                `json:"phase"`
	State        string                `json:"state"` // absent, complete, unknown
	Code         string                `json:"code"`
	Outcome      Outcome               `json:"outcome"`
	Installation *InstallationEvidence `json:"installation,omitempty"`
	Removal      *RemovalEvidence      `json:"removal,omitempty"`
	Restoration  *RestorationEvidence  `json:"restoration,omitempty"`
}

type RemovalEvidence struct {
	CaptureSHA256   string `json:"capture_sha256"`
	IntentSHA256    string `json:"intent_sha256"`
	PreservedSHA256 string `json:"preserved_sha256"`
	TombstoneSHA256 string `json:"tombstone_sha256"`
}

func (e RemovalEvidence) Valid() bool {
	return validDigest(e.CaptureSHA256) && validDigest(e.IntentSHA256) && validDigest(e.PreservedSHA256) && validDigest(e.TombstoneSHA256)
}

type RestorationEvidence struct {
	CaptureSHA256   string `json:"capture_sha256,omitempty"`
	IntentSHA256    string `json:"intent_sha256"`
	ActiveSHA256    string `json:"active_sha256"`
	ObjectSHA256    string `json:"object_sha256"`
	PreservedSHA256 string `json:"preserved_sha256"`
	NoEffects       bool   `json:"no_effects,omitempty"`
}

func (e RestorationEvidence) Valid() bool {
	return (e.NoEffects && e.CaptureSHA256 == "" || !e.NoEffects && validDigest(e.CaptureSHA256)) && validDigest(e.IntentSHA256) && validDigest(e.ActiveSHA256) && validDigest(e.ObjectSHA256) && validDigest(e.PreservedSHA256)
}

// InstallationEvidence contains only immutable digests. It lets the control
// plane retain a recovery reference before a later task retires this identity.
type InstallationEvidence struct {
	CaptureSHA256 string `json:"capture_sha256"`
	ActiveSHA256  string `json:"active_sha256"`
}

func (e InstallationEvidence) Valid() bool {
	return validDigest(e.CaptureSHA256) && validDigest(e.ActiveSHA256)
}

func result(r Request, state, code string, out Outcome) Result {
	return Result{Protocol: Protocol, Job: r.Job, Node: r.Node, PlanDigest: r.PlanDigest, Epoch: r.Epoch, Phase: r.Phase, State: state, Code: code, Outcome: out}
}

// Handler must execute only the named fixed phase. It must never start a new
// service or alter effective configuration during preflight/stage. Reconcile
// may report absent/complete only after proving the old operation has stopped;
// otherwise unknown is mandatory. No request can supply commands or scripts.
type Handler interface {
	Supports(string) bool
	Apply(Request) (Outcome, error)
	Reconcile(Request) (string, Outcome, error)
}

// A persisted stage receipt is not evidence that its prepared files still
// exist. Real handlers must revalidate those files before replaying a receipt.
type CompletedVerifier interface {
	VerifyCompleted(Request, Outcome) error
}

type installationEvidenceProvider interface {
	installationEvidence(Request) (*InstallationEvidence, error)
}

type Failure struct{ Code string }

func (f Failure) Error() string { return safeCode(f.Code) }
func safeCode(code string) string {
	switch code {
	case "preflight-failed", "artifact-invalid", "backup-failed", "activation-failed", "verification-failed", "remote-unavailable", "remote-conflict", "remote-state-unknown", "executor-unavailable":
		return code
	default:
		return "remote-unavailable"
	}
}
func failureCode(err error) string {
	var f Failure
	if errors.As(err, &f) {
		return safeCode(f.Code)
	}
	return "remote-unavailable"
}
