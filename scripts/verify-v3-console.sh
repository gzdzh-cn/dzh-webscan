#!/usr/bin/env bash
# Own-schema API and real PG/VM dependency tests in an internal Linux network. No SSH,
# remote collector targets, executor or business notifications are used.
# Bootstrap tests start local roles against empty, isolated fixtures only.
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$task_root"
mkdir -p .cache/verification/v3
task_run="$(mktemp -d "$task_root/.cache/verification/v3/console-linux.XXXXXX")"
task_suffix="$(basename "$task_run")"
task_pg="webscan-v3-pg-$task_suffix"
task_tests="webscan-v3-tests-$task_suffix"
task_vm="webscan-v3-vm-$task_suffix"
task_network="webscan-v3-test-$task_suffix"
task_image="${WEBSCAN_V3_AGENT_TEST_IMAGE:-sha256:c7b76b7061936ada0706593e3edc3ff94fa8dad1b1bc82d2e4f5094f69afcf3f}"
task_pg_image="${WEBSCAN_V3_TEST_PG_IMAGE:-postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24}"
task_vm_image="${WEBSCAN_V3_TEST_VM_IMAGE:-victoriametrics/victoria-metrics:v1.128.0@sha256:c27e736a8aff888cf30c4f20ec648b767358694993d87e89afc6bf80f28991da}"
task_selection="${WEBSCAN_V3_CONSOLE_TEST_RUN:-^Test(ConfigurationApplication|ConfigurationOperationGate|DeploymentTerminal|ConfigurationEnvironment|ConfigurationSaved|BootstrapDraft|BootstrapRuntime|SettingsDraft|SettingsEditor|NodeRuntime|Dashboard|Console|APISession|APIDatabaseFailure|APIRejectsCrossOrigin|EventMigration|ManualHistoryAPI|DeploymentAPI|DeploymentPreview|DeploymentConfigurationBackup|NodeProvisioning|LocalProvisioning|PKIRegistryBackup|AlertReadModels|NotificationHistoryMetadata|WebsiteAPI|WebsiteStatusSummary|RetentionAPI|RetentionWorker|RetentionStandby|WebsiteBackupAPI|WebsiteBackupStrict|WebsiteBackupSchema9|AuditAPI|AuditSummary|ConfigurationDocument|ConfigurationBackup|ConfigurationDelete|ConfigurationRestore|ConfigurationRevision|ConfigurationEditBackup)}"
printf '%s\n' "$task_selection" > "$task_run/test-selection.txt"
cleanup() {
  docker rm -fv "$task_tests" "$task_pg" "$task_vm" >/dev/null 2>&1 || true
  docker network rm "$task_network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker image inspect "$task_image" > "$task_run/test-image.json"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags '-X webscan/internal/deploy.Release=v3.0.0-local-test' \
  -o "$task_run/webscan" ./cmd/webscan
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c \
  -o "$task_run/controlplane.test" ./internal/controlplane
docker network create --internal "$task_network" > "$task_run/network.id"
docker run -d --name "$task_pg" --network "$task_network" --network-alias postgres \
  -e POSTGRES_HOST_AUTH_METHOD=trust "$task_pg_image" > "$task_run/postgres.container"
docker run -d --name "$task_vm" --network "$task_network" --network-alias victoriametrics \
  "$task_vm_image" -retentionPeriod=1d > "$task_run/victoriametrics.container"
task_ready=0
for ((task_i=0; task_i<30; task_i++)); do
  if docker exec "$task_pg" pg_isready -U postgres >/dev/null 2>&1; then task_ready=1; break; fi
  sleep 1
done
if [[ "$task_ready" != 1 ]]; then echo '隔离 PostgreSQL 未就绪。' >&2; exit 1; fi
docker run --rm --name "$task_tests" --platform linux/amd64 --network "$task_network" --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m,mode=1777 \
  --tmpfs /configuration-lowdisk:rw,noexec,nosuid,size=1m,mode=700 \
  -e WEBSCAN_V3_CONFIGURATION_LOW_DISK_DIRECTORY=/configuration-lowdisk \
  -e WEBSCAN_V3_TEST_CLI=/validation/webscan \
  -e WEBSCAN_V3_TEST_VM='http://victoriametrics:8428' \
  -e WEBSCAN_V3_TEST_DSN='postgres://postgres@postgres:5432/postgres?sslmode=disable' \
  -v "$task_run:/validation:ro" \
  -v "$task_root/internal/controlplane:/source/internal/controlplane:ro" \
  -v "$task_root/webscan-v3.example.yaml:/source/webscan-v3.example.yaml:ro" \
  --workdir /source/internal/controlplane \
  --entrypoint /validation/controlplane.test "$task_image" \
  -test.run "$task_selection" -test.timeout 30m -test.v | tee "$task_run/integration.log"
printf 'Isolated console evidence: %s\n' "$task_run"
