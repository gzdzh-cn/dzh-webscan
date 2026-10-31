#!/usr/bin/env bash
# Actual single-server snapshot and fresh restore, entirely offline. A scoped
# host bind uses the workspace disk without cleaning Docker's existing store.
# Neither bind nor tmpfs replaces kernel/power-loss durability acceptance.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${WEBSCAN_V3_SNAPSHOT_TEST_VM_IMAGE:?Provide the cached VictoriaMetrics v1.128.0 Linux amd64 image ID}"
: "${WEBSCAN_V3_SNAPSHOT_TEST_RUNNER_IMAGE:?Provide a cached Linux amd64 runner image ID}"
[[ "$WEBSCAN_V3_SNAPSHOT_TEST_VM_IMAGE" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 2
[[ "$WEBSCAN_V3_SNAPSHOT_TEST_RUNNER_IMAGE" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 2
task_run="$(mktemp -d "$(pwd)/.cache/verification/v3/metrics-snapshot.XXXXXX")"
task_suffix="$(basename "$task_run")"
task_source="webscan-v3-snapshot-source-$task_suffix"
task_runner="webscan-v3-snapshot-runner-$task_suffix"
task_storage="${WEBSCAN_V3_SNAPSHOT_TEST_STORAGE:-bind}"
[[ "$task_storage" == bind || "$task_storage" == tmpfs ]] || exit 2
task_mounts=()
if [[ "$task_storage" == bind ]]; then
  mkdir -m 700 "$task_run/storage"
  task_mounts=(-v "$task_run/storage:/test-storage" -e TMPDIR=/test-storage)
fi
cleanup() {
  docker rm -fv "$task_runner" "$task_source" > "$task_run/cleanup.log" 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker create --pull never --platform linux/amd64 --name "$task_source" \
  --label webscan.purpose=isolated-metrics-snapshot --network none --read-only \
  --log-driver none "$WEBSCAN_V3_SNAPSHOT_TEST_VM_IMAGE" > "$task_run/source.id"
docker cp "$task_source:/victoria-metrics-prod" "$task_run/victoria-metrics-prod"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/controlplane.test" ./internal/controlplane
docker run --rm --pull never --platform linux/amd64 --name "$task_runner" \
  --label webscan.purpose=isolated-metrics-snapshot --read-only --network none \
  --log-driver none --tmpfs /tmp:rw,exec,nosuid,size=1073741824 \
  -v "$task_run:/evidence:ro" \
  "${task_mounts[@]}" \
  -e WEBSCAN_V3_TEST_VM_EXECUTABLE=/evidence/victoria-metrics-prod \
  --entrypoint /bin/sh "$WEBSCAN_V3_SNAPSHOT_TEST_RUNNER_IMAGE" -ec \
  'if test "${TMPDIR:-/tmp}" = /test-storage; then chown 0:0 /test-storage; chmod 700 /test-storage; fi; exec /evidence/controlplane.test -test.run "^TestMetricsSnapshot" -test.v -test.timeout 3m' \
  | tee "$task_run/integration.log"
printf 'VM snapshot/restore checks passed (isolated %s). Evidence: %s\n' "$task_storage" "$task_run"
