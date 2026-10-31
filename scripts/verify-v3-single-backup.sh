#!/usr/bin/env bash
# Actual signed Linux helper + PostgreSQL 17 + VictoriaMetrics, entirely
# isolated. Existing images/storage are not cleaned or reconfigured.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${WEBSCAN_V3_BACKUP_TEST_PG_IMAGE:?Provide a cached PostgreSQL 17 Linux amd64 image ID}"
: "${WEBSCAN_V3_BACKUP_TEST_VM_IMAGE:?Provide a cached VictoriaMetrics v1.128.0 Linux amd64 image ID}"
: "${WEBSCAN_V3_BACKUP_TEST_RUNNER_IMAGE:?Provide a cached Linux amd64 runner image ID}"
for task_image in "$WEBSCAN_V3_BACKUP_TEST_PG_IMAGE" "$WEBSCAN_V3_BACKUP_TEST_VM_IMAGE" "$WEBSCAN_V3_BACKUP_TEST_RUNNER_IMAGE"; do
  [[ "$task_image" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 2
  task_platform="$(docker image inspect --platform linux/amd64 --format '{{.Os}}/{{.Architecture}}' "$task_image")"
  [[ "$task_platform" == linux/amd64 ]] || { echo 'All isolated backup images must provide Linux amd64; no containers created.' >&2; exit 2; }
done
task_release="${WEBSCAN_V3_BACKUP_TEST_RELEASE:-v3.0.3-local-test}"
task_helper="${WEBSCAN_V3_BACKUP_TEST_HELPER:-}"
[[ "$task_release" =~ ^v[0-9][A-Za-z0-9._-]{1,80}$ ]] || exit 2
if [[ -n "$task_helper" || "$task_release" != v3.0.3-local-test ]]; then
  [[ "$task_helper" == /* && -f "$task_helper" && ! -L "$task_helper" ]] || { echo 'Explicit regular exact-release helper required.' >&2; exit 2; }
fi
task_run="$(mktemp -d "$(pwd)/.cache/verification/v3/single-backup.XXXXXX")"
task_suffix="$(basename "$task_run")"
task_pg="webscan-v3-backup-pg-$task_suffix"
task_vm="webscan-v3-backup-vm-$task_suffix"
task_runner="webscan-v3-backup-runner-$task_suffix"
cleanup() {
  for task_container in "$task_runner" "$task_vm" "$task_pg"; do
    if [[ "$(docker inspect --format '{{ index .Config.Labels "webscan.purpose" }}' "$task_container" 2>/dev/null || true)" == isolated-single-backup ]]; then
      docker rm -fv "$task_container" >> "$task_run/cleanup.log" 2>&1 || true
    fi
  done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 700 "$task_run/storage"
docker create --pull never --platform linux/amd64 --name "$task_vm" \
  --label webscan.purpose=isolated-single-backup --network none --read-only \
  --log-driver none "$WEBSCAN_V3_BACKUP_TEST_VM_IMAGE" > "$task_run/vm.id"
docker cp "$task_vm:/victoria-metrics-prod" "$task_run/victoria-metrics-prod"
if [[ -n "$task_helper" ]]; then
  cp "$task_helper" "$task_run/webscan"
else
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags "-X webscan/internal/deploy.Release=$task_release" \
    -o "$task_run/webscan" ./cmd/webscan
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c \
  -ldflags "-X webscan/internal/deploy.Release=$task_release" \
  -o "$task_run/controlplane.test" ./internal/controlplane
shasum -a 256 "$task_run/webscan" "$task_run/controlplane.test" > "$task_run/inputs.sha256"
docker run -d --pull never --platform linux/amd64 --name "$task_pg" \
  --label webscan.purpose=isolated-single-backup --network none --read-only \
  --log-driver none --tmpfs /var/lib/postgresql/data:rw,nosuid,size=1073741824 \
  --tmpfs /var/run/postgresql:rw,nosuid,size=16777216 \
  --tmpfs /tmp:rw,nosuid,size=16777216 \
  -e POSTGRES_PASSWORD=isolated-full-backup-only -e POSTGRES_DB=webscan \
  "$WEBSCAN_V3_BACKUP_TEST_PG_IMAGE" postgres -c max_wal_size=128MB \
  -c min_wal_size=32MB -c checkpoint_timeout=30s > "$task_run/pg.id"
task_ready=0
for ((task_attempt=0; task_attempt<30; task_attempt++)); do
  if docker exec "$task_pg" pg_isready -U postgres > /dev/null 2>&1; then
    task_ready=1
    break
  fi
  sleep 1
done
[[ "$task_ready" == 1 ]] || { echo 'Isolated PostgreSQL did not become ready.' >&2; exit 1; }
docker run --rm --pull never --platform linux/amd64 --name "$task_runner" \
  --label webscan.purpose=isolated-single-backup --read-only --log-driver none \
  --network "container:$task_pg" --tmpfs /tmp:rw,exec,nosuid,size=268435456 \
  -v "$task_run:/evidence:ro" -v "$task_run/storage:/test-storage" -e TMPDIR=/test-storage \
  -e WEBSCAN_V3_TEST_BACKUP_HELPER=/evidence/webscan \
  -e WEBSCAN_V3_TEST_VM_EXECUTABLE=/evidence/victoria-metrics-prod \
  -e WEBSCAN_V3_TEST_RELEASE="$task_release" \
  -e 'WEBSCAN_V3_TEST_DSN=postgres://postgres:isolated-full-backup-only@127.0.0.1:5432/webscan?sslmode=disable' \
  --entrypoint /bin/sh "$WEBSCAN_V3_BACKUP_TEST_RUNNER_IMAGE" -ec \
  'chown 0:0 /test-storage; chmod 700 /test-storage; exec /evidence/controlplane.test -test.run "^TestSingleBackupActualSignedHelperAndEnginesLinux$" -test.v -test.timeout 4m' \
  | tee "$task_run/integration.log"
printf 'Signed manual/scheduled backups and isolated API restore checks passed (no production service/DR cutover). Evidence: %s\n' "$task_run"
