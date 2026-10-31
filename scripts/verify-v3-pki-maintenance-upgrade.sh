#!/usr/bin/env bash
# Isolated actual signed Linux helper + PG checks. Data lives in tmpfs: this
# verifies schema/signature/queue behavior, not disk durability or systemd.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${WEBSCAN_V3_PKI_TEST_PG_IMAGE:?Provide a cached PostgreSQL 17 Linux amd64 image ID or immutable reference}"
: "${WEBSCAN_V3_PKI_TEST_RUNNER_IMAGE:?Provide a cached Linux amd64 runner image ID or immutable reference}"
for task_image in "$WEBSCAN_V3_PKI_TEST_PG_IMAGE" "$WEBSCAN_V3_PKI_TEST_RUNNER_IMAGE"; do
  task_platform="$(docker image inspect --platform linux/amd64 --format '{{.Os}}/{{.Architecture}}' "$task_image")"
  [[ "$task_platform" == linux/amd64 ]] || { echo 'All isolated maintenance images must provide Linux amd64; no containers created.' >&2; exit 2; }
done
task_release="${WEBSCAN_V3_PKI_TEST_RELEASE:-v3.0.3-local-test}"
task_helper="${WEBSCAN_V3_PKI_TEST_HELPER:-}"
[[ "$task_release" =~ ^v[0-9][A-Za-z0-9._-]{1,80}$ ]] || exit 2
if [[ -n "$task_helper" || "$task_release" != v3.0.3-local-test ]]; then
  [[ "$task_helper" == /* && -f "$task_helper" && ! -L "$task_helper" ]] || { echo 'Explicit regular exact-release helper required.' >&2; exit 2; }
fi
task_run="$(mktemp -d "$(pwd)/.cache/verification/v3/pki-maintenance.XXXXXX")"
task_suffix="$(basename "$task_run")"
task_pg="webscan-v3-pki-pg-$task_suffix"
task_runner="webscan-v3-pki-runner-$task_suffix"
cleanup() {
  docker logs --tail 100 "$task_pg" > "$task_run/postgres.log" 2>&1 || true
  docker rm -fv "$task_runner" "$task_pg" > "$task_run/cleanup.log" 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
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
  --label webscan.purpose=isolated-pki-maintenance --network none \
  --tmpfs /var/lib/postgresql/data:rw,nosuid,size=1073741824 \
  --tmpfs /tmp:rw,nosuid,size=67108864 --shm-size=256m \
  -e POSTGRES_PASSWORD=isolated-pki-tests-only -e POSTGRES_DB=webscan \
  "$WEBSCAN_V3_PKI_TEST_PG_IMAGE" > "$task_run/postgres.id"
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
  --label webscan.purpose=isolated-pki-maintenance --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=1073741824 --network "container:$task_pg" \
  -v "$task_run:/evidence:ro" \
  -e WEBSCAN_V3_TEST_MAINTENANCE_HELPER=/evidence/webscan \
  -e WEBSCAN_V3_TEST_RELEASE="$task_release" \
  -e 'WEBSCAN_V3_TEST_DSN=postgres://postgres:isolated-pki-tests-only@127.0.0.1:5432/webscan?sslmode=disable' \
  --entrypoint /evidence/controlplane.test "$WEBSCAN_V3_PKI_TEST_RUNNER_IMAGE" \
  -test.run '^TestSinglePKIUpgradeSignedHelperLinux$' -test.v -test.timeout 3m \
  | tee "$task_run/integration.log"
printf 'Signed helper and PostgreSQL checks passed (tmpfs, no systemd/kernel acceptance). Evidence: %s\n' "$task_run"
