#!/usr/bin/env bash
# Disposable PostgreSQL and Linux CLI tests only. Does not load webscan.yaml,
# start an executor, connect SSH or use production notification channels.
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$task_root"
mkdir -p .cache/verification/v3
task_run="$(mktemp -d "$task_root/.cache/verification/v3/provisioning.XXXXXX")"
task_suffix="$(basename "$task_run")"
task_pg="webscan-v3-pg-$task_suffix"
task_tests="webscan-v3-tests-$task_suffix"
task_network="webscan-v3-test-$task_suffix"
task_image="${WEBSCAN_V3_AGENT_TEST_IMAGE:-sha256:c7b76b7061936ada0706593e3edc3ff94fa8dad1b1bc82d2e4f5094f69afcf3f}"
task_pg_image="${WEBSCAN_V3_TEST_PG_IMAGE:-postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24}"
cleanup() {
  docker rm -fv "$task_tests" "$task_pg" >/dev/null 2>&1 || true
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
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c \
  -o "$task_run/nodepki.test" ./internal/nodepki
docker network create --internal "$task_network" > "$task_run/network.id"
docker run -d --name "$task_pg" --network "$task_network" --network-alias postgres \
  -e POSTGRES_HOST_AUTH_METHOD=trust "$task_pg_image" > "$task_run/postgres.container"
task_ready=0
for ((task_i=0; task_i<30; task_i++)); do
  if docker exec "$task_pg" pg_isready -U postgres >/dev/null 2>&1; then task_ready=1; break; fi
  sleep 1
done
if [[ "$task_ready" != 1 ]]; then echo '隔离 PostgreSQL 未就绪。' >&2; exit 1; fi
docker run --rm --name "$task_tests" --platform linux/amd64 --network "$task_network" --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m,mode=1777 \
  -e WEBSCAN_V3_TEST_DSN='postgres://postgres@postgres:5432/postgres?sslmode=disable' \
  -e WEBSCAN_V3_TEST_CLI=/validation/webscan \
  -v "$task_run:/validation:ro" --entrypoint /validation/controlplane.test "$task_image" \
  -test.run '^Test(LocalProvisioning|PKIRegistry|DeploymentPreview|ManualHistorySchema11|WebsiteBackupSchema9)' -test.v | tee "$task_run/integration.log"
docker run --rm --name "$task_tests" --platform linux/amd64 --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
  -v "$task_run:/validation:ro" --entrypoint /validation/nodepki.test "$task_image" \
  -test.run '^Test(RegisteredIssuer|RegistryCRLFloor)' -test.v | tee "$task_run/pki.log"
printf 'Isolated provisioning evidence: %s\n' "$task_run"
