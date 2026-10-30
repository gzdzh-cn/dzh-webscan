#!/usr/bin/env bash
# Disposable layered tests only, not SSH/systemd/Docker recovery acceptance.
# Never loads production YAML, databases, SSH credentials or notifications.
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$task_root"
mkdir -p .cache/verification/v3
task_run="$(mktemp -d "$task_root/.cache/verification/v3/identity-recovery.XXXXXX")"
task_suffix="$(basename "$task_run")"
task_pg="webscan-v3-pg-$task_suffix"
task_tests="webscan-v3-tests-$task_suffix"
task_network="webscan-v3-network-$task_suffix"
task_image="${WEBSCAN_V3_AGENT_TEST_IMAGE:-webscan-v3-scanner-validation:local}"
task_pg_image="${WEBSCAN_V3_TEST_PG_IMAGE:-postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24}"
cleanup() {
  docker logs "$task_pg" > "$task_run/postgres.log" 2>&1 || true
  docker rm -fv "$task_tests" "$task_pg" >/dev/null 2>&1 || true
  docker network rm "$task_network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# The scanner fixture contains an actual Linux Agent and scanner tools. Build
# scripts/Dockerfile.v3-scanner-validator first if this local image is absent.
docker image inspect "$task_image" > "$task_run/scanner-image.json"
task_image="$(docker image inspect --format '{{.Id}}' "$task_image")"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/controlplane.test" ./internal/controlplane
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/nodeops.test" ./internal/nodeops
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/nodepki.test" ./internal/nodepki
docker network create --internal "$task_network" > "$task_run/network.id"
docker run -d --name "$task_pg" --network "$task_network" --network-alias postgres \
  --tmpfs /var/lib/postgresql/data:rw,size=768m \
  -e POSTGRES_HOST_AUTH_METHOD=trust "$task_pg_image" \
  -c max_wal_size=64MB -c min_wal_size=32MB -c checkpoint_timeout=30s > "$task_run/postgres.container"
task_ready=0
for ((task_i=0; task_i<30; task_i++)); do
  if docker exec "$task_pg" pg_isready -U postgres >/dev/null 2>&1; then task_ready=1; break; fi
  sleep 1
done
if [[ "$task_ready" != 1 ]]; then echo '隔离 PostgreSQL 未就绪。' >&2; exit 1; fi
docker run --rm --name "$task_tests" --platform linux/amd64 --network "$task_network" --read-only --cap-drop ALL \
  --tmpfs /tmp:rw,exec,nosuid,size=768m,mode=1777 -w /src/internal/controlplane \
  -e WEBSCAN_V3_TEST_DSN='postgres://postgres@postgres:5432/postgres?sslmode=disable' \
  -v "$task_root/webscan-v3.example.yaml:/src/webscan-v3.example.yaml:ro" \
  -v "$task_run:/validation:ro" --entrypoint /validation/controlplane.test "$task_image" \
  -test.run '^TestNodeIdentityRecovery|^TestNodeName(Change|Pruning)|^TestNodeIssuance|^TestNodeRenewal|^TestDeploymentSSH|^TestLifecycleSSHRunner' \
  -test.v -test.timeout 10m | tee "$task_run/postgres-integration.log"
docker run --rm --name "$task_tests" --platform linux/amd64 --network none --read-only --cap-drop ALL \
  --tmpfs /tmp:rw,exec,nosuid,size=768m,mode=1777 \
  --tmpfs /var/lib:rw,exec,nosuid,size=512m --tmpfs /var/log:rw,nosuid,size=128m \
  -e WEBSCAN_V3_TEST_BUNDLE=1 -v "$task_run:/validation:ro" \
  --entrypoint /validation/nodeops.test "$task_image" \
  -test.run '^TestIdentityRecovery|^TestNameChange|^TestGeneratedConfiguration' -test.v -test.timeout 3m | tee "$task_run/agent.log"
docker run --rm --name "$task_tests" --platform linux/amd64 --network none --read-only --cap-drop ALL \
  --tmpfs /tmp:rw,exec,nosuid,size=256m,mode=1777 -v "$task_run:/validation:ro" \
  --entrypoint /validation/nodepki.test "$task_image" -test.v -test.timeout 3m | tee "$task_run/pki.log"
printf '分层验证资料：%s\n不代表完整服务安装／恢复或 v3 发布验收。\n' "$task_run"
