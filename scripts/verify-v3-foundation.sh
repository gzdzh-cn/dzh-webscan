#!/usr/bin/env bash
# Creates disposable local databases only. Never reads webscan.yaml or connects
# to the deployed management service, SMTP or Feishu endpoints.
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$task_root"
mkdir -p .cache/verification/v3
task_run="$(mktemp -d "$task_root/.cache/verification/v3/run.XXXXXX")"
task_suffix="$(basename "$task_run")"
task_pg="webscan-v3-pg-$task_suffix"
task_vm="webscan-v3-vm-$task_suffix"
task_network="webscan-v3-test-$task_suffix"
cleanup() {
  docker rm -fv "$task_pg" "$task_vm" >/dev/null 2>&1 || true
  docker network rm "$task_network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
task_pg_image="${WEBSCAN_V3_TEST_PG_IMAGE:-postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24}"
task_vm_image="${WEBSCAN_V3_TEST_VM_IMAGE:-victoriametrics/victoria-metrics:v1.128.0@sha256:c27e736a8aff888cf30c4f20ec648b767358694993d87e89afc6bf80f28991da}"
docker network create "$task_network" > "$task_run/network.id"
docker run -d --name "$task_pg" --network "$task_network" --network-alias postgres -p 127.0.0.1::5432 \
  -e POSTGRES_HOST_AUTH_METHOD=trust "$task_pg_image" > "$task_run/postgres.container"
docker run -d --name "$task_vm" --network "$task_network" --network-alias victoriametrics -p 127.0.0.1::8428 \
  "$task_vm_image" -retentionPeriod=1d > "$task_run/victoriametrics.container"
task_ready=0
for ((task_i=0; task_i<30; task_i++)); do
  if docker exec "$task_pg" pg_isready -U postgres >/dev/null 2>&1; then task_ready=1; break; fi
  sleep 1
done
if [[ "$task_ready" != 1 ]]; then echo '隔离 PostgreSQL 未就绪。' >&2; exit 1; fi
task_pg_address="$(docker port "$task_pg" 5432/tcp)"
task_vm_address="$(docker port "$task_vm" 8428/tcp)"
export WEBSCAN_V3_TEST_DSN="postgres://postgres@${task_pg_address}/postgres?sslmode=disable"
export WEBSCAN_V3_TEST_VM="http://${task_vm_address}"
go test -race ./internal/controlplane ./internal/nodeops ./internal/nodeconfig ./internal/nodepki ./internal/pull ./api/control/v3 -count=1 -v | tee "$task_run/integration.log"
go test ./... | tee "$task_run/go-all.log"
# Explicitly mark this disposable test executable; the default "development"
# string is intentionally not a deployable semver release or a signed artifact.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags '-X webscan/internal/deploy.Release=v3.0.0-local-test' \
  -o "$task_run/webscan-linux-amd64" ./cmd/webscan
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/agent.test" ./internal/agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/controlplane.test" ./internal/controlplane
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/nodeops.test" ./internal/nodeops
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/nodepki.test" ./internal/nodepki
task_agent_image="${WEBSCAN_V3_AGENT_TEST_IMAGE:-gzdzh/webscan-agent:v2.0.46}"
if docker image inspect "$task_agent_image" >/dev/null 2>&1; then
  docker run --rm --platform linux/amd64 --network none -v "$task_run:/v3-tests:ro" \
    -e WEBSCAN_V3_TEST_SCANNER=1 \
    --entrypoint /v3-tests/agent.test "$task_agent_image" -test.v | tee "$task_run/agent-linux.log"
  if [[ -n "${WEBSCAN_V3_SCANNER_TEST_IMAGE:-}" ]]; then
    docker run --rm --platform linux/amd64 --network none -v "$task_run:/v3-tests:ro" \
      -e WEBSCAN_V3_TEST_CLAMD=1 --entrypoint /v3-tests/agent.test "$WEBSCAN_V3_SCANNER_TEST_IMAGE" \
      -test.run '^TestScannerReadinessWithPrivateClamd$' -test.v | tee "$task_run/scanner-clamd-linux.log"
  else
    echo '未指定隔离扫描服务镜像；本轮没有运行实际 clamd 服务联调，见 scripts/Dockerfile.v3-scanner-validator。' | tee "$task_run/clamd-not-run.txt"
  fi
  docker run --rm --platform linux/amd64 --network none -v "$task_run:/v3-tests:ro" \
    --entrypoint /v3-tests/nodepki.test "$task_agent_image" -test.v | tee "$task_run/nodepki-linux.log"
  # Export a cached public fixture only; do not load into or change this daemon.
  docker image save --output "$task_run/agent-image.tar" "$task_agent_image"
  chmod 600 "$task_run/agent-image.tar"
  docker image inspect "$task_agent_image" > "$task_run/agent-image-inspect.json"
  python3 - "$task_run" <<'IMAGE_PROOF'
import hashlib, json, pathlib, sys
from scripts.v3_saved_image_config import saved_image_config
root = pathlib.Path(sys.argv[1])
image = json.loads((root / "agent-image-inspect.json").read_text())[0]
archive = root / "agent-image.tar"
hasher = hashlib.sha256()
with archive.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        hasher.update(chunk)
checksum = hasher.hexdigest()
proof = {"mode": "docker", "metrics_port": 19100, "monitor_directories": ["/"],
         "artifact_bytes": 0, "clamav": False,
         "agent_image": image["RepoDigests"][0], "image_archive_sha256": checksum,
         "image_archive_bytes": archive.stat().st_size,
         "image_config_sha256": saved_image_config(archive)}
(root / "image-proof.json").write_text(json.dumps(proof))
IMAGE_PROOF
  docker run --rm --platform linux/amd64 --network none -v "$task_run:/v3-tests:ro" \
    -e WEBSCAN_V3_TEST_BUNDLE=1 -e WEBSCAN_V3_TEST_IMAGE_ARCHIVE=1 \
    -e WEBSCAN_V3_TEST_NODE_BINARY=/v3-tests/webscan-linux-amd64 \
    --entrypoint /v3-tests/nodeops.test "$task_agent_image" -test.v | tee "$task_run/nodeops-linux.log"
  docker run --rm --platform linux/amd64 --network none --memory 256m --cpus 1.25 \
    --ulimit nofile=65536:65536 -v "$task_run:/v3-tests:ro" \
    -e WEBSCAN_V3_TEST_KERNEL_LIMITS=1 --entrypoint /v3-tests/nodeops.test "$task_agent_image" \
    -test.run '^TestKernelCgroupResourceLimitReader$' -test.v | tee "$task_run/kernel-limits-linux.log"
  if [[ -n "${WEBSCAN_V3_SYSTEMD_TEST_IMAGE:-}" ]]; then
    docker run --rm --platform linux/amd64 --network none -v "$task_run:/v3-tests:ro" \
      -e WEBSCAN_V3_TEST_SYSTEMD_ANALYZE=1 \
      --entrypoint /v3-tests/nodeops.test "$WEBSCAN_V3_SYSTEMD_TEST_IMAGE" \
      -test.run 'TestNativeDefinitionPassesSystemdAnalyze|TestSystemctlMutationRetainsOperationLock' -test.v | tee "$task_run/systemd-linux.log"
  else
    echo '未指定 systemd 校验镜像；本轮没有运行 systemd-analyze，见 scripts/Dockerfile.v3-systemd-validator。' | tee "$task_run/systemd-not-run.txt"
  fi
  WEBSCAN_V3_TEST_SERVICE_DEFINITIONS=1 go test ./internal/nodeops -run TestCompose -count=1 -v | tee "$task_run/compose-definitions.log"
  WEBSCAN_V3_TEST_DOCKER_RUNTIME=1 go test ./internal/nodeops \
    -run '^TestDockerLoadedRuntimeOnDisposableContainer$' -count=1 -v | tee "$task_run/docker-loaded-runtime.log"
  docker run --rm --platform linux/amd64 --network "$task_network" -v "$task_run:/v3-tests:ro" \
    -e WEBSCAN_V3_TEST_HELPER_INSTALL=1 \
    -e WEBSCAN_V3_TEST_AGENT_HEALTH=1 \
    -e WEBSCAN_V3_TEST_DSN='postgres://postgres@postgres:5432/postgres?sslmode=disable' \
    -e WEBSCAN_V3_TEST_VM='http://victoriametrics:8428' \
    --entrypoint /v3-tests/controlplane.test "$task_agent_image" -test.v | tee "$task_run/controlplane-linux.log"
  cat > "$task_run/node-cli-smoke.sh" <<'NODE_SMOKE'
set -eu
binary=/v3-tests/webscan-linux-amd64
mkdir -m 700 /tmp/v3-pki-smoke
"$binary" pki-v3 --action init --authority /tmp/v3-pki-smoke/authority > /tmp/pki-init.json
"$binary" pki-v3 --action issue --authority /tmp/v3-pki-smoke/authority --role node --id smoke-node --names 127.0.0.1 --output /tmp/v3-pki-smoke/node > /tmp/pki-issued.json
"$binary" pki-v3 --action revoke --authority /tmp/v3-pki-smoke/authority --certificate /tmp/v3-pki-smoke/node/identity.crt > /tmp/pki-revoked.json
"$binary" pki-v3 --action renew-crl --authority /tmp/v3-pki-smoke/authority > /tmp/pki-renewed.json
test "$(stat -c '%a' /tmp/v3-pki-smoke/authority/ca.key)" = 600
test ! -e /tmp/v3-pki-smoke/node/ca.key
grep -q '"revision":3' /tmp/pki-renewed.json
echo LINUX_OFFLINE_PKI_LIFECYCLE_OK
cat > /tmp/request.json <<'REQUEST'
{"protocol":1,"operation":"inspect","job":"cli-check","node":"cli-node","plan_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","epoch":1,"phase":"preflight","spec":{"mode":"native","metrics_port":19100,"monitor_directories":["/"],"artifact_bytes":1024,"clamav":false}}
REQUEST
"$binary" node-v3 < /tmp/request.json > /tmp/inspect.json
grep -q '"state":"absent"' /tmp/inspect.json
# Hold a fixed read-only systemctl probe long enough to simulate SSH hangup.
mkdir -p /tmp/probe-bin
cat > /tmp/probe-bin/systemctl <<'PROBE'
#!/bin/sh
touch /tmp/probe-entered
sleep 2
echo 'systemd 252'
PROBE
chmod 700 /tmp/probe-bin/systemctl
sed 's/"operation":"inspect"/"operation":"apply"/' /tmp/request.json > /tmp/apply-request.json
PATH="/tmp/probe-bin:$PATH" "$binary" node-v3 < /tmp/apply-request.json > /tmp/apply.json 2>/tmp/apply-error &
probe_pid=$!
for probe_i in 1 2 3 4 5 6 7 8 9 10; do
  if [ -f /tmp/probe-entered ]; then break; fi
  sleep 1
done
test -f /tmp/probe-entered
kill -HUP "$probe_pid"
probe_exit=0
wait "$probe_pid" || probe_exit=$?
# This isolated container has no running systemd; it must report that failure,
# survive hangup and persist the failed probe without touching existing services.
test "$probe_exit" = 1
grep -q '"code":"preflight-failed"' /tmp/apply.json
grep -q '"code":"linux-amd64"' /tmp/apply.json
"$binary" node-v3 < /tmp/request.json > /tmp/inspect-after.json
grep -q '"state":"absent"' /tmp/inspect-after.json
sed 's/"phase":"preflight"/"phase":"activate"/' /tmp/request.json > /tmp/unsupported.json
probe_exit=0
"$binary" node-v3 < /tmp/unsupported.json > /tmp/unsupported-result.json 2>/tmp/unsupported-error || probe_exit=$?
test "$probe_exit" = 1
grep -q '"code":"executor-unavailable"' /tmp/unsupported-result.json
echo LINUX_NODE_HELPER_PREFLIGHT_HANGUP_AND_UNSUPPORTED_PHASE_OK
NODE_SMOKE
  docker run --rm --platform linux/amd64 --network none -v "$task_run:/v3-tests:ro" \
    --entrypoint /bin/sh "$task_agent_image" /v3-tests/node-cli-smoke.sh | tee "$task_run/node-cli-linux.log"
else
  echo 'Linux Agent 和主控仅完成编译；未找到测试镜像，运行验收未执行。' | tee "$task_run/agent-linux-not-run.txt"
fi
(cd web && npm run typecheck && npm test && npm run build) | tee "$task_run/frontend.log"
echo "本地验证记录：$task_run"
echo '这不是 10,000 台实际采集、72 小时稳定性或三台独立机器 HA 验收。'
