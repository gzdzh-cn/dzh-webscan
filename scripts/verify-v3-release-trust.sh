#!/usr/bin/env bash
# Offline, disposable validation only. No production config, database, SSH,
# registry upload, Feishu or SMTP; test keys die with their containers.
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$task_root"
mkdir -p .cache/verification/v3
task_run="$(mktemp -d "$task_root/.cache/verification/v3/release-trust.XXXXXX")"
task_image="${WEBSCAN_V3_AGENT_TEST_IMAGE:-sha256:c7b76b7061936ada0706593e3edc3ff94fa8dad1b1bc82d2e4f5094f69afcf3f}"
docker image inspect "$task_image" > "$task_run/test-image.json"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags '-X webscan/internal/deploy.Release=v3.0.0-local-test' \
  -o "$task_run/webscan" ./cmd/webscan
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c \
  -o "$task_run/controlplane.test" ./internal/controlplane
task_suffix="$(basename "$task_run")"
task_tests="webscan-v3-trust-tests-$task_suffix"
task_cli="webscan-v3-trust-cli-$task_suffix"
cleanup() { docker rm -fv "$task_tests" "$task_cli" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker run --rm --name "$task_tests" --platform linux/amd64 --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
  --tmpfs /trust-lowdisk:rw,noexec,nosuid,size=1m,mode=700 \
  -e WEBSCAN_V3_TRUST_LOW_DISK_DIRECTORY=/trust-lowdisk \
  -v "$task_run:/validation:ro" --entrypoint /validation/controlplane.test "$task_image" \
  -test.run 'TestOfflineRelease|TestTrustPublication|TestVaultTools|TestReleaseOptions|TestDeploymentTrustConfiguration|TestVaultRejects|TestSignedRelease|TestDeploymentManifest' \
  -test.v | tee "$task_run/integration.log"

docker run --rm -i --name "$task_cli" --platform linux/amd64 --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m,mode=1777 \
  -v "$task_run:/validation:ro" --entrypoint /bin/sh "$task_image" -eu <<'TRUST_CLI' | tee "$task_run/cli.log"
umask 077
mkdir -m 700 /tmp/trust-lab
mkdir -m 700 /tmp/trust-lab/artifacts
cp /validation/webscan /tmp/trust-lab/artifacts/webscan
chmod 700 /tmp/trust-lab/artifacts/webscan
# Only a checksum/signing fixture, not a deployable scanner bundle.
tar -czf /tmp/trust-lab/artifacts/fixture-native.tar.gz -C /tmp/trust-lab/artifacts webscan
/validation/webscan release-v3 --action init-key --output /tmp/trust-lab/signing
/validation/webscan vault-v3 --action init-key --output /tmp/trust-lab/vault
/validation/webscan vault-v3 --action check --key-file /tmp/trust-lab/vault/vault.key
/validation/webscan release-v3 --action sign \
  --key-file /tmp/trust-lab/signing/signing.key --release v3.0.0-local-test \
  --helper /tmp/trust-lab/artifacts/webscan --native-bundle /tmp/trust-lab/artifacts/fixture-native.tar.gz \
  --agent-image docker.io/example/webscan-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --output /tmp/trust-lab/signed
/validation/webscan release-v3 --action verify \
  --public-key-file /tmp/trust-lab/signing/signing.pub \
  --manifest /tmp/trust-lab/signed/release.json --signature /tmp/trust-lab/signed/release.sig \
  --helper /tmp/trust-lab/artifacts/webscan --native-bundle /tmp/trust-lab/artifacts/fixture-native.tar.gz
cat > /tmp/trust-lab/control.yaml <<'TRUST_CONFIG'
config_version: 3
central:
  topology: single
  instance_id: isolated-trust-cli
  public_url: https://monitor.example.test
database:
  dsn_file: /tmp/trust-lab/database-does-not-exist
metrics:
  write_url: http://127.0.0.1:8428
  query_url: http://127.0.0.1:8428
deployment_trust:
  vault_key_file: /tmp/trust-lab/vault/vault.key
  release_public_key_file: /tmp/trust-lab/signing/signing.pub
  release_manifest_file: /tmp/trust-lab/signed/release.json
  release_signature_file: /tmp/trust-lab/signed/release.sig
  helper_file: /tmp/trust-lab/artifacts/webscan
  native_bundle_file: /tmp/trust-lab/artifacts/fixture-native.tar.gz
TRUST_CONFIG
/validation/webscan control-v3 --config /tmp/trust-lab/control.yaml --action check-deployment-trust
cp /tmp/trust-lab/vault/vault.key /tmp/trust-lab/previous-key
if /validation/webscan vault-v3 --action init-key --output /tmp/trust-lab/vault > /tmp/trust-lab/expected-error 2>&1; then
  echo 'FAIL existing key overwritten'; exit 1
fi
cmp /tmp/trust-lab/vault/vault.key /tmp/trust-lab/previous-key
printf 'changed' >> /tmp/trust-lab/artifacts/webscan
if /validation/webscan control-v3 --config /tmp/trust-lab/control.yaml --action check-deployment-trust > /tmp/trust-lab/expected-error 2>&1; then
  echo 'FAIL changed helper accepted'; exit 1
fi
echo 'PASS real CLI: signing, independent verification, vault identity, no DB/network, no overwrite, changed artifact refusal'
TRUST_CLI
printf 'Offline validation evidence: %s\n' "$task_run"
