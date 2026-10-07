#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
TASK_VERSION=${1:?Usage: package.sh RELEASE}
[[ $(go version) == 'go version go1.26.3 '* ]] || { echo 'Go 1.26.3 required' >&2; exit 1; }
mkdir -p "$TASK_ROOT/dist/$TASK_VERSION"
cd "$TASK_ROOT"
cp config/bootstrap-ca.crt "dist/$TASK_VERSION/bootstrap-ca.crt"
printf "*\n!webscan\n!bootstrap-ca.crt\n" > "dist/$TASK_VERSION/.dockerignore"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Release=$TASK_VERSION -X webscan/internal/deploy.Release=$TASK_VERSION" -o "dist/$TASK_VERSION/bootstrap" ./cmd/bootstrap
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X webscan/internal/deploy.Release=$TASK_VERSION" -o "dist/$TASK_VERSION/webscan" ./cmd/webscan
TASK_SHA=$(shasum -a 256 "dist/$TASK_VERSION/bootstrap" | awk '{print $1}')
cat > "dist/$TASK_VERSION/deploy-webscan.sh" <<HEADER
#!/usr/bin/env bash
# Webscan $TASK_VERSION. Embedded Linux amd64 bootstrap; no Python or Go needed.
set -euo pipefail
umask 077
TASK_DEPLOY_DIR=\$(cd -- "\$(dirname -- "\$0")" && pwd)
cd "\$TASK_DEPLOY_DIR"
TASK_BOOT_DIR=\$(mktemp -d /tmp/webscan-bootstrap.XXXXXXXX)
trap 'rm -rf -- "\$TASK_BOOT_DIR"' EXIT
TASK_SHOW_PROGRESS=1
for TASK_ARGUMENT in "\$@"; do
  case "\$TASK_ARGUMENT" in --dry-run|--config-help|--help|-h) TASK_SHOW_PROGRESS=0;; esac
done
if [[ \$TASK_SHOW_PROGRESS == 1 ]]; then printf '[引导00][进行][主服务器] 正在解压 Go 引导程序……\n'; fi
base64 -d <<'WEBSCAN_BOOTSTRAP' | gzip -dc > "\$TASK_BOOT_DIR/bootstrap"
HEADER
gzip -n -c "dist/$TASK_VERSION/bootstrap" | base64 >> "dist/$TASK_VERSION/deploy-webscan.sh"
cat >> "dist/$TASK_VERSION/deploy-webscan.sh" <<FOOTER
WEBSCAN_BOOTSTRAP
[[ \$(sha256sum "\$TASK_BOOT_DIR/bootstrap" | cut -d ' ' -f1) == '$TASK_SHA' ]] || { echo 'bootstrap checksum mismatch' >&2; exit 1; }
chmod 700 "\$TASK_BOOT_DIR/bootstrap"
if [[ \$TASK_SHOW_PROGRESS == 1 ]]; then printf '[引导00][成功][主服务器] 引导程序校验通过，正在进入部署管理。\n'; fi
"\$TASK_BOOT_DIR/bootstrap" "\$@"
FOOTER
chmod 700 "dist/$TASK_VERSION/deploy-webscan.sh"
printf 'Built %s\n' "$TASK_VERSION"
