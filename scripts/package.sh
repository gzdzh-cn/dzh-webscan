#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
TASK_VERSION=${1:?Usage: package.sh RELEASE}
[[ $(go version) == 'go version go1.26.3 '* ]] || { echo 'Go 1.26.3 required' >&2; exit 1; }
mkdir -p "$TASK_ROOT/dist/$TASK_VERSION"
cd "$TASK_ROOT"
# Production pages are built locally before Go embeds them. Fail closed.
command -v npm >/dev/null || { echo '前端构建需要本地 Node.js 和 npm' >&2; exit 1; }
(cd web && npm ci --no-audit --no-fund && npm run typecheck && npm test && npm run build)
[[ -d internal/website/ui/assets ]] && grep -q '/assets/' internal/website/ui/index.html || { echo '前端产物缺失，拒绝打包占位页面' >&2; exit 1; }
go test ./...
cp config/bootstrap-ca.crt "dist/$TASK_VERSION/bootstrap-ca.crt"
printf "*\n!webscan\n!bootstrap-ca.crt\n!native-tools.sh\n" > "dist/$TASK_VERSION/.dockerignore"
TASK_BUILD_COMMIT=$(git rev-parse HEAD)
if [[ -n $(git status --porcelain -- internal cmd scripts web/src go.mod go.sum Dockerfile.release) ]]; then TASK_BUILD_COMMIT="$TASK_BUILD_COMMIT-dirty"; fi
TASK_BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TASK_BUILD_SOURCE=$(git ls-files -z --cached --others --exclude-standard -- internal cmd scripts web/src go.mod go.sum Dockerfile.release config | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}')
export WEBSCAN_BUILD_FLAGS="-X webscan/internal/deploy.BuildCommit=$TASK_BUILD_COMMIT -X webscan/internal/deploy.BuildTime=$TASK_BUILD_TIME -X webscan/internal/deploy.BuildSource=$TASK_BUILD_SOURCE"
printf '{"release":"%s","commit":"%s","built_at":"%s","source_digest":"%s"}\n' "$TASK_VERSION" "$TASK_BUILD_COMMIT" "$TASK_BUILD_TIME" "$TASK_BUILD_SOURCE" > "dist/$TASK_VERSION/build-info.json"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X webscan/internal/deploy.Release=$TASK_VERSION $WEBSCAN_BUILD_FLAGS" -o "dist/$TASK_VERSION/webscan" ./cmd/webscan
bash scripts/package-bootstrap.sh "$TASK_VERSION"
cp scripts/native-tools.sh "dist/$TASK_VERSION/native-tools.sh"
cp install.sh "dist/$TASK_VERSION/install.sh"
chmod 700 "dist/$TASK_VERSION/install.sh"
printf 'Built %s\n' "$TASK_VERSION"
