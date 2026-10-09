#!/usr/bin/env bash
# Prepare immutable GitHub installer assets after the source commit is finalized.
set -euo pipefail
TASK_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TASK_ROOT"
TASK_RELEASE=${1:?Usage: package-install.sh RELEASE SOURCE_COMMIT}
TASK_COMMIT=$(git rev-parse "${2:?SOURCE_COMMIT required}^{commit}")
[[ $TASK_RELEASE =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && $TASK_COMMIT =~ ^[a-f0-9]{40}$ ]] || { echo '版本号或源码提交无效' >&2; exit 1; }
TASK_DIR="dist/$TASK_RELEASE"
[[ -f "$TASK_DIR/deploy-webscan.sh" && -f "$TASK_DIR/release.json" ]] || { echo '请先构建、验证并发布对应镜像。' >&2; exit 1; }
# Public assets come from the exact published Git tree, never from actual YAML.
git show "$TASK_COMMIT:install.sh" > "$TASK_DIR/install.sh"
git show "$TASK_COMMIT:webscan.example.yaml" > "$TASK_DIR/webscan.example.yaml"
TASK_SCRIPT_SHA=$(shasum -a 256 "$TASK_DIR/deploy-webscan.sh" | awk '{print $1}')
TASK_GIT_SCRIPT_SHA=$(git show "$TASK_COMMIT:deploy-webscan.sh" | shasum -a 256 | awk '{print $1}')
[[ $TASK_SCRIPT_SHA == "$TASK_GIT_SCRIPT_SHA" ]] || { echo '提交内的部署脚本与发布产物不一致。' >&2; exit 1; }
TASK_EXAMPLE_SHA=$(shasum -a 256 "$TASK_DIR/webscan.example.yaml" | awk '{print $1}')
cat > "$TASK_DIR/install-manifest.txt" <<MANIFEST
release=$TASK_RELEASE
source_commit=$TASK_COMMIT
script_sha256=$TASK_SCRIPT_SHA
example_sha256=$TASK_EXAMPLE_SHA
MANIFEST
chmod 700 "$TASK_DIR/install.sh"
bash -n "$TASK_DIR/install.sh"
printf 'GitHub 安装附件已准备：%s（源码 %s）\n' "$TASK_RELEASE" "$TASK_COMMIT"
