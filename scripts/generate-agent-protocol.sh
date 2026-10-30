#!/usr/bin/env bash
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$task_root"
command -v protoc >/dev/null || { echo '请先安装 protoc。' >&2; exit 1; }
export GOBIN="$task_root/.cache/v3-tools"
mkdir -p "$GOBIN"
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.9
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
export PATH="$GOBIN:$PATH"
protoc --go_out=. --go_opt=module=webscan \
  --go-grpc_out=. --go-grpc_opt=module=webscan api/agent/v1/agent.proto
