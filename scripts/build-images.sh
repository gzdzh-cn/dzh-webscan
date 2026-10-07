#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
go run ./cmd/release --action build --release "${1:?Usage: build-images.sh RELEASE [YAML]}" --config "${2:-webscan.yaml}"
