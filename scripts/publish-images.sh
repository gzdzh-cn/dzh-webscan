#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
go run ./cmd/release --action publish --release "${1:?Usage: publish-images.sh RELEASE [YAML]}" --config "${2:-webscan.yaml}"
