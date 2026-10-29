#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tag=${1:-}
[[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  printf '需要稳定 SemVer Tag，例如 v0.1.0\n' >&2
  exit 2
}
[[ $tag == "v$(bash reality-target-checker.sh --version)" ]] || {
  printf 'Tag 与脚本版本不一致\n' >&2
  exit 2
}
mkdir -p dist
cp reality-target-checker.sh LICENSE dist/
chmod 755 dist/reality-target-checker.sh
(cd dist && sha256sum reality-target-checker.sh LICENSE >SHA256SUMS && sha256sum --check SHA256SUMS)
