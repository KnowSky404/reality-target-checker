#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tag=${1:-}
[[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  printf '需要稳定 SemVer Tag，例如 v0.3.0\n' >&2
  exit 2
}
[[ $tag == "v$(bash reality-target-checker.sh --version)" ]] || {
  printf 'Tag 与脚本版本不一致\n' >&2
  exit 2
}
mkdir -p dist
assets=(reality-target-checker.sh reality-target-discover.py reality-target-sources.py reality-target-state.py reality-target-kernel.py LICENSE)
cp "${assets[@]}" dist/
chmod 755 dist/reality-target-checker.sh
for asset in "${assets[@]:1}"; do chmod 644 "dist/$asset"; done
tar --sort=name --format=ustar --mtime='@0' --owner=0 --group=0 --numeric-owner \
  -czf dist/reality-target-discovery.tar.gz -C dist "${assets[@]}"
(cd dist && sha256sum "${assets[@]}" reality-target-discovery.tar.gz >SHA256SUMS && sha256sum --check SHA256SUMS)
