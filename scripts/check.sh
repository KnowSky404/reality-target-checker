#!/usr/bin/env bash
# Development dependencies only; the shipped checker is standalone.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
files=(reality-target-checker.sh examples/*.sh scripts/*.sh tests/helpers/mock-command)
for file in "${files[@]}"; do bash -n "$file"; done
shellcheck "${files[@]}"
shellcheck -s bash tests/*.bats
shfmt -d -i 2 -ci "${files[@]}" tests/*.bats
bats tests
python3 -m unittest discover -s tests -p 'test_*.py' -v
