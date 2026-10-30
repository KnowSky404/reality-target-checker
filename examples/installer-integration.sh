#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copy this example into your installer and pin BOTH version and trusted digest.
set -euo pipefail

readonly version=v0.3.0
readonly repository=KnowSky404/reality-target-checker
readonly asset=reality-target-checker.sh

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || die '用法: RTC_SHA256=<已审阅的固定摘要> installer-integration.sh DOMAIN [ORIGIN_IP]'
[[ ${RTC_SHA256:-} =~ ^[a-fA-F0-9]{64}$ ]] || die '必须设置 RTC_SHA256：从可信且已审阅的固定版本取得 SHA256，不可自动信任同次下载的新摘要'
for dependency in curl sha256sum jq bash mktemp awk; do
  command -v "$dependency" >/dev/null || die "缺少依赖: $dependency"
done
umask 077
integration_tmp=$(mktemp -d "${TMPDIR:-/tmp}/rtc-installer.XXXXXXXX")
trap 'rm -rf -- "$integration_tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
base_url="https://github.com/$repository/releases/download/$version"
for file in "$asset" SHA256SUMS; do
  curl --disable --fail --silent --show-error --location --max-redirs 3 \
    --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 \
    --output "$integration_tmp/$file" "$base_url/$file" || die "下载 $version/$file 失败；首版 Tag 发布前请使用仓库本地脚本测试"
done
release_digest=$(awk '$2 == "reality-target-checker.sh" && length($1) == 64 {n++; digest=$1} END {if(n==1) print digest}' "$integration_tmp/SHA256SUMS")
[[ ${release_digest,,} == "${RTC_SHA256,,}" ]] || die 'Release 校验文件与预先固定的可信摘要不符'
printf '%s  %s\n' "${RTC_SHA256,,}" "$asset" >"$integration_tmp/PINNED_SHA256SUMS"
(cd "$integration_tmp" && sha256sum --check --status PINNED_SHA256SUMS) || die '脚本 SHA256 验证失败，拒绝执行'

args=(check "$1" --json --timeout 5)
if [[ $# == 2 ]]; then args+=(--origin-ip "$2"); fi
rc=0
bash "$integration_tmp/$asset" "${args[@]}" >"$integration_tmp/result.json" || rc=$?
# Validate the schema AND exit/status agreement. Never infer acceptance from a
# network error, empty stdout, JSON parsing failure, or merely basic_tls=PASS.
jq -e --arg version "${version#v}" --argjson rc "$rc" '
  .schema_version == "1.0" and .tool_version == $version and
  .summary.exit_code == $rc and
  ((($rc == 0 or $rc == 3) and .summary.basic_tls == "PASS" and
     .summary.compatibility == "PASS" and .selection.complete == true and
     (.endpoints | length) > 0 and
     .summary.status == (if $rc == 0 then "PASS" else "WARN" end)) or
   ($rc == 1 and .summary.status == "FAIL") or
   ($rc == 2 and .summary.status == "UNKNOWN"))
' "$integration_tmp/result.json" >/dev/null || die '检测器输出无效或与退出码不一致，停止安装器的候选目标选择'
cat "$integration_tmp/result.json"
case $rc in
  0) printf '候选检查通过，可交由安装器的后续策略处理。\n' >&2 ;;
  1) printf '候选基础条件失败，拒绝使用。\n' >&2 ;;
  2) printf '检测未完成，停止选择；不能视为合格。\n' >&2 ;;
  3) printf '基础检查通过，但附加风险或未知项需要审阅；本示例保守停止。\n' >&2 ;;
  *) die '未识别的检测器退出码' ;;
esac
exit "$rc"
