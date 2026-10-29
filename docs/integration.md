# 安全接入一键安装脚本

## 版本和资产

生产环境固定 `v0.1.0` 这样的稳定 SemVer Tag，同时固定该版本脚本的可信 SHA256。Release 提供脚本、`SHA256SUMS` 和 MIT `LICENSE`。当前尚未推送 v0.1.0 Tag，下载地址在正式发布后才有效；开发时先从本地仓库运行。

不要直接执行未经校验的远程脚本，不要把 main 分支当作生产入口。只把同次下载的脚本与同次下载的摘要比较，不能在发布渠道被替换时提供独立保护；应在审阅版本时从可信渠道确认摘要，写入安装器或其受控配置。SHA256 本身不是发布者签名。

正式发布后手工下载、先校验再执行的步骤如下（在空目录操作）：

```bash
version=v0.1.0
base="https://github.com/KnowSky404/reality-target-checker/releases/download/$version"
curl --disable -fL --proto '=https' --proto-redir '=https' --max-time 60 \
  -o reality-target-checker.sh "$base/reality-target-checker.sh"
curl --disable -fL --proto '=https' --proto-redir '=https' --max-time 60 \
  -o SHA256SUMS "$base/SHA256SUMS"
# 手动核对 SHA256SUMS 中的脚本摘要与独立可信的已固定值后，再做文件校验：
grep -E '^[a-f0-9]{64}  reality-target-checker\.sh$' SHA256SUMS > SCRIPT_SHA256SUMS
test "$(wc -l < SCRIPT_SHA256SUMS)" -eq 1
sha256sum --check SCRIPT_SHA256SUMS
bash reality-target-checker.sh --version
```

上面是逐步手动操作说明。自动化应使用 [完整示例](../examples/installer-integration.sh)，它会强制要求预先固定的 `RTC_SHA256`、核对版本摘要、验证下载文件，再执行。摘要不匹配时下载的代码不会运行。

```bash
RTC_SHA256='<替换为可信的固定版本脚本 SHA256>' \
  bash examples/installer-integration.sh example.com 192.0.2.20
```

最后的 IP 应为用户确认的 VPS 公网 IP；可省略，此时同 ASN 判断为 UNKNOWN。示例仅输出检测 JSON 和决策提示，不自动写入现有 sing-box 配置，不安装、停止或重启服务，也不更改 DNS、路由、TUN、代理或防火墙。

## JSON 1.0 契约

成功产生检测报告时始终包含下列字段：

| 字段 | 约定 |
| --- | --- |
| schema_version | 字符串 `"1.0"`，结构版本，独立于工具版本 |
| tool_version | 字符串，例如 `"0.1.0"` |
| target / sni / port | 规范化域名、实际 TLS SNI、固定端口 443 |
| timeout_seconds / tools | 每次操作上限、OpenSSL/curl 版本信息 |
| origin | 用户指定 IP、单一 ASN（十进制字符串或 null）、组织和 `user_supplied_only` 来源标记 |
| selection | `scope` 为 `dns` / `explicit_ip`；`complete` 表示选定范围是否完整；`limit=16`；`reason` 解释范围限制 |
| dns | `a`、`aaaa`、`cnames` 数组；`checks` 含 A / AAAA / CNAME 的状态和原因 |
| endpoints | 每 IP 一个对象，包含 ip、family（4/6）、asn、organization、certificate、http、checks |
| risks | 各端点 WARN 项的数组，含 ip、id、status、reason；不是所有不确定性的集合 |
| unknowns | DNS 和各端点 UNKNOWN 项，含 scope、id、reason；空数组才表示没有未知项 |
| summary | basic_tls、compatibility、ancillary、status、exit_code、reason |

`endpoints[].certificate` 含 `not_before` / `not_after`，无法读取时为空字符串。`http` 含 `status_code`（整数或 null）、`version`、`location`（无法读取时为空字符串）。ASN 不转成整数，避免消费者在不同语言里丢失精度或错误处理 null。IPv6 输出为 8 组小写十六进制规范形式。

固定检查 ID：`tcp443`、`tls13`、`alpn_h2`、`cert_chain`、`cert_san`、`cert_validity`、`x25519`、`cert_expiry`、`https_response`、`http_redirect`、`asn`、`same_asn`、`cdn`。不要依赖检查数组顺序或原因文字。`risks` 为空不等于没有未知指标，必须同时检查 `unknowns` 和 `selection`。

参数、依赖、临时目录等启动错误返回 2，JSON 模式会输出错误 envelope：

```json
{"schema_version":"1.0","tool_version":"0.1.0","target":null,"sni":null,"error":{"code":"USAGE","message":"..."},"summary":{"status":"UNKNOWN","exit_code":2}}
```

错误报告没有 endpoints/dns 等完整报告字段。缺少 jq 时也会输出静态合法 JSON，错误代码为 DEPENDENCY。诊断文字始终进入 stderr。进程被信号中断、系统终止或文件系统写入失败时可能没有完整报告，调用方必须检查 JSON 和退出码。

1.x 结构可增加字段或检查 ID；消费者应忽略不认识的附加字段，对未知状态保守拒绝。字段删除、类型或语义不兼容变化会升级结构主版本。只比较 reason 文字或假定所有未来 schema 都可用不在兼容承诺内。

## 退出码和策略

捕获原始退出码，再解析 JSON；不要用 jq 管道覆盖检测器状态：

```bash
rc=0
bash ./reality-target-checker.sh check example.com --json --timeout 5 > result.json || rc=$?
jq -e '.schema_version == "1.0" and (.summary.status | type == "string")' result.json >/dev/null || exit 2
case "$rc" in
  0) printf '所选范围的全部检查通过\n' ;;
  1) printf '基础条件明确失败，拒绝候选\n' >&2; exit 1 ;;
  2) printf '无法完成，停止选择\n' >&2; exit 2 ;;
  3) printf '基础通过但有风险或未知项，需要显式审阅\n' >&2; exit 3 ;;
  *) printf '进程中断或异常，停止选择\n' >&2; exit 2 ;;
esac
```

完整示例还会核对工具版本、退出码与报告是否一致，以及通过时是否有完整地址集合与非空端点。遇到不合法 JSON、未知结构、退出状态不一致、下载失败或校验失败时不继续选择。

首版 CDN 常为 UNKNOWN / WARN，因此候选通常返回 3。若第三方安装器决定接受特定附加风险，应在自己的策略中明确逐项审阅，只在 `basic_tls=PASS`、`compatibility=PASS`、`selection.complete=true` 且所有端点符合预期时才进入该策略；不得将所有非 1 的退出码当作通过。

整次调用若需要上限，可在安装器外层使用 GNU `timeout`。外层 124/137 或信号 130/143 一律当作无法完成，而不是可用；报告文件也可能不完整。网络异常不能触发自动接受默认域名。

## 维护和发布

修改脚本的 VERSION，保持文档和固定版本示例一致，运行 `bash scripts/check.sh`；`bash scripts/package-release.sh v0.1.0` 可在本地生成并校验 dist 资产。正式决定发布后推送相同版本的稳定 Tag。Release 工作流会重新执行全部测试，校验 Tag 与脚本版本，再用最小写入权限发布资产；不会强制推送或覆盖 Release。发布者应避免移动已发布 Tag 或替换相同版本资产。

需要升级的安装器应同时审阅新版本、变更的 JSON 契约、固定版本 URL 和新摘要，再更新自身固定值。后续可以增加签名/来源证明；当前不宣称已提供这类保证。
