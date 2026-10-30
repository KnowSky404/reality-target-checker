# 安全接入一键安装脚本

## 版本和资产

生产环境固定 `v0.3.0` 这样的稳定 SemVer Tag，同时固定执行资产的可信 SHA256。Release 提供 Bash、`reality-target-discover.py`、`reality-target-sources.py`、`reality-target-state.py`、`reality-target-kernel.py`、MIT `LICENSE`、完整 `reality-target-discovery.tar.gz` 和 `SHA256SUMS`。清单分别校验六个单文件与 bundle；bundle 仅含这六个文件，不包含 SHA256SUMS 或 Xray 内核。本次不创建 Tag，下载地址在对应版本正式发布后才有效；开发时先从本地仓库运行。

不要直接执行未经校验的远程脚本，不要把 main 分支当作生产入口。只把同次下载的脚本与同次下载的摘要比较，不能在发布渠道被替换时提供独立保护；应在审阅版本时从可信渠道确认摘要，写入安装器或其受控配置。SHA256 本身不是发布者签名。

正式发布后手工下载、先校验再执行的步骤如下（在空目录操作）：

```bash
version=v0.3.0
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

仅调用 `check` 的安装器继续只下载 Bash；发布清单增加文件不会改变脚本摘要的匹配规则。基础 CIDR `discover` 需要 Bash 和核心 Python；ASN/清单导入需要 sources 模块，缓存/续扫需要 state 模块，可选 Xray 自检需要 kernel 模块和用户已安装的内核。所有模块与 Bash 放在同一目录并逐个固定可信摘要，或先校验完整 bundle 的独立可信摘要再解包。不得仅校验 Bash 后直接执行未经校验的 Python 文件。发现模式需要 Python >= 3.9 和 jq，没有第三方 Python 包依赖。

完整发现能力的 bundle 下载示例（在空目录操作，先从独立可信渠道固定摘要；此命令仅下载与解包，不扫描）：

```bash
(
  set -euo pipefail
  [[ ${RTC_BUNDLE_SHA256:-} =~ ^[a-fA-F0-9]{64}$ ]] || exit 2
  version=v0.3.0
  bundle=reality-target-discovery.tar.gz
  base="https://github.com/KnowSky404/reality-target-checker/releases/download/$version"
  curl --disable -fL --proto '=https' --proto-redir '=https' --max-time 60 \
    -o "$bundle" "$base/$bundle"
  printf '%s  %s\n' "${RTC_BUNDLE_SHA256,,}" "$bundle" > PINNED_BUNDLE_SHA256SUMS
  sha256sum --check PINNED_BUNDLE_SHA256SUMS
  tar -xzf "$bundle"
  bash reality-target-checker.sh --version
)
```

上述 bundle 需要 GNU tar/gzip 解包；SHA 校验失败时不得继续解包或执行。自动化脚本应使用 `set -euo pipefail` 或显式检查每一步退出码。仅下载同次发布的 SHA256SUMS 不能替代预先固定的可信摘要。

## check JSON 1.0 契约

成功产生检测报告时始终包含下列字段：

| 字段 | 约定 |
| --- | --- |
| schema_version | 字符串 `"1.0"`，结构版本，独立于工具版本 |
| tool_version | 字符串，例如 `"0.3.0"` |
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
{"schema_version":"1.0","tool_version":"0.3.0","target":null,"sni":null,"error":{"code":"USAGE","message":"..."},"summary":{"status":"UNKNOWN","exit_code":2}}
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

## discover JSON 1.0 契约

`discover` 使用独立报告类型，顶层有 `report_type: "discovery"`、`schema_version: "1.0"` 和工具版本。不要把它作为上面的单域名 check 报告解析，也不要把发现任务退出码直接套用到单个候选。

| 字段 | 约定 |
| --- | --- |
| scope / plan | 明确选择的 CIDR 或有限清单、主机数、预算、过滤的输入 IP、ASN 快照及源 IP；清单模式的 cidr 可为空 |
| scan | 本次策略执行是否完整、完成数量、耗时、停止或截断原因；不代表域名发现全集完整 |
| hosts | 每 IP 的 TCP、无 SNI TLS 和 PTR 发现证据、域名来源及有限通配线索 |
| candidates | 去重 IP/SNI 对、sources、eligible、dns_binding、原 check 报告或复核错误；0.3.0 附加 measurements 和 statistics |
| summary | 发现任务状态及退出码 |

`eligible=true` 需要所有计划样本的实际基础 TLS 和候选兼容性均通过；启用 Xray 自检时，每个相关样本还须自检 PASS。原 check 可返回 WARN/3，其 `risks` 和 `unknowns` 仍应逐项审阅。单个 FAIL 候选不会取消其他候选。`dns_binding` 为 MATCH、DIFFERENT 或 UNKNOWN：IPv4 使用本次 A 查询，IPv6 使用 AAAA；定向 IP 验证通过不保证以域名作为 target 时仍连到同一地址。

0.3.0 保留候选的原字段，并附加以下证据；不能仅根据最后一个 `report` 接受多样本候选：

| 字段 | 约定 |
| --- | --- |
| measurements | 每个计划样本的报告、eligible、错误、DNS 绑定和可选 kernel 结果 |
| observed_at / evidence_source | 样本观测 Unix 秒及 live/checkpoint 等来源；未开始为 null/not_started，恢复保留原时间 |
| statistics | planned、已生成 checker 报告的 completed、passed、success_rate、median_ms、spread_ms、metric |
| statistics.metric | 固定为 checker_wall_ms，包含 checker 的 DNS/TLS/HTTP/ASN 总耗时；不是 RTT，不包含节流排队时间 |
| measurements[].kernel | 可选 Xray 端到端自检 PASS/UNKNOWN、固定错误、版本及耗时；不含 UUID、密钥或原始日志 |

`--samples` 默认为 1（最大 5），`--sample-interval` 默认为 0。多样本模式按合格性、成功率、中位耗时、波动和 IP/SNI 排序；单样本保留合格性与 IP/SNI 顺序。部分成功、未完成或 UNKNOWN 不会被另一个成功样本覆盖。

发现退出码：0 为完整且有无附加风险的合格候选；3 为完整且存在带风险的合格候选；1 为完整且没有合格候选、没有待确认复核；2 为参数/依赖问题、执行不完整或存在 UNKNOWN 复核。总超时和候选截断不能报告为完整无结果；即使退出 2，已确认候选仍会保留。130/143 为中断，调用方必须保守处理。完整参数、资源边界和验收见 [SPEC](SPEC-discovery.md)。

```bash
rc=0
bash ./reality-target-checker.sh discover 192.0.2.0/24 --json > discovery.json || rc=$?
jq -e '.report_type == "discovery" and .schema_version == "1.0"' discovery.json >/dev/null || exit 2
jq '.candidates[] | select(.eligible) | {ip, sni, sources, dns_binding, report}' discovery.json
printf 'discovery exit=%s\n' "$rc"
```

示例地址需替换为明确选择的实际范围；此示例仅展示候选，不自动接受风险或修改代理配置。`--rate` 是任务启动频率，一个复核包含多个网络操作；总时间由 `--deadline` 限制。

## ASN 计划、导入与恢复

`discover --asn AS64500 --json` 或 `--asn-from-ip IP` 在未明确选择地址时默认仅生成 `report_type: "discovery_plan"`。计划成功退出 0 只表示范围查询/规划完成，不是目标探测通过，计划没有 candidates/scan 的端口结论。`requires_selection` 表示仍需选择范围；scope 同时提供预算与是否需要已知 IPv6 地址。MOAS、无法验证或失效的快照返回 UNKNOWN；大于执行预算的纯计划可保留 WARN。消费者必须先区分报告类型：

```bash
kind=$(jq -r '.report_type // "error"' discovery.json)
case "$kind" in
  discovery_plan) jq '{requires_selection, asn, scope, summary}' discovery.json ;;
  discovery) jq '.candidates[] | {ip, sni, eligible, measurements, statistics}' discovery.json ;;
  *) exit 2 ;;
esac
```

主动执行可显式给出 `--include-cidr`（可重复）或本地 `--known-ips` / `--seeds` 清单；同时给出两种清单时取去重并集，再按 CIDR/ASN 范围过滤。ASN/源 IP 是明确的元数据查询输入，不会触发自动出口 IP 发现。IPv6 前缀只过滤清单；单个 `/128` 可作为明确的已知地址，不能枚举更大 IPv6 前缀。

输入适配器读取有限的本地 JSON、JSONL 或带表头 CSV，`--seed-format` 为 generic/censys/shodan/dns，不在线调用付费平台。通用记录使用 ip 和 sni（或 hostname/domain），可附 source、observed_at。历史时间和提供商的 TLS/ASN 标记只属于种子来源，最终仍固定 IP/SNI 验证；不自动跟随导出文件中的分页链接。

`--cache-dir` 启用 ASN 元数据与成功非空发现种子缓存，不缓存握手验证。`--checkpoint PATH` 持久保存完成事件，`--resume` 才能复用同一任务的明确结果；新任务不覆盖已有文件。默认 TTL 均为 3600 秒，由 `--cache-ttl` / `--state-ttl` 控制。缓存命中和恢复均保留原观测时间；恢复的样本标记 checkpoint，UNKNOWN、过期记录重新执行。源范围、输入内容、采样、工具/信任库或内核身份变化会拒绝复用；仅 deadline、并发、任务启动速率可以调整。

缓存与 checkpoint 是用户明确选择的私有 SQLite 文件，不是可执行输入。错误权限、symlink、损坏、未来时间或版本/指纹不匹配会明确停止或保留 UNKNOWN，不作为空候选成功。完整范围与资源约束见 [后续阶段 SPEC](SPEC-discovery-workflows.md)。

## 维护和发布

修改脚本的 VERSION，保持文档和固定版本示例一致，运行 `bash scripts/check.sh`；`bash scripts/package-release.sh v0.3.0` 可在本地生成并校验 dist 资产。正式决定发布后推送相同版本的稳定 Tag。Release 工作流会重新执行全部测试，校验 Tag 与脚本版本，再用最小写入权限发布资产；不会强制推送或覆盖 Release。发布者应避免移动已发布 Tag 或替换相同版本资产。

需要升级的安装器应同时审阅新版本、变更的 JSON 契约、固定版本 URL 和新摘要，再更新自身固定值。后续可以增加签名/来源证明；当前不宣称已提供这类保证。
