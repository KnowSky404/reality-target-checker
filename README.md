# reality-target-checker

轻量、独立的 Bash CLI，用于评估域名是否适合作为 VLESS + REALITY 的候选握手目标（Target / SNI）；可选 Python 协调器支持从指定 IPv4 网段发现候选。面向 sing-box、Xray-core 等实现的使用场景，不依赖任何代理内核。

当前源码版本为 **v0.2.0**。本次不创建 Release Tag；下文 Release 下载方式在对应版本正式发布后生效。

## 功能

- 查询 A、AAAA、CNAME；逐个评估所选地址族的 IP，支持指定 IP 和独立 SNI。
- 验证 TCP 443、TLS 1.3、实际 ALPN `h2`、证书链、DNS SAN、有效期及 X25519。
- 使用 HTTPS HEAD 记录 HTTP 状态、协议版本和重定向，不下载响应正文、不跟随重定向。
- 使用 Team Cymru DNS 查询 IPv4 / IPv6 的 ASN 和组织；只与用户明确提供的同地址族源 IP 比较。
- 根据 ASN、CNAME 提示潜在 CDN / 共享边缘网络风险。没有线索时仍为 `UNKNOWN`。
- 提供中文终端输出和版本化 JSON，适合非交互安装脚本调用。
- 在明确的 IPv4 CIDR 内探测 443，从默认证书 SAN 和 PTR 收集具体域名，再逐个固定 IP/SNI 完整复核；提供并发、任务启动速率、候选数和总时间预算。

工具只评估候选站点，不执行 REALITY 鉴权握手，也不保证抗封锁、不可识别、所有内核兼容或未来持续可用。应从实际 VPS 网络重复检查。

## 运行依赖

Linux、Bash ≥ 4.3、OpenSSL（推荐发行版维护的 1.1.1 或更新版本）、curl、`dig`、GNU coreutils（含 `timeout`、`date`、`mktemp`）、常见 POSIX 文本工具，以及系统 CA 信任库。`check --json` 额外需要 jq ≥ 1.6。`discover` 始终需要 jq、Python ≥ 3.9 和与 Bash 脚本放在同一目录的 `reality-target-discover.py`；没有第三方 Python 包依赖。本项目不自动安装依赖、不要求 root。

Ubuntu 24.04 / Debian 12 的依赖安装命令（由管理员按需执行）：

```bash
sudo apt-get update
sudo apt-get install bash openssl curl dnsutils coreutils ca-certificates jq python3
```

Arch Linux：

```bash
sudo pacman -S --needed bash openssl curl bind coreutils ca-certificates jq python
```

curl 没有 HTTP/2 支持时，仍可独立用 OpenSSL 判断 ALPN h2；HTTP 检查会如实记录 curl 实际使用的协议。OpenSSL 缺少相关能力或输出证据时，该项为 `UNKNOWN`。

## 从当前源码执行

```bash
git clone https://github.com/KnowSky404/reality-target-checker.git
cd reality-target-checker
./reality-target-checker.sh --help
./reality-target-checker.sh check example.com
./reality-target-checker.sh check example.com --ipv4 --timeout 3
./reality-target-checker.sh check example.com --ipv6
```

指定实际目标 IP 和 SNI：

```bash
./reality-target-checker.sh check example.com --ip 192.0.2.10 --sni example.com
./reality-target-checker.sh check example.com --ip 2001:db8::10 --ipv6
./reality-target-checker.sh check example.com --origin-ip 192.0.2.20 --json
```

`192.0.2.0/24`、`2001:db8::/32` 为文档地址；请替换为自己确认的实际地址。`--origin-ip` 不会触发出口 IP 自动发现，避免把 TUN、透明代理或上游代理出口误认为 VPS 所属网络。目标与源 IP 地址族不同则不推断 ASN 一致性。

`check` 的选项可放在子命令或域名之后。目标和 SNI 接受 ASCII 域名（IDN 请先转 punycode），不接受 URL、路径、端口或 Shell 表达式；`--ip` 不接受括号、zone ID 或前导零 IPv4。IPv6 地址由工具规范化。

## 从 IPv4 网段发现候选

```bash
./reality-target-checker.sh discover --help
./reality-target-checker.sh discover 192.0.2.0/24 --json
./reality-target-checker.sh discover 192.0.2.0/24 --origin-ip 192.0.2.20 \
  --max-hosts 256 --concurrency 8 --rate 10 --timeout 3 --deadline 300 --max-candidates 256
```

替换为明确选择的实际网段；示例是文档地址。`discover` 必须是第一个参数，CIDR 必须严格对齐网络地址。默认最多 256 个主机，硬上限 4096；超出主机预算时在网络操作前拒绝，需显式选择更小范围或调整预算。通常排除网络和广播地址，/31 和 /32 分别检测两个和一个地址。

默认并发 8、每秒最多启动 10 个发现或复核任务、单次操作超时 3 秒、总时间预算 300 秒、全局最多 256 对 IP/SNI，每 IP 最多保留 16 个具体域名。`--rate` 控制任务启动次数，一个任务内部可能发起多个请求；它不是逐包或逐请求限速。候选截断、总超时等会明确报告不完整。

发现为 **best effort**：无 SNI 的握手可能拿不到正确证书，PTR 不一定是 HTTPS 域名，通配 SAN 不会被猜测展开。候选均须固定 IP/SNI 复核；`eligible=true` 表示基础 TLS 和候选兼容性通过，仍需审阅保留的风险。`dns_binding` 另行表示本次 DNS 是否解析到这个 IP，不能把定向握手成功当成当前 DNS 属于该网段。

发现任务的退出码独立聚合：完整执行且有候选为 0（无附加风险）或 3（需审阅风险）；完整执行但没有合格候选为 1；执行不完整或存在待确认复核为 2，已确认的候选仍保留。`scan.complete=true` 只表示有限策略执行完整，不表示找全域名。ASN 自动展开、外部主机索引、IPv6 已知地址发现和断点续扫留待后续实现。设计与验收见 [SPEC](docs/SPEC-discovery.md)。

## 如何解读 check 结果

| 状态 | 含义 |
| --- | --- |
| PASS | 本次探测已有明确符合条件的证据 |
| WARN | 基础可用但有风险、推荐条件不满足或需要审阅 |
| FAIL | 本次探测确认不符合该检查条件 |
| UNKNOWN | 工具能力、网络或信息不足，不能作肯定判断 |

结果分成三个维度：

1. `basic_tls`：TCP 443、TLS 1.3、可信证书链、SNI 的 DNS SAN 匹配、证书有效期。
2. `compatibility`：实际 ALPN h2 和 X25519。本工具采用这两个条件组成保守候选筛选标准，**不把它们宣称为所有 REALITY 实现、传输方式的统一协议强制要求**。
3. `ancillary`：HTTP 行为、临近到期、ASN、同 ASN 推荐条件、CDN 线索及 DNS 参考信息。附加未知项和风险单独保留。

| 退出码 | 最终状态 | 调用方处理 |
| --- | --- | --- |
| 0 | PASS | 所选范围的检查全部通过 |
| 1 | FAIL | 至少一个已检测 IP 的基础或候选兼容性条件明确失败 |
| 2 | UNKNOWN | 检测无法完成、地址集合不完整、基础指标未知，或参数/依赖错误 |
| 3 | WARN | 所选范围的基础与兼容性通过，但附加指标存在风险或未知项 |

FAIL 优先于 UNKNOWN；某一个 IP 通过不能覆盖另一个 IP 的失败。默认评估 A 和 AAAA；VPS 无 IPv6 出站时，相应结果可能为 UNKNOWN。明确只使用 IPv4 时可以指定 `--ipv4`，结论也随之限定到该地址族。指定 `--ip` 时只评价该 IP，DNS 失败不会阻止这个定向探测，但仍会记录在输出里。

没有证据可以仅凭本工具的启发式规则证明“不存在 CDN”。因此 v0.2.0 的 CDN 项通常为 UNKNOWN 或 WARN，正常的合格候选也通常返回 **3**，不能把它当成“完全无风险”。

示意输出（非某个真实域名的检测报告）：

```text
[PASS   ] tls13            已完成 TLS 1.3 握手并协商实际密码套件
[PASS   ] alpn_h2          服务端实际通过 ALPN 选择 h2
[UNKNOWN] same_asn         未提供可确认的同地址族 --origin-ip，或 ASN 查询信息不足
[UNKNOWN] cdn              未发现已知线索；不能据此排除 CDN / 共享边缘网络
基础 TLS: PASS | H2/X25519 兼容性: PASS | 附加指标: WARN
最终: WARN | 地址集合完整: true | WARN: 0 | UNKNOWN: 2 | 退出码: 3
```

返回 403、405 等 HTTP 状态不代表 TLS 不可用。重定向仅记录，不自动探测另一个域名。完整判据、证据边界和参考资料见 [docs/criteria.md](docs/criteria.md)。

## JSON 与脚本调用

```bash
rc=0
./reality-target-checker.sh check example.com --json --ipv4 > result.json || rc=$?
jq '{schema_version, target, sni, selection, summary, risks, unknowns}' result.json
printf 'checker exit=%s\n' "$rc"
```

不要直接在 `set -e` 下忽略非零状态，也不要通过普通管道让 jq 的退出码覆盖检测器退出码。JSON 模式 stdout 只有一个 JSON 文档；诊断写入 stderr。`--help` / `--version` 是独立的信息命令，输出纯文本。

结构版本为 `schema_version: "1.0"`，工具版本为 `tool_version: "0.2.0"`。完整字段、错误对象和兼容约定见 [docs/integration.md](docs/integration.md)。原因文字用于展示，程序应依据状态和固定检查 ID 判断。

## 固定版本分发与安装器集成

Release 将提供 `reality-target-checker.sh`、可选的 `reality-target-discover.py`、`SHA256SUMS` 和 `LICENSE`。仅使用 `check` 可以只下载 Bash；使用 `discover` 要下载并校验同版本的两个文件，放在同一目录。生产集成固定 Release 版本及各文件独立审阅的 SHA256；不要依赖持续变化的 main，也不要直接执行未经校验的远程脚本。

[examples/installer-integration.sh](examples/installer-integration.sh) 仅集成 `check`，会先下载并校验，再执行和解析结果。发布 v0.2.0 后，可将可信发布渠道核对过的摘要填入：

```bash
RTC_SHA256='<替换为已审阅的 v0.2.0 脚本的 64 位 SHA256>' \
  bash examples/installer-integration.sh example.com 192.0.2.20
```

该示例不交互、不修改 sing-box/Xray 配置，不安装、不重启服务；退出 3 时保守停止并提示审阅。校验与接入步骤见 [docs/integration.md](docs/integration.md)。SHA256 提供完整性与固定内容校验；信任摘要的来源同样重要。

## 开发与发布

所有变更必须在独立 worktree 中开发；每次推送或创建、更新 PR 前，先验证并完成本地 `/review`、解决问题，且最终提交后须再次审查整个任务分支。推送分支并创建 PR 后，等待当前 HEAD 的 Codex 机器人 review 完成且问题已处理、所需 CI 与审批通过，再使用 Rebase and merge 合并；确认合并后清理任务远程/本地分支及 worktree。审查不可用或结果不明确时保留 PR 和分支并报告阻塞。完整约束与记录要求见 [AGENTS.md](AGENTS.md) 和 [PR 模板](.github/pull_request_template.md)。

开发依赖：ShellCheck、shfmt、Bats ≥ 1.5、Python 3（标准库）、jq 和运行依赖。Ubuntu / Debian：

```bash
sudo apt-get install shellcheck shfmt bats python3 jq
bash scripts/check.sh
bash scripts/package-release.sh v0.2.0
```

检查包括 Bash 语法、ShellCheck、`shfmt -i 2 -ci`、Bats 网络 mock / 安装器测试，以及无需 root 的本地真实 OpenSSL TLS 服务测试。常规测试不访问公网、不依赖某个外部网站。临时测试证书和私钥只生成在临时目录并清理。

CI 对 main push、PR 运行检查。Release 工作流仅在推送稳定 SemVer Tag（如 `v0.2.0`）且版本与脚本一致、全部检查通过后发布；不覆盖已有 Release。外部 Action 固定完整 commit SHA，只有发布 job 获得 `contents: write`。现在无需创建 Tag。

## 网络与隐私边界

- `check` 检测指定域名和明确的定向 IP；`discover` 仅主动连接用户明确输入的 IPv4 范围内地址。端口固定 443，不跟随发现的域名、DNS 或重定向去扫描范围外 IP。
- `check` 最多处理 16 个去重后的目标 IP，`--timeout` 默认 5 秒，仅限制每次操作。`discover` 使用独立主机/候选预算和 `--deadline` 总时间预算，详见 [SPEC](docs/SPEC-discovery.md)。
- HTTPS 复核禁用 curl 配置文件和显式环境代理，固定连接目标 IP，证书按实际 SNI 和本地信任库验证。发现阶段可读取不受信任的默认证书，仅提取种子，不作为验证通过证据。透明代理、TUN 和链路干预仍可能影响观察结果。
- DNS 查询通过现有解析器。Team Cymru 查询会让解析器和该服务获知待查 IP（以及提供时的源 IP）的 DNS 编码和 ASN；其 BGP 数据并非实时权威归属或地理位置保证。
- `discover` 会让范围内站点获知扫描端地址，也会向现有解析器查询已开放地址的 PTR 和候选域名。它不自动探测出口 IP、不隐式扩大到整个 ASN。
- 不读取或上传代理私有配置、UUID、密钥；不修改系统网络、DNS、防火墙或代理配置。

后续值得完善的是：更多 OpenSSL/发行版输出兼容测试、CDN 证据规则维护、可选的后量子密钥交换观测及发布资产签名。本版不把混合密钥交换或其他内核专属能力当作已经验证。

MIT License。
