# IPv4 网段候选发现 SPEC

状态：本次实现第一阶段；工具版本 0.2.0。`check` 的 JSON 1.0 契约保持兼容，`discover` 使用独立的报告类型。

## 问题与目标

现有 `check` 需要用户预先知道域名。新增 `discover CIDR`，在明确的 IPv4 网段内发现普通 HTTPS 站点的候选域名，再固定 IP 与 SNI 复用检查器验证，减少手工寻找 REALITY target 的工作。结果是候选清单，不保证 REALITY 端到端握手、抗封锁或持续可用。

首阶段不自动发现出口 IP，不根据源 IP 自动扩大扫描范围，不扫描 ASN 全部地址，不穷举 IPv6，不接入付费平台、不爬取网页，也不修改代理或系统配置。

## 可行性与证据

- 已有 Bash 检查器提供 `--ip`、`--sni`、`--origin-ip` 和 JSON，可以作为每一候选的独立验证进程。
- 无 SNI 的 TLS 握手可能得到默认证书，也可能被拒绝；服务器可以根据 SNI 选择证书。因此 SAN 与 PTR 只是种子，发现覆盖率始终为 best effort。[RFC 6066](https://www.rfc-editor.org/rfc/rfc6066.html#section-3)
- SAN 的域名不保证当前解析到发现 IP；PTR 也不保证是 HTTPS 域名。必须再次携带具体 SNI 在固定 IP 上验证。通配 SAN 不能直接作为 SNI，也不能凭空补全主机名。
- curl 会把一到四组十进制、八进制或十六进制数字归一化成 IPv4 地址。种子与 check 的域名校验都排除这些地址形式，避免 URL 解析与 DNS 定向解析对主机名产生不同解释。[curl URL 语法](https://curl.se/docs/url-syntax.html#numerical-ipv4-addresses)
- 同 ASN 不代表同机房、相邻路由或更低延迟。ASN/前缀查询仅作为后续的范围生成器，实际连接仍须复测。[RIPEstat](https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes.html)
- CT 记录证书，并不提供完整、实时的 ASN 到托管域名映射。外部主机索引可以补充种子，但需考虑权限、费用、历史性和分页。[CT](https://certificate.transparency.dev/howctworks/)、[Censys](https://docs.censys.com/reference/get-started)

## 命令与依赖

```bash
./reality-target-checker.sh discover 192.0.2.0/24 --json
./reality-target-checker.sh discover 192.0.2.0/24 --origin-ip 192.0.2.20 \
  --max-hosts 256 --concurrency 8 --rate 10 --timeout 3 --deadline 300 --max-candidates 256
```

示例为文档地址，执行时替换为明确选择的实际范围。`discover` 必须是第一个参数。`discover --help` 不探测网络。参数错误在开始网络操作前退出 2；JSON 模式输出错误 envelope，诊断进入 stderr。

`check` 继续独立使用 Bash 原有依赖；只有 `discover` 额外需要 Python >= 3.9 与相邻的 `reality-target-discover.py`，始终需要 jq，因为复核使用 JSON。延续 Linux 运行环境要求，通过 `/proc` 跟踪独立子 session 内的进程组。使用 Python 标准库协调并发、解析地址、TLS 发现和报告；没有第三方 Python 包或外部扫描器依赖。

| 参数 | 默认值 | 约束 |
| --- | --- | --- |
| CIDR | 必填 | 一个严格对齐的 IPv4 网络；拒绝 IPv6、主机位不为零及多余参数 |
| `--max-hosts` | 256 | 1..4096；待探测主机超过预算时整次拒绝，不默默截取前缀 |
| `--concurrency` | 8 | 1..32；发现和复核分别使用有界工作池 |
| `--rate` | 10 | 1..100；所有发现任务与复核任务共用启动节流器，单位为任务/秒，不宣称逐包或 checker 内部逐请求限速 |
| `--timeout` | 3 | 1..60 秒；连接、TLS、DNS 等单次操作上限，且受剩余总时间约束 |
| `--deadline` | 300 | 1..3600 秒；任务总时间预算；到期停止派发并终止运行中的子进程组 |
| `--max-candidates` | 256 | 1..4096；全局去重 IP/SNI 对预算；每 IP 最多保留 16 个具体域名 |
| `--origin-ip` | 无 | 用户确认的 IPv4 源 IP；仅传递给检查器比较 ASN |
| `--json` | 关闭 | stdout 只输出一个独立 JSON 文档 |

按 IPv4 `hosts()` 枚举：通常排除网络和广播地址；/31 包含两个地址，/32 包含一个地址。允许显式指定私网或本地范围。只连接输入范围内的 IP:443；不跟随 PTR、SAN、DNS 或重定向去探测范围外 IP。

## 发现与验证流程

1. 预检参数和运行依赖，计算主机数，建立 monotonic 总 deadline。
2. 按地址顺序调度发现任务：连接 TCP 443；成功后进行无 SNI TLS 握手，提取叶证书，使用 OpenSSL 解析 DNS SAN。发现阶段允许读取未经信任验证的证书，仅用于生成种子，不能据此通过验证。
3. 对 TCP 已开放的 IP 查询 PTR。只接收成功响应中对应反向 owner 或其响应内可达 CNAME 链终点的合法 ASCII 域名；支持 [RFC 2317](https://www.rfc-editor.org/rfc/rfc2317.html) 的小网段反向 DNS 委派，最多跟踪 16 跳。循环、多目标或 CNAME/PTR 矛盾为 UNKNOWN；不为别名发起额外查询，不接收无关 owner 的 PTR。去除末尾点、转小写、去重。忽略通配、IP 字面量、非法字符和超长名字；发现和 check 入口均拒绝 curl 会按 IPv4 字面量解释的十六进制/混合数字名称，防止绕过定向解析。SAN 与 PTR 来源合并；对泛域名只记录有限线索，不猜测具体标签。
4. 对 IP/域名排序去重；每 IP 16 个名字及全局候选预算超限都必须记录截断，并标记执行不完整。返回有限的证据，避免证书或 DNS 使候选集合无限放大。
5. 对每对 IP/SNI 启动独立 Bash checker：`check SNI --sni SNI --ip IP --ipv4 --json --timeout T`，可选传递源 IP。每次 checker 独立临时目录；不在同一个 Bash 全局状态里并发检查。
6. 核对 JSON 类型/结构版本、进程退出码与报告一致、目标及 SNI 一致、`explicit_ip` 和完整 selection、恰有一个相同 IP 的 endpoint、实际必要检查项与汇总一致。错误 envelope、损坏报告、矛盾结果或进程异常都为 UNKNOWN，不接受为候选。
7. 仅当基础 TLS 与兼容性实际检查全部 PASS 时标记 `eligible=true`；允许原报告为 WARN/3，但完整保留 risks、unknowns 和原检查报告。FAIL 与 UNKNOWN 也保留，方便解释没有结果的原因。
8. 根据 checker 的本次 A 查询分别记录 `dns_binding=MATCH/DIFFERENT/UNKNOWN`。DNS 不对应不抹去定向 IP/SNI 握手证据，也不能宣传成当前 DNS 位于目标网段。

## 报告与状态

独立 envelope：`schema_version: "1.0"`、`report_type: "discovery"`、`tool_version: "0.2.0"`。顶层包括 `scope`（CIDR、主机数、预算、origin_ip）、`scan`（complete、完成主机数、候选数、耗时、停止/截断原因）、`hosts`（TCP/TLS/PTR 发现证据、来源和有限通配线索）、`candidates` 与 `summary`。

每个候选包括 `ip`、`sni`、`sources`、`eligible`、`dns_binding`、复核耗时及 `report`；复核不能完成时保存有限的 `error`。保留原报告中的 ASN、证书、检查证据和风险。输出顺序固定为可用候选优先，再按 IP 数值与域名排序；耗时是单次运行观测，不作为稳定性承诺。

`scan.complete` 仅表示本次有限发现策略及其生成的候选已按预算执行完成，不表示找全所有域名。TCP 拒绝连接、明确的无 SNI TLS alert 拒绝或没有具体名字可以形成已完成的空发现；意外 TLS EOF、协议解码错误、操作超时、DNS 异常、子进程/解析错误、候选截断和总超时会使 scan 不完整。未完成的已生成候选必须保留 UNKNOWN，不能消失。

| 退出码 | 发现任务含义 |
| --- | --- |
| 0 | 执行完整，至少一个 eligible 候选，所有 eligible 候选均无附加风险 |
| 1 | 执行完整，没有 eligible 候选且没有待确认复核；不证明范围内不存在其他域名 |
| 2 | 参数/依赖/执行不完整，或存在 UNKNOWN 复核；已确认的候选仍保留 |
| 3 | 执行完整，存在 eligible 候选且其中有 WARN/UNKNOWN 附加指标，需要审阅 |
| 130 / 143 | SIGINT / SIGTERM；尽力输出部分报告并回收子进程，调用方不得当作成功 |

单个被拒绝候选不使其他合格候选消失，也不按原 check 的“任一 endpoint FAIL 即整次 FAIL”聚合整个发现任务。缺少依赖/解析错误不能变成“找不到候选”。文本输出必须明确提示 best effort、固定 IP 验证与 DNS 绑定的区别。

## 生命周期与资源

- 所有子进程使用参数列表，无 shell/eval；输出从临时文件读取，限制每进程证据大小，超限作为 UNKNOWN。TLS 证书有大小限制。
- checker 使用独立 session；通过 Linux `/proc` 跟踪其中全部进程组，包括 GNU timeout 新建的组。总超时或取消时 TERM 所有组；必要时先 KILL 未退出的探测组，给 Bash 执行 EXIT 清理临时目录的机会，最后再回收外层进程。线程与套接字均在剩余时间内结束，连接与 TLS 握手短轮询取消事件；不留下后台任务。
- 不把原始远端错误或控制字符直接注入终端。JSON 序列化转义控制字符。
- 不调用公网服务做常规测试，不实际扫描用户未指定的网段，不改变 DNS、防火墙、CA 或服务。
- 发布同时提供 Bash 与可选 Python 文件并校验各自摘要；只下载 Bash 的已有 check 集成保持有效。此次不创建 Release Tag。

## 验收

必须通过 `bash scripts/check.sh` 和 `bash scripts/package-release.sh "v$(bash reality-target-checker.sh --version)"`。

离线测试覆盖：CLI 及 /31、/32 和范围预算；SAN/PTR 去重及注入输入；通配不扩展；默认证书失败后 PTR 仍能产生候选；固定 IP/SNI 调用；WARN 候选接受并保留风险；FAIL/UNKNOWN/错误 JSON/矛盾报告不被接受；DNS MATCH/DIFFERENT/UNKNOWN；候选上限；总 deadline、取消和子进程组清理；有限并发/节流；真实本地无 SNI TLS 证书读取；原有 check/安装器兼容及打包资产完整性。

## 后续阶段

ASN 范围生成器需明确公告快照、前缀去重、MOAS 与范围预算，先展示或输出范围，不隐式全 ASN 扫描。数据源适配器可导入主机索引/历史 DNS 的 IP/SNI，并以相同验证流水线复核。IPv6 仅处理已知地址。缓存、断点续扫、重复测量排序及可选内核端到端验证按后续独立 SPEC 扩展。
