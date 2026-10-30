# 检查标准与证据边界

`check` 和默认 `discover` 是内核无关的 REALITY 候选目标评估，不模拟 REALITY 客户端。0.3.0 另外提供显式启用的 Xray 端到端自检，使用临时本地服务端/客户端，不加载用户已有代理配置。每次结果只是指定网络路径、SNI、IP、信任库、本机时钟和所选内核下的快照。

## 来源与版本

基础判据依据以下官方资料核对（2026-10-29），并以本机工具的实际能力为准。核对时最新稳定 Xray-core 为 v26.10.29、sing-box 为 v1.14.4；这些是参考上下文，并非默认检查的运行依赖或固定要求的内核版本，也不代表常规 CI 已运行真实 REALITY 认证。

- [XTLS / REALITY](https://github.com/XTLS/REALITY)：原始实现及候选站点建议。
- [Xray REALITY 配置](https://xtls.github.io/config/transports/reality.html)：target、serverNames、后量子密钥交换及未认证流量回落风险。
- [sing-box TLS / REALITY](https://sing-box.sagernet.org/configuration/shared/tls/)：server_name、ALPN 和 REALITY handshake 配置。
- [Team Cymru IP-to-ASN](https://www.team-cymru.com/ip-asn-mapping)：IPv4 反转 octet、IPv6 反转 nibble、ASN 组织查询及 BGP 数据限制。
- [OpenSSL s_client](https://docs.openssl.org/3.0/man1/openssl-s_client/) 和 [x509](https://docs.openssl.org/3.0/man1/openssl-x509/)：工具选项及证书检查能力。

“推荐”不等于统一协议强制要求。不同内核版本、传输方式和 TLS 客户端指纹存在差异。工具以基础 TLS、H2/X25519 候选兼容性、附加指标三个维度报告，不用分数隐藏不确定性。

## DNS 和检测范围

通过 `dig -r` 查询目标域名 A、AAAA、CNAME，禁用用户 digrc 和搜索域。每次查询只尝试一次并限制时间。记录解析器 RCODE：

- NOERROR 且有有效记录：PASS，保留和去重地址。
- NOERROR / NODATA：该类型查询已完成但无记录，PASS 不代表有可检测的地址。例如没有 CNAME 并不说明没有 CDN。
- NXDOMAIN：该 DNS 项 FAIL；若无法选出目标地址，整体 UNKNOWN / 2。
- 超时、SERVFAIL、缺少 RCODE 或异常记录：UNKNOWN，不合成地址。

默认逐个检查 A 和 AAAA。只有所选地址族查询完成且全部所选地址已检测时，`selection.complete` 才为 true。DNS 失败即使已有另一地址族的结果，也不能冒充完整检查。`--ipv4`、`--ipv6` 可明确限定候选范围。

最多检查 16 个地址；超限仅检查返回顺序的前 16 个，并报告 `complete=false`、原因和退出码 2（若已确认某 IP 失败，FAIL / 1 优先）。DNS、轮询顺序、负载均衡和缓存可能使下一次结果不同。CNAME 信息仅来自本次回答，未穷举所有别名历史与分支。

`--ip` 固定目标，避免 DNS 变化影响定向测试。此时 `selection.scope=explicit_ip`，只评价该地址；DNS 回答仍显示为参考，不能将结论推广到域名的其他地址。TLS SNI 和 HTTPS Host 使用 `--sni` 或默认域名；HTTP 直接连接到这个固定 IP，不再解析 SNI 去选择别的服务端。

## 基础 TLS（basic_tls）

| 检查 ID | PASS 证据 | FAIL 证据 | UNKNOWN 示例 |
| --- | --- | --- | --- |
| tcp443 | Bash `/dev/tcp` 连接到目标 IP:443 成功 | 明确 connection refused | 超时、本机无路由、其他连接异常 |
| tls13 | 强制 TLS 1.3，观察到实际 TLS 密码套件及证书，且无服务端错误告警 | 服务端明确 protocol_version 告警 | 无证书、Cipher NONE、工具不支持、超时、其他握手异常 |
| cert_chain | 同次握手 OpenSSL verify return code 为 0 | 同次握手非零验证码 | 无法解析证书或验证结果 |
| cert_san | 叶证书 DNS SAN 匹配实际 SNI | 有可解析证书但没有匹配的 DNS SAN | 无法读取扩展或证书 |
| cert_validity | 本机 UTC 时钟位于 notBefore / notAfter 内 | 尚未生效或已过期 | 无法解析时间或证书 |

OpenSSL s_client 默认可能在证书失败时继续握手，也可能在完成握手后因对端未发送 close_notify 而非零退出。因此不单看退出码，更不能看到 `Verify return code: 0` 就认定 TLS 1.3 可用；必须结合实际协商证据。服务端要求客户端证书等错误告警会阻止握手 PASS。无法区分特定 TLS 指纹限制或链路干预时保留 UNKNOWN。

链验证使用 s_client 的本地 CA 信任库和服务器用途检查，不增加 `-verify_hostname`，以便分别报告链和 SAN。SAN 检查只接受 DNS SAN 的不区分大小写精确匹配或整段最左标签通配符，`*.example.com` 仅匹配 `a.example.com`。不以 Common Name 兜底，不接受多层通配符。IDN 需由用户输入 punycode。

未做 OCSP/CRL 吊销检查、CT 审计、在线 AIA 补链或证书固定；“可信”只指当前本地信任库验证成功。缺少中间证书或本地根证书也会导致 cert_chain FAIL，其原因不等于服务端在所有客户端都不可用。环境中的 `SSL_CERT_FILE` / `SSL_CERT_DIR` 可影响信任结果；不改动系统 CA。证书剩余不足 7 天额外报告 `cert_expiry=WARN`，不会单独把仍有效的证书归为基础失败。

## 候选兼容性（compatibility）

`alpn_h2`：在 TLS 1.3 握手中实际提供 `h2,http/1.1`。只有服务端明确选择 `h2` 才 PASS。完成握手但选择 HTTP/1.1 或明确无 ALPN 则 FAIL；缺少 ALPN 能力或无法读到结果则 UNKNOWN。不能从 curl 提供过 `--http2` 或 HTTP 状态成功推断 h2。

`x25519`：实际观察到 `Server Temp Key` 或 `Peer Temp Key` 为纯 X25519 才 PASS。若默认协商其他组，最多增加一次只提供 X25519 的 TLS 1.3 握手。该次成功且明确观察到 X25519 时 PASS；服务端明确拒绝该约束握手则 FAIL（仅代表当前探测条件下不满足候选标准）；超时、未知选项或无可解析组信息均 UNKNOWN。

混合组如 X25519MLKEM768 不能仅凭名称含 X25519 就误报为本项通过。本版可再尝试纯 X25519，但不评估后量子组本身。H2 与 X25519 是本工具保守筛选条件，不能据此宣称缺失时所有 REALITY 实现都绝对不可用。它们以独立兼容性汇总呈现。

## HTTP 行为

使用 curl 对 `https://SNI/` 发起 HEAD，请求固定到当前 IP:443，验证证书；不使用 `-k`。启用可用的 HTTP/2 支持，并记录 curl 实际返回的 `%{http_version}` 和 `%{http_code}`，同时核对远端 IP 与定向 IP 一致。

- 任何有效的 1xx..5xx 最终响应说明本次 HTTPS 请求收到了 HTTP 响应。403、405 也可 PASS，不直接否定独立 TLS 结果。
- 3xx 设置 `http_redirect=WARN`，保留经终端控制字符过滤的 Location；不跟随，不把重定向目的站点的能力归给原目标。
- 超时、TLS/HTTP 异常、无法确认远端或无响应均 UNKNOWN；记录 curl 退出码。没有 HTTP 响应并不证明 TLS 协议不支持。

HEAD 与 GET、登录状态、区域或客户端指纹可能有不同响应；本版不下载页面，也不验证 HTTP/2 应用层的完整功能。OpenSSL 的 ALPN 协商证据与 curl 的 HTTP 协议观测分别保留。

## ASN 与 CDN

Team Cymru 的 `origin.asn.cymru.com` / `origin6.asn.cymru.com` 提供 BGP origin ASN，再向 `AS<number>.asn.cymru.com` 查询组织信息。每次运行缓存相同 IP 的查询结果。多个 TXT 答案、多源 ASN（MOAS）、非法或缺失记录不任意挑选一个，记为 UNKNOWN。只有取得单一 ASN 和组织信息，`asn` 才 PASS；即使组织查询失败，已取得的 ASN 仍可显示。

没有 `--origin-ip` 就不探测、不猜测源 IP。该参数是用户对 VPS 公网归属的明确输入，并非工具发现；只比较同地址族。相同 ASN 是推荐条件 PASS，不同 ASN 为 WARN，信息不足或跨地址族为 UNKNOWN，不影响基础 TLS 的独立结果。

CDN 仅使用可说明的公开线索：Cloudflare、Akamai、Fastly 等已知 ASN，常见边缘 CNAME；Amazon AS16509 仅提示潜在共享云/边缘，无法区分 CloudFront 与普通云主机。命中规则输出 WARN 及具体证据，不直接判定 TLS 失败。缺少 CNAME、未命中 ASN 或 ASN 查询失败时均不能证明非 CDN，报告 UNKNOWN。名单不是完整数据库，需长期维护。

风险来自未通过 REALITY 鉴权的流量可能被转发到 target，使 VPS 成为共享边缘网络的转发入口。是否需要 SNI 过滤、回落限速或其他控制应结合所用内核及部署策略判断；本工具不修改任何配置。

## 汇总与资源边界

每个检查的 FAIL 代表该项已验证不符合，UNKNOWN 代表没能确认。全部 IP 的基础 TLS 及兼容性分别聚合，FAIL 优先于 UNKNOWN，再次于 PASS。最终退出码为：

1. 任一基础或兼容性 FAIL → FAIL / 1。
2. 否则，基础/兼容性 UNKNOWN 或地址集合不完整 → UNKNOWN / 2。
3. 否则，存在附加 WARN、FAIL 或 UNKNOWN → WARN / 3。
4. 所选范围全部检查 PASS → PASS / 0。

没有无证据的“非 CDN PASS”规则，所以首版正常候选也通常为 WARN / 3。这是保留不确定性，调用方需要明确策略。

`check` 最多 3 次目标 DNS 查询，最多 2 次源 ASN 查询；每 IP 最多 1 次 TCP 探测、2 次 TLS 握手、1 次 HTTPS HEAD 和 2 次 ASN DNS 查询。一次 `check` 内按顺序执行，重复 ASN 查询使用缓存。`--timeout T` 限制每次网络操作，GNU timeout 超过 T 秒发 TERM，必要时再过 1 秒 KILL；总用时随 IP 数增长，调用方可加独立的整次运行 deadline。理论网络操作上界约为 `(3 + 2 + 6 × IP数) × (T + 1)` 秒，通常提前结束。

`check` 的临时目录使用 `mktemp -d` 和 umask 077，在退出及信号处理后清理。信号中断没有承诺完整 JSON（退出 130/143），调用方应当作无法完成；不能把残缺 JSON 视为结果。`check` 不执行参数表达式或 eval，不使用动态端口，不安装服务或写入网络配置。

## 网段与已知地址发现

`discover` 是额外的有限扫描策略：输入严格对齐的 IPv4 CIDR 或明确的 IPv4/IPv6 地址清单，先验证主机预算，再通过 TCP 443、无 SNI 默认证书 DNS SAN 和 PTR 生成具体域名种子。已导入具体 SNI 的记录直接进入固定 IP 验证，不必再次依赖默认证书。无 SNI 阶段可以读取不受信任的证书，但不会给候选验证 PASS；通配 SAN 只保留有限线索，不猜测主机名。默认证书不能覆盖所有虚拟主机，因此完整执行也始终是 best effort。

每个 IP/SNI 对通过独立的 `check SNI --ip IP --sni SNI --json` 进程复核，再按该 IP 的地址族附加 `--ipv4` 或 `--ipv6`，沿用本文所有基础 TLS、候选兼容性和附加风险判据。协调器核对结构、身份、端点、退出码和实际检查结果后才接受候选。所有计划样本的基础和兼容性均通过才有 `eligible=true`；启用 Xray 自检时还要求自检 PASS。WARN/3 的风险和未知项保持可见，不能只筛退出码 0。

本次 DNS A（IPv4）或 AAAA（IPv6）查询与固定 IP 的对应关系单独输出为 MATCH、DIFFERENT、UNKNOWN；DNS 失败不等于 DIFFERENT，定向握手成功也不证明当前域名解析属于目标网段。发现始终固定连接输入范围内 IP，不按 SAN、PTR 或重定向扩大扫描范围。IPv6 只处理明确地址或 `/128`，不枚举更大前缀；同 ASN 也不能证明同机房或低延迟。

发现与复核共用有界任务启动速率，复核进程内部仍可能进行多个网络操作；因此 `--rate` 不是严格逐请求或逐包速率。总 deadline、地址/域名预算及进程组清理约束见 [第一阶段 SPEC](SPEC-discovery.md) 和 [后续阶段 SPEC](SPEC-discovery-workflows.md)。候选截断、超时或解析异常会报告不完整，并保留已经得到的结果；没有结果不能证明范围内不存在合适站点。

## ASN、外部种子与历史证据

ASN 规划使用带时间戳的 RIPE RIS 数据，明确保留公告快照与数据源限制，不把默认历史窗口中的所有前缀当作当前公告。源 IP 查询出现 MOAS 时保留完整集合，不默选单一 ASN；公告覆盖也不是每个 IP 的独占归属证明。ASN 默认只输出计划，主动执行必须另有明确 CIDR 或有限清单，并在目标连接前检查范围与预算。

Censys、Shodan 和历史 DNS 适配器只解析本地导出文件，不在线查询付费账户。证书、DNS、ASN 标记和历史 PASS 仅提供种子，不能作为当前握手证据；每一具体 IP/SNI 仍须本机复核。拒绝超量、损坏、未完成分页以及非法名字输入，不按提供商链接扩大扫描。

缓存仅复用 ASN 元数据和成功非空的发现种子；checkpoint 可恢复已经完成的明确样本，保留原时间并标记 `evidence_source=checkpoint`。UNKNOWN/错误与过期证据重试，状态权限、格式或任务指纹不符不会变成候选成功。默认 `--samples 1`；启用多次采样时所有计划样本须通过，按成功率及 checker 运行耗时中位数/波动排序。该耗时包含 DNS/TLS/HTTP/ASN，不是目标 RTT。

## 可选 Xray 自检的证据范围

`--kernel xray` 使用用户已安装的内核，临时生成本地 REALITY 服务端和 VLESS/REALITY 客户端，经随机认证 SOCKS 入口，对固定 IP/SNI 发送正常验证证书的 HTTPS HEAD。有效 HTTP 响应才可给出本地认证及代理路径 PASS；单纯启动成功或 `xray tls ping` 不足以通过。

配置、UUID、short ID 和密钥只属于临时自检，目录 0700、配置 0600；不读取已有配置，不将密钥或原始日志写入报告。配置环境/默认 confdir 被隔离，loopback 控制端口动态分配，目标路由仅允许候选 IP 的 443。自检串行执行一组，等待及运行均受取消和总 deadline 限制，完成后回收进程和临时文件。

缺少可用内核、版本不兼容、启动失败或网络异常都为 UNKNOWN，不无依据判断目标永久不可用。PASS 只适用于本次临时配置和报告中的 Xray 版本，不证明用户既有部署或其他内核可用。常规 CI 使用模拟内核验证 runner 和生命周期，不能把这些测试称为实际 Xray REALITY 认证已通过。
