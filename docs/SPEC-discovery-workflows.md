# ASN、输入源与可恢复发现 SPEC

状态：实现后续阶段，源码版本 0.3.0。继承 [第一阶段 SPEC](SPEC-discovery.md) 的证据边界、固定 IP/SNI 复核、资源预算和开发流程。

## 交付范围

本阶段同时交付 ASN 范围计划、离线主机索引/历史 DNS 导入、已知 IPv6 地址发现与复核、显式缓存、持久断点续扫、多次测量排序和可选 Xray REALITY 端到端自检。保持 `check` 独立 Bash 使用；正常发现不需要代理内核。此次不创建 Release Tag。

ASN 信息是带时间戳的 BGP 观测，不是实时权威所有权或物理距离证明。默认只输出 ASN 计划；主动执行必须有明确选择的 CIDR 或用户提供的有限地址/候选清单。IPv6 只处理已知地址，不枚举前缀。

## 命令

```bash
# 仅查询和展示 ASN 的 IPv4 / IPv6 公告范围，不探测目标端口
./reality-target-checker.sh discover --asn AS64500 --plan-only --json
./reality-target-checker.sh discover --asn-from-ip 192.0.2.20 --json

# 选择公告内明确网段后执行，原有主机预算仍然有效
./reality-target-checker.sh discover --asn AS64500 --include-cidr 192.0.2.0/24 --json

# 只处理清单内 IP / SNI；CIDR 或 ASN（若提供）作为额外范围过滤
./reality-target-checker.sh discover --known-ips addresses.txt --seeds candidates.jsonl --json
./reality-target-checker.sh discover --seeds hosts.json --seed-format censys --json

# 重复采样、正向发现缓存、持久 checkpoint
./reality-target-checker.sh discover 192.0.2.0/24 --samples 3 --cache-dir ./rtc-cache \
  --checkpoint ./rtc-run.sqlite --deadline 300 --json
./reality-target-checker.sh discover 192.0.2.0/24 --samples 3 --cache-dir ./rtc-cache \
  --checkpoint ./rtc-run.sqlite --resume --deadline 900 --json

# 可选：使用用户已安装的 Xray，临时生成本地 REALITY 服务端/客户端复核
./reality-target-checker.sh discover --seeds candidates.jsonl --kernel xray \
  --kernel-bin /usr/local/bin/xray --json
```

上述 IP/ASN 为示例，执行时替换为明确选择的实际范围。`discover` 仍为第一个参数。`--asn` 与 `--asn-from-ip` 互斥；后者仅指定 ASN 查询输入，VPS 比较仍由独立的 `--origin-ip` 指定。

| 新参数 | 约定 |
| --- | --- |
| 可选位置 CIDR / `--include-cidr` | 严格规范 CIDR；后者可重复。IPv4 可有限枚举；IPv6 为已知地址过滤范围 |
| `--asn` | 十进制 ASN 或 AS 前缀；1..4294967295 |
| `--asn-from-ip` | 用户明确提供的 IPv4/IPv6，用于查询 BGP origin ASN |
| `--plan-only` | 输出独立 discovery_plan 报告；允许展示超过执行预算的范围，不探测 TCP/TLS |
| `--known-ips` | 一个 UTF-8 纯文本 IP 清单，每行一个；去重，最多 4096 个 |
| `--seeds` / `--seed-format` | 有限 JSON/JSONL/CSV 离线候选，格式 generic、censys、shodan、dns；不是在线付费 API 连接 |
| `--cache-dir` / `--cache-ttl` | 可选显式缓存目录；TTL 默认 3600 秒，1..86400 |
| `--checkpoint` / `--resume` | SQLite 持久任务记录；新任务不覆盖已有文件，resume 必须匹配同一任务语义 |
| `--state-ttl` | 恢复证据的最长年龄，默认 3600 秒，1..86400；过期记录重新执行 |
| `--samples` | 每 IP/SNI 的计划采样次数，1..5，默认 1 |
| `--sample-interval` | 同一候选采样间隔，0..60 秒，默认 0；等待可取消且计入总预算 |
| `--kernel` / `--kernel-bin` | 可选 xray 后端及本机可执行文件；不下载或安装内核，不加载现有代理配置 |

已有 `--max-hosts`、`--max-candidates`、`--concurrency`、`--rate`、`--timeout`、`--deadline` 继续有效。输入清单按文件大小、记录数、名称与 IP 格式预检；不因数据源内容自动扩大范围。没有输入源/网段时拒绝启动，单独 ASN 请求自动进入计划模式。

## ASN 计划与来源

1. 使用固定 HTTPS RIPEstat API，通过现有代理/CA 访问，设置单次超时和输出上限；不跟随任意重定向，不接受数据提供的 URL 作为下一跳。
2. `--asn-from-ip` 保留完整 origin ASN 集合；MOAS 时不任意选一个 ASN，输出 UNKNOWN 计划，要求明确输入 ASN 后再执行。
3. 公告查询显式限定时间窗口，只使用覆盖最新可核实快照的 timeline；保留查询时间、观测快照、缓存命中及 RIS 可见性限制。过期、未来或无法确定的快照不冒充当前公告。
4. IPv4 与 IPv6 前缀分别规范化与去重。公告前缀可按地址集合折叠；用户选择的 CIDR 保留其 hosts() 语义，避免 /31 合并成 /30 后丢失地址。
5. 用户选定 CIDR 必须是公告范围的子网；导入 IP 必须在所选 CIDR/ASN 过滤范围内。排除的输入 IP 单独记录，不发起目标连接。ASN 快照不是每个 IP 的独占 ASN 证明，最终候选仍保留实际 ASN 查询结果及未知项。
6. 计划明确区分可用公告范围、选定范围、实际目标数量与预算。仅计划模式可以显示大网段；执行时先核对目标去重数量，不默默截取前 N 个主机。

参考：[RIPEstat announced-prefixes](https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes.html)、[network-info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info.html)。

## 候选导入与 IPv6

通用输入支持 `ip,sni,source,observed_at`，域名字段可使用 hostname/domain 别名；索引适配器提取主机 IP 与证书/DNS 名称，历史数据的时间仅表示种子来源时间。任何索引的 PASS、证书可信标记或 ASN 声明均不作为本机握手证据。拒绝控制字符、通配种子、URL、端口、zone ID 和 curl 数字 IP 别名。

原生搜索响应若含分页标记或提供方总记录数，须核对导出完整性。Censys 的 `result.total` 与原始 `result.hits` 条数、Shodan 的 `total` 与原始 `matches` 条数均须在候选去重前核对：计数必须为非负整数，超出实际条数视为部分导出，少于实际条数视为计数矛盾；无计数的逐条 JSONL 仅代表用户明确提供的有限记录，不宣称覆盖整个索引。

提供地址/候选清单后，实际目标仅来自这些清单，CIDR/ASN 作为过滤；已带具体 SNI 的 IP 可直接进入固定 IP/SNI 复核，避免再次进行无 SNI 发现。没有 SNI 的已知 IPv4/IPv6 仍执行 SAN/PTR 发现；IPv6 PTR 使用 ip6.arpa。

IPv6 在内部规范为与 Bash checker 一致的展开形式。TLS/HTTPS 使用 IPv6 固定目标，按 AAAA 查询单独报告 DNS 绑定；源/目标不同地址族时保留原 checker 的 ASN 比较 UNKNOWN，不做跨地址族推断。

## 缓存与持久任务

- 不指定路径时不产生持久状态。缓存只复用 ASN 元数据及成功、非空的域名发现种子；缓存种子仍需当前任务的实际复核，不缓存“关闭端口/无候选”来阻止再次发现。
- 使用 SQLite 标准库、参数化 SQL、原子事务、线程同步及非阻塞进程锁。新文件 0600，拒绝 symlink、错误所有者、损坏数据库和不兼容版本；Checkpoint 单条 1 MiB，总计 256 MiB；Cache 总计 64 MiB，元数据条目允许有限增大。
- 每条状态带原观测时间，缓存/恢复不会重置为当前探测时间。未来时间是状态错误；过期条目重新执行。恢复的明确结果标记 `evidence_source=checkpoint`，不称为当前新握手。
- 复合 ASN 计划分别检查 IP→ASN 与 ASN→前缀请求的获取时间；新的公告请求不能延长旧 origin 查询的 checkpoint 寿命。BGP 数据快照时间与请求获取时间独立，前者按数据源时效判断，后者按恢复 TTL 判断。
- Checkpoint 保存计划、已完成主机发现与逐候选逐样本结果；每个完成事件提交持久事务，中断后保留已经完成的工作。UNKNOWN/错误样本下次重试，未开始样本不可丢失。
- 指纹包含范围选择、输入文件内容、样本策略、检查器/协调器版本与内容、源 IP、信任库环境和可选内核身份。允许恢复时调整 deadline、并发和启动速率；语义变化拒绝复用。大 ASN 计划只保存规范化前缀/快照摘要，不持久化无界原始响应。
- 恢复记录中的 checker 报告必须再次核对身份、类型、检查项与返回码；缓存或状态格式损坏不得变成“无候选”。

## 多次测量与排序

每个样本保留原报告、时间、证据来源、DNS 绑定和实际检查耗时。耗时从获得启动节流许可后计量，指标为整个 checker 的运行耗时，包含 DNS/TLS/HTTP/ASN 操作，不宣称为 RTT。已恢复样本不捏造新的计时。

`eligible` 要求所有计划样本完成并满足原有基础/兼容性条件；启用 Xray 自检时还要求该自检 PASS。记录成功率、中位耗时和最大/最小耗时差；多次采样时按合格性、成功率、中位耗时、波动、IP 与 SNI 排序，默认单次采样保留原有合格性/IP/SNI 顺序。一次成功不能掩盖其他样本的 FAIL/UNKNOWN；未知或未完成采样仍返回 2，已有证据完整保留。中位耗时按有效 checker 报告计量，不包含排队或额外内核自检耗时。

## 可选 Xray 端到端自检

自检使用用户明确选择、已安装的 Xray。临时生成 UUID、short ID 和 X25519 密钥；在 0700 目录写入 0600 配置，创建仅监听 loopback 的 REALITY 服务端及 VLESS/REALITY 客户端。握手 target/SNI 固定为当前候选；临时服务端仅允许代理至该 IP 的 443，其余拒绝。SOCKS 口采用随机认证，凭据不进入 argv 或报告。

通过这个独立客户端 SOCKS 入口，对固定 IP/SNI 发出正常验证证书的 HTTPS HEAD；不跟随跳转、不关闭 TLS 验证。有效 HTTP 响应才是此本地 REALITY 认证和转发路径的 PASS。它不是 `xray tls ping`，也不保证用户既有部署或其他内核版本可用。

明确隔离 Xray/V2Ray 配置环境和 confdir，避免合并用户既有配置。自检串行执行一组内核，等待锁可取消；所有派生 session、配置和密钥在完成、超时、取消时清理。无法启动、版本不兼容或网络失败为 UNKNOWN，不直接断言目标永久不支持 REALITY。默认不启用，不导出配置、UUID、密钥或原始日志。

## 报告、验收和交付

保留 discover 的原字段及退出码语义，新增计划/来源、样本、统计、缓存/恢复标记、内核结果。`report_type=discovery_plan` 与实际 `discovery` 区分；计划没有目标端口探测结论。源码版本 0.3.0，JSON 结构以兼容附加字段方式扩展。

离线验收覆盖：ASN 正常/过期/未来/历史快照、MOAS、范围越界与预算、Provider/CSV/JSONL 导入边界、已知 IPv6 的真实本地 TLS、AAAA 绑定、缓存过期与损坏、Checkpoint 指纹/中断/恢复/并发写、重复测量的 FAIL/UNKNOWN 与确定排序、Xray 临时配置/认证/进程回收/密钥不外泄。常规测试不依赖公网、付费账户或用户已有代理。

可选真实集成测试通过 `RTC_XRAY_BIN` 指定已校验内核，执行 `python3 -m unittest discover -s tests -p 'test_kernel_live.py' -v`。本轮另用官方固定 [Xray v26.10.29](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29) 完成 loopback REALITY/VLESS 认证和 HTTPS 正例、错误 VLESS 身份负例。测试夹具将固定目标端口适配为临时非特权端口，并仅对本地夹具地址设置内核私网规则例外；生产模块仍固定候选 443，不修改该保护策略。这个结果不代表已验证任意公网候选或其他内核版本。

运行 `bash scripts/check.sh` 及 `bash scripts/package-release.sh "v$(bash reality-target-checker.sh --version)"`。更新发布资产与文档，让所有可选模块随固定版本校验分发；最终 HEAD 全分支 review、当前 HEAD 的机器人 review 与 CI 通过后 Rebase and merge，并核实清理。
