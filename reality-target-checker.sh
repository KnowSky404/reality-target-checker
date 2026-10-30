#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Standalone, read-only candidate assessment. No proxy core is required.

VERSION=0.3.0
SCHEMA_VERSION=1.0
MAX_ENDPOINTS=16

usage() {
  cat <<'EOF'
reality-target-checker — REALITY 候选握手目标评估器

用法: reality-target-checker.sh check DOMAIN [选项]
      reality-target-checker.sh discover [CIDR] [选项]
      reality-target-checker.sh --help | --version

check 选项：
  --json             仅向 stdout 输出 JSON（需要 jq）
  --timeout SECONDS  每次网络操作的超时，整数 1..60，默认 5
  --origin-ip IP     用户确认的 VPS 公网 IP（不自动探测出口 IP）
  --sni DOMAIN       实际 TLS SNI / HTTPS Host，默认为 DOMAIN
  --ip IP           仅检测此 IP；DNS 结果仍作为参考
  --ipv4 | --ipv6    仅检测所选地址族；默认检测两者
  --help             查看帮助
  --version          查看版本

端口固定为 443。最多检查 16 个去重后的地址，超出时明确报告不完整。
退出码: 0 检查通过；1 候选基础条件失败；2 无法完成；
        3 基础通过但有 WARN / UNKNOWN 附加指标，必须审阅。

discover 支持 IPv4 网段、ASN 范围计划及已知 IPv4/IPv6 清单，固定 IP/SNI 复核。
需要 Python >= 3.9、jq 和相邻的 reality-target-discover.py；ASN/导入、
缓存/续扫、可选 Xray 自检分别使用同版本 sources/state/kernel Python 模块。
ASN 默认只生成计划；主动扫描须明确选择网段或提供清单，不枚举 IPv6 前缀。
支持 --seeds、--samples、--checkpoint/--resume；discover 必须为第一个参数。
发现任务选项、预算和退出码见 reality-target-checker.sh discover --help。
EOF
}

fatal() {
  local code=$1 message=$2
  printf 'reality-target-checker: %s\n' "$message" >&2
  if ((json)); then
    if command -v jq >/dev/null 2>&1; then
      jq -cn --arg version "$VERSION" --arg schema "$SCHEMA_VERSION" \
        --arg code "$code" --arg message "$message" \
        '{schema_version:$schema,tool_version:$version,target:null,sni:null,
          error:{code:$code,message:$message},summary:{status:"UNKNOWN",exit_code:2}}'
    else
      printf '%s\n' '{"schema_version":"1.0","tool_version":"0.3.0","target":null,"sni":null,"error":{"code":"DEPENDENCY","message":"JSON mode requires jq"},"summary":{"status":"UNKNOWN","exit_code":2}}'
    fi
  fi
  exit 2
}

dispatch_discover() {
  local script_dir discovery_script message=''
  script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || return 2
  discovery_script=$script_dir/reality-target-discover.py
  if ! command -v python3 >/dev/null 2>&1; then
    message='discover 需要 Python >= 3.9'
  elif ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
    message='discover 需要可运行的 Python >= 3.9'
  elif [[ ! -r $discovery_script ]]; then
    message='discover 需要相邻的 reality-target-discover.py；请下载并校验同版本资产'
  fi
  if [[ -n $message ]]; then
    printf 'reality-target-checker: %s\n' "$message" >&2
    if ((json)); then
      printf '{"schema_version":"%s","tool_version":"%s","report_type":"discovery","error":{"code":"DEPENDENCY","message":"Discovery requires Python >= 3.9 and the adjacent reality-target-discover.py"},"summary":{"status":"UNKNOWN","exit_code":2}}\n' "$SCHEMA_VERSION" "$VERSION"
    fi
    return 2
  fi
  exec python3 "$discovery_script" "$@"
}

valid_domain() {
  local name=${1%.} label
  local -a labels
  [[ -n $name && ${#name} -le 253 && $name != *. && $name != *..* && $name != *[!a-zA-Z0-9.-]* ]] || return 1
  [[ ! $name =~ ^[0-9.]+$ ]] || return 1
  # Reject numeric URL hosts that curl can reinterpret instead of using --resolve.
  [[ ! $name =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)(\.(0[xX][0-9a-fA-F]+|[0-9]+)){0,3}$ ]] || return 1
  IFS=. read -r -a labels <<<"$name"
  for label in "${labels[@]}"; do
    [[ ${#label} -le 63 && $label =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || return 1
  done
}

valid_ipv4() {
  local ip=$1 part
  local -a parts
  [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a parts <<<"$ip"
  for part in "${parts[@]}"; do
    [[ ${#part} -le 3 && ($part == 0 || $part != 0*) ]] || return 1
    ((10#$part <= 255)) || return 1
  done
}

# Normalize IPv6, including an embedded dotted IPv4 tail, without another runtime.
normalize_ip() {
  local ip=${1,,} left right tail group expanded='' zeros i v4hex
  local -a lhs=() rhs=() octets=()
  if valid_ipv4 "$ip"; then
    IP_NORMALIZED=$ip
    IP_FAMILY=4
    return 0
  fi
  [[ $ip == *:* && $ip != *[!0-9a-f:.]* ]] || return 1
  if [[ $ip == *.* ]]; then
    tail=${ip##*:}
    valid_ipv4 "$tail" || return 1
    IFS=. read -r -a octets <<<"$tail"
    printf -v v4hex '%x:%x' "$((octets[0] * 256 + octets[1]))" "$((octets[2] * 256 + octets[3]))"
    ip=${ip%:*}:$v4hex
  fi
  if [[ $ip == *::* ]]; then
    left=${ip%%::*}
    right=${ip#*::}
    [[ $right != *::* ]] || return 1
    [[ -z $left ]] || IFS=: read -r -a lhs <<<"$left"
    [[ -z $right ]] || IFS=: read -r -a rhs <<<"$right"
    zeros=$((8 - ${#lhs[@]} - ${#rhs[@]}))
    ((zeros >= 1)) || return 1
    # A lone leading/trailing ':' outside the compression is invalid.
    [[ $left != :* && $left != *: && $right != :* && $right != *: ]] || return 1
  else
    [[ $ip != :* && $ip != *: ]] || return 1
    IFS=: read -r -a lhs <<<"$ip"
    ((${#lhs[@]} == 8)) || return 1
    zeros=0
  fi
  for group in "${lhs[@]}"; do
    [[ $group =~ ^[0-9a-f]{1,4}$ ]] || return 1
    printf -v group '%04x' "$((16#$group))"
    expanded+=$group:
  done
  for ((i = 0; i < zeros; i++)); do expanded+=0000:; done
  for group in "${rhs[@]}"; do
    [[ $group =~ ^[0-9a-f]{1,4}$ ]] || return 1
    printf -v group '%04x' "$((16#$group))"
    expanded+=$group:
  done
  IP_NORMALIZED=${expanded%:}
  IP_FAMILY=6
}

clean_text() {
  # Untrusted network strings must not control a terminal.
  LC_ALL=C tr -cd ' -~' | head -c 512
}

set_check() {
  statuses["$1:$2"]=$3
  reasons["$1:$2"]=$4
}

bounded() {
  timeout --signal=TERM --kill-after=1 "${network_timeout}s" "$@"
}

# Keep RCODE, distinguish authoritative empty answers from SERVFAIL/timeouts.
dns_query() {
  local name=$1 type=$2 rc
  DNS_RESPONSE=$(bounded dig -r "+time=$network_timeout" +tries=1 +nosearch \
    +noall +comments +answer "$name." "$type" 2>/dev/null)
  rc=$?
  DNS_CODE=$(sed -n 's/.*status: \([A-Z]*\),.*/\1/p' <<<"$DNS_RESPONSE" | head -1)
  ((rc == 0)) && [[ $DNS_CODE == NOERROR || $DNS_CODE == NXDOMAIN ]]
}

collect_dns() {
  local type _owner _ttl class kind value _rest found malformed=0
  local -A seen_a=() seen_aaaa=() seen_cname=()
  for type in A AAAA CNAME; do
    if ! dns_query "$target" "$type"; then
      set_check dns "$type" UNKNOWN "DNS 查询失败或无可验证的 RCODE（${DNS_CODE:-timeout}）"
      continue
    fi
    if [[ $DNS_CODE == NXDOMAIN ]]; then
      set_check dns "$type" FAIL '解析器返回 NXDOMAIN'
      continue
    fi
    found=0 malformed=0
    while read -r _owner _ttl class kind value _rest; do
      [[ $class == IN ]] || continue
      case $kind in
        A | AAAA)
          if ! normalize_ip "$value" || [[ $kind == A && $IP_FAMILY != 4 || $kind == AAAA && $IP_FAMILY != 6 ]]; then
            malformed=1
            continue
          fi
          if [[ $kind == A && ! ${seen_a[$IP_NORMALIZED]+yes} ]]; then
            dns_a+=("$IP_NORMALIZED")
            seen_a[$IP_NORMALIZED]=1
          elif [[ $kind == AAAA && ! ${seen_aaaa[$IP_NORMALIZED]+yes} ]]; then
            dns_aaaa+=("$IP_NORMALIZED")
            seen_aaaa[$IP_NORMALIZED]=1
          fi
          [[ $kind != "$type" ]] || found=1
          ;;
        CNAME)
          if valid_domain "$value"; then
            value=${value%.}
            value=${value,,}
            if [[ ! ${seen_cname[$value]+yes} ]]; then
              dns_cnames+=("$value")
              seen_cname[$value]=1
            fi
            [[ $type != CNAME ]] || found=1
          else
            malformed=1
          fi
          ;;
      esac
    done <<<"$DNS_RESPONSE"
    if ((malformed)); then
      set_check dns "$type" UNKNOWN 'DNS 回答含无法解析的记录'
    elif ((found)); then
      set_check dns "$type" PASS '收到可解析的 DNS 回答'
    else
      set_check dns "$type" PASS 'NOERROR / NODATA：此类型无记录（不等于查询失败）'
    fi
  done
}

select_endpoints() {
  local ip
  local -a candidates=()
  if [[ -n $forced_ip ]]; then
    candidates=("$forced_ip")
    selection_scope=explicit_ip
    selection_reason='仅评估用户指定 IP；域名的其他地址不在结论范围内'
  else
    [[ $family == 6 ]] || candidates+=("${dns_a[@]}")
    [[ $family == 4 ]] || candidates+=("${dns_aaaa[@]}")
    for ip in A AAAA; do
      [[ $family == 4 && $ip == AAAA || $family == 6 && $ip == A ]] && continue
      if [[ ${statuses["dns:$ip"]} != PASS ]]; then
        selection_complete=false
        selection_reason='所选地址族的 DNS 查询失败或结果不完整'
      fi
    done
  fi
  for ip in "${candidates[@]}"; do
    if ((${#endpoints[@]} < MAX_ENDPOINTS)); then
      endpoints+=("$ip")
    else
      selection_complete=false
      selection_reason='解析地址超过 16 个，仅评估前 16 个，不能作出完整结论'
    fi
  done
  if ((${#endpoints[@]} == 0)); then
    selection_complete=false
    selection_reason='所选范围内没有可检测的 IP'
  fi
}

tls_established() {
  # A version banner alone (Cipher NONE / failed handshake) is not success.
  grep -Eq '^(New|Reused), TLSv1\.3, Cipher is TLS_[A-Z0-9_]+' "$1" &&
    grep -q '^-----BEGIN CERTIFICATE-----' "$1" &&
    ! grep -Eqi 'error:.*alert|^SSL alert number ' "$1"
}

check_certificate() {
  local idx=$1 transcript=$2 cert=$workdir/leaf.pem san dates before after now start end verify name matched=0
  awk '/^-----BEGIN CERTIFICATE-----/{p=1} p{print} /^-----END CERTIFICATE-----/{exit}' "$transcript" >"$cert"
  if ! openssl x509 -in "$cert" -noout >/dev/null 2>&1; then return; fi

  verify=$(sed -n 's/^[[:space:]]*Verify return code: \([0-9]*\).*/\1/p' "$transcript" | tail -1)
  if [[ $verify == 0 ]]; then
    set_check "$idx" cert_chain PASS 'OpenSSL 使用本地信任库验证证书链成功（不包含吊销检查）'
  elif [[ $verify =~ ^[0-9]+$ ]]; then
    set_check "$idx" cert_chain FAIL "OpenSSL 证书链验证失败，verify code=$verify（含本地信任库限制）"
  fi

  if san=$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null); then
    # Only DNS SANs; never accept a Common Name fallback. Wildcards span one label.
    while IFS= read -r name; do
      name=${name,,}
      if [[ $name == "$sni" ]]; then
        matched=1
      elif [[ $name == \*.* ]]; then
        name=${name#*.}
        if valid_domain "$name" && [[ ${sni#*.} == "$name" && $sni != "$name" ]]; then matched=1; fi
      fi
    done < <(printf '%s\n' "$san" | tr ',' '\n' | sed -n 's/^[[:space:]]*DNS:\([^[:space:]]*\)[[:space:]]*$/\1/p')
    if ((matched)); then
      set_check "$idx" cert_san PASS '证书 DNS SAN 匹配实际 SNI'
    else
      set_check "$idx" cert_san FAIL '证书 DNS SAN 不匹配实际 SNI，或没有 DNS SAN'
    fi
  fi

  dates=$(openssl x509 -in "$cert" -noout -dates 2>/dev/null) || return
  before=$(sed -n 's/^notBefore=//p' <<<"$dates")
  after=$(sed -n 's/^notAfter=//p' <<<"$dates")
  cert_before[idx]=$before
  cert_after[idx]=$after
  start=$(date -u -d "$before" +%s 2>/dev/null) || return
  end=$(date -u -d "$after" +%s 2>/dev/null) || return
  now=$(date -u +%s)
  if ((now < start || now > end)); then
    set_check "$idx" cert_validity FAIL '本机时钟下证书尚未生效或已经过期'
  else
    set_check "$idx" cert_validity PASS '本机时钟下证书位于有效期内'
    if ((end - now < 604800)); then
      set_check "$idx" cert_expiry WARN '证书将在 7 天内过期'
    else
      set_check "$idx" cert_expiry PASS '证书剩余有效期至少 7 天'
    fi
  fi
}

check_tls() {
  local idx=$1 address=$2 rc file=$workdir/tls.txt xfile=$workdir/x25519.txt
  local -a args=(-connect "$address" -servername "$sni" -tls1_3 -showcerts -verify 10 -purpose sslserver)
  [[ $ssl_help == *-tls1_3* ]] || return
  if [[ $ssl_help == *-alpn* ]]; then args+=(-alpn 'h2,http/1.1'); fi
  bounded openssl s_client "${args[@]}" </dev/null >"$file" 2>&1
  rc=$?
  if tls_established "$file"; then
    set_check "$idx" tls13 PASS '已完成 TLS 1.3 握手并协商实际密码套件'
    if [[ $ssl_help == *-alpn* ]]; then
      if grep -q '^ALPN protocol: h2$' "$file"; then
        set_check "$idx" alpn_h2 PASS '服务端实际通过 ALPN 选择 h2'
      elif grep -Eq '^(ALPN protocol: |No ALPN negotiated)' "$file"; then
        set_check "$idx" alpn_h2 FAIL 'TLS 1.3 握手成功，但未协商 h2'
      fi
    fi
    check_certificate "$idx" "$file"
    if grep -Eq '(Server|Peer) Temp Key: X25519(,|$)' "$file"; then
      set_check "$idx" x25519 PASS '握手实际协商 X25519'
    elif [[ $ssl_help == *-groups* ]]; then
      bounded openssl s_client "${args[@]}" -groups X25519 </dev/null >"$xfile" 2>&1
      rc=$?
      if tls_established "$xfile" && grep -Eq '(Server|Peer) Temp Key: X25519(,|$)' "$xfile"; then
        set_check "$idx" x25519 PASS '仅提供 X25519 的独立 TLS 1.3 握手成功'
      elif ((rc != 124 && rc != 137)) && grep -Eqi 'alert (handshake failure|illegal parameter)' "$xfile"; then
        set_check "$idx" x25519 FAIL '服务端明确拒绝了仅提供 X25519 的握手（当前探测条件下）'
      fi
    fi
  elif ((rc != 124 && rc != 137)) && grep -Eqi 'alert protocol version' "$file"; then
    set_check "$idx" tls13 FAIL '服务端明确返回 protocol_version 告警，拒绝 TLS 1.3'
  fi
}

check_http() {
  local idx=$1 ip=$2 resolve_ip=$2 rc meta code protocol remote location
  local -a args=()
  [[ $ip != *:* ]] || resolve_ip="[$ip]"
  [[ $curl_features != *HTTP2* ]] || args+=(--http2)
  meta=$(bounded curl --disable --proxy '' --noproxy '*' --silent --show-error \
    --connect-timeout "$network_timeout" --max-time "$network_timeout" \
    --proto '=https' --head "${args[@]}" --resolve "$sni:443:$resolve_ip" \
    --output /dev/null --dump-header "$workdir/headers" \
    --write-out '%{http_code} %{http_version} %{remote_ip}' "https://$sni/" 2>"$workdir/curl-error")
  rc=$?
  read -r code protocol remote <<<"$meta"
  if ((rc == 0)) && [[ $code =~ ^[1-5][0-9]{2}$ && -n $protocol ]] &&
    normalize_ip "$remote" && [[ $IP_NORMALIZED == "$ip" ]]; then
    http_code[idx]=$code
    http_version[idx]=$protocol
    location=$(sed -n 's/^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[[:space:]]*//p' "$workdir/headers" | tail -1 | clean_text)
    http_location[idx]=$location
    set_check "$idx" https_response PASS "HTTPS HEAD 返回 HTTP $code / HTTP $protocol（状态码不用于否定 TLS）"
    if [[ $code == 3* ]]; then
      set_check "$idx" http_redirect WARN '观察到 HTTP 3xx；记录 Location，未跟随重定向'
    else
      set_check "$idx" http_redirect PASS '本次 HEAD 响应未发生 HTTP 3xx 重定向'
    fi
  elif ((rc == 28 || rc == 124 || rc == 137)); then
    set_check "$idx" https_response UNKNOWN 'HTTPS 操作超时，不能据此判定 TLS 不受支持'
  elif ((rc == 0)); then
    set_check "$idx" https_response UNKNOWN 'curl 未提供有效 HTTP 响应或远端 IP 与定向目标不一致'
  else
    set_check "$idx" https_response UNKNOWN "HTTPS 请求未完成，curl exit=$rc；独立 TLS 结果保留"
  fi
}

asn_lookup() {
  local ip=$1 query='' hex i txt raw number prefix _cc _registry _allocated extra mask expected_family=4
  local txt_pattern='^[^|]+\|[^|]+\|[^|]+\|[^|]+\|[^|]+$'
  local -a octets=()
  ASN_NUMBER='' ASN_ORG=''
  if [[ ${asn_cache_number[$ip]+yes} ]]; then
    ASN_NUMBER=${asn_cache_number[$ip]}
    ASN_ORG=${asn_cache_org[$ip]}
    return
  fi
  if [[ $ip == *:* ]]; then
    expected_family=6
    hex=${ip//:/}
    for ((i = ${#hex} - 1; i >= 0; i--)); do query+=${hex:i:1}.; done
    query+=origin6.asn.cymru.com
  else
    IFS=. read -r -a octets <<<"$ip"
    query=${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.origin.asn.cymru.com
  fi
  if dns_query "$query" TXT && [[ $DNS_CODE == NOERROR ]]; then
    # Multiple TXT answers / MOAS are deliberately not reduced to one ASN.
    raw=$(awk '$3=="IN" && $4=="TXT" {sub(/^[^"]*"/, ""); sub(/"[[:space:]]*$/, ""); print}' <<<"$DNS_RESPONSE")
    if [[ $raw != *$'\n'* && $raw != *\"* && $raw =~ $txt_pattern ]]; then
      IFS='|' read -r number prefix _cc _registry _allocated extra <<<"$raw"
      number=${number//[[:space:]]/}
      prefix=${prefix//[[:space:]]/}
      mask=${prefix##*/}
      if [[ $number =~ ^[1-9][0-9]{0,9}$ && $prefix == */* && $mask =~ ^(0|[1-9][0-9]{0,2})$ ]] &&
        ((number <= 4294967295)) && normalize_ip "${prefix%/*}" &&
        [[ $IP_FAMILY == "$expected_family" ]] && ((mask <= (expected_family == 4 ? 32 : 128))); then
        ASN_NUMBER=$number
        if dns_query "AS$number.asn.cymru.com" TXT && [[ $DNS_CODE == NOERROR ]]; then
          txt=$(awk '$3=="IN" && $4=="TXT" {sub(/^[^"]*"/, ""); sub(/"[[:space:]]*$/, ""); print}' <<<"$DNS_RESPONSE")
          IFS='|' read -r raw _cc _registry _allocated extra <<<"$txt"
          raw=${raw//[[:space:]]/}
          if [[ $raw == "$number" && $txt != *$'\n'* && $txt != *\"* && $txt =~ $txt_pattern && -n $extra ]]; then
            ASN_ORG=$(printf '%s' "$extra" | clean_text)
          fi
        fi
      fi
    fi
  fi
  asn_cache_number[$ip]=$ASN_NUMBER
  asn_cache_org[$ip]=$ASN_ORG
}

check_network() {
  local idx=$1 ip=$2 cname evidence='' number
  asn_lookup "$ip"
  number=$ASN_NUMBER
  endpoint_asn[idx]=$ASN_NUMBER
  endpoint_org[idx]=$ASN_ORG
  if [[ -n $ASN_NUMBER && -n $ASN_ORG ]]; then
    set_check "$idx" asn PASS "Team Cymru 返回 AS$ASN_NUMBER 及组织信息"
  fi
  if [[ -n $origin_ip && $ip == *:* && $origin_ip != *:* || -n $origin_ip && $ip != *:* && $origin_ip == *:* ]]; then
    set_check "$idx" same_asn UNKNOWN '源 IP 与目标 IP 地址族不同，未作跨地址族推断'
  elif [[ -n $origin_asn && -n $number ]]; then
    if [[ $origin_asn == "$number" ]]; then
      set_check "$idx" same_asn PASS '用户指定源 IP 与目标 IP 的 ASN 相同（推荐条件）'
    else
      set_check "$idx" same_asn WARN '用户指定源 IP 与目标 IP 的 ASN 不同（不是协议强制条件）'
    fi
  fi
  case $number in
    13335 | 209242) evidence="Cloudflare ASN AS$number" ;;
    20940 | 16625 | 32787) evidence="Akamai / 共享边缘网络 ASN AS$number" ;;
    54113) evidence='Fastly ASN AS54113' ;;
    16509) evidence='Amazon 共享云 / 边缘网络 AS16509（不能区分 CloudFront 与普通云主机）' ;;
  esac
  for cname in "${dns_cnames[@]}"; do
    case $cname in
      *.cloudflare.net | *.cloudfront.net | *.fastly.net | *.akamaiedge.net | *.akamai.net | *.edgekey.net | *.edgesuite.net)
        evidence+=" CNAME=$cname"
        ;;
    esac
  done
  if [[ -n $evidence ]]; then
    set_check "$idx" cdn WARN "潜在共享 CDN / 云边缘线索：$evidence；请审阅未认证回落的转发滥用风险"
  fi
}

check_endpoint() {
  local idx=$1 ip=$2 address=$2:443 key rc
  [[ $ip != *:* ]] || address="[$ip]:443"
  for key in "${check_keys[@]}"; do
    set_check "$idx" "$key" UNKNOWN '无法验证，或未取得足够证据'
  done
  set_check "$idx" same_asn UNKNOWN '未提供可确认的同地址族 --origin-ip，或 ASN 查询信息不足'
  set_check "$idx" cdn UNKNOWN '未发现已知线索；不能据此排除 CDN / 共享边缘网络'
  # shellcheck disable=SC2016 # $1 is expanded by the child Bash, never evaluated as code.
  bounded bash -c 'exec 3<>"/dev/tcp/$1/443"' _ "$ip" >"$workdir/tcp" 2>&1
  rc=$?
  if ((rc == 0)); then
    set_check "$idx" tcp443 PASS 'TCP 443 连接成功'
    check_tls "$idx" "$address"
    check_http "$idx" "$ip"
  elif grep -qi 'Connection refused' "$workdir/tcp"; then
    set_check "$idx" tcp443 FAIL 'TCP 443 明确拒绝连接'
  else
    set_check "$idx" tcp443 UNKNOWN 'TCP 443 连接未完成（超时、路由或本地网络限制）'
  fi
  check_network "$idx" "$ip"
}

aggregate() {
  local idx key basic=PASS compatibility=PASS ancillary=PASS status
  unknown_count=0 warn_count=0
  for key in A AAAA CNAME; do
    status=${statuses["dns:$key"]}
    [[ $status != UNKNOWN ]] || ((unknown_count += 1))
    [[ $status == PASS ]] || ancillary=WARN
  done
  for ((idx = 0; idx < ${#endpoints[@]}; idx++)); do
    for key in "${check_keys[@]}"; do
      status=${statuses["$idx:$key"]}
      [[ $status != UNKNOWN ]] || ((unknown_count += 1))
      [[ $status != WARN ]] || ((warn_count += 1))
      case " $basic_keys " in
        *" $key "*)
          if [[ $status == FAIL ]]; then basic=FAIL; elif [[ $status == UNKNOWN && $basic != FAIL ]]; then basic=UNKNOWN; fi
          ;;
      esac
      case $key in
        alpn_h2 | x25519)
          if [[ $status == FAIL ]]; then compatibility=FAIL; elif [[ $status == UNKNOWN && $compatibility != FAIL ]]; then compatibility=UNKNOWN; fi
          ;;
        cert_expiry | https_response | http_redirect | asn | same_asn | cdn)
          [[ $status == PASS ]] || ancillary=WARN
          ;;
      esac
    done
  done
  if ((${#endpoints[@]} == 0)); then
    basic=UNKNOWN
    compatibility=UNKNOWN
  fi
  basic_status=$basic compatibility_status=$compatibility ancillary_status=$ancillary
  if [[ $basic == FAIL || $compatibility == FAIL ]]; then
    overall=FAIL exit_code=1
    summary_reason='至少一个已检测 IP 不满足候选检查条件；见对应 FAIL 项'
  elif [[ $basic == UNKNOWN || $compatibility == UNKNOWN || $selection_complete != true ]]; then
    overall=UNKNOWN exit_code=2
    summary_reason='基础或兼容性证据不足，或地址集合未完整检测'
  elif [[ $ancillary != PASS ]]; then
    overall=WARN exit_code=3
    summary_reason='所选 IP 的基础及兼容性检查通过，但附加风险或未知项需要审阅'
  else
    overall=PASS exit_code=0
    summary_reason='所选范围的检查均通过'
  fi
}

emit_json() {
  local idx key type dns_a_json dns_aaaa_json cnames_json endpoints_file=$workdir/endpoints.jsonl
  : >"$workdir/checks.jsonl"
  : >"$endpoints_file"
  : >"$workdir/dns.jsonl"
  for type in A AAAA CNAME; do
    jq -cn --arg type "$type" --arg status "${statuses["dns:$type"]}" --arg reason "${reasons["dns:$type"]}" \
      '{type:$type,status:$status,reason:$reason}' >>"$workdir/dns.jsonl" || fatal SERIALIZE 'JSON 序列化失败'
  done
  for ((idx = 0; idx < ${#endpoints[@]}; idx++)); do
    for key in "${check_keys[@]}"; do
      jq -cn --argjson endpoint "$idx" --arg id "$key" --arg status "${statuses["$idx:$key"]}" \
        --arg reason "${reasons["$idx:$key"]}" \
        '{endpoint:$endpoint,id:$id,status:$status,reason:$reason}' >>"$workdir/checks.jsonl" || fatal SERIALIZE 'JSON 序列化失败'
    done
    jq -cn --argjson idx "$idx" --arg ip "${endpoints[$idx]}" \
      --arg asn "${endpoint_asn[$idx]:-}" --arg org "${endpoint_org[$idx]:-}" \
      --arg code "${http_code[$idx]:-}" --arg protocol "${http_version[$idx]:-}" \
      --arg location "${http_location[$idx]:-}" --arg before "${cert_before[$idx]:-}" --arg after "${cert_after[$idx]:-}" \
      --slurpfile checks "$workdir/checks.jsonl" \
      '{ip:$ip,family:(if ($ip|contains(":")) then 6 else 4 end),
        asn:($asn|if .=="" then null else . end),organization:($org|if .=="" then null else . end),
        certificate:{not_before:$before,not_after:$after},
        http:{status_code:($code|if .=="" then null else tonumber end),version:$protocol,location:$location},
        checks:[$checks[]|select(.endpoint==$idx)|del(.endpoint)]}' >>"$endpoints_file" || fatal SERIALIZE 'JSON 序列化失败'
  done
  dns_a_json=$(jq -cn --args '$ARGS.positional' "${dns_a[@]}") || fatal SERIALIZE 'JSON 序列化失败'
  dns_aaaa_json=$(jq -cn --args '$ARGS.positional' "${dns_aaaa[@]}") || fatal SERIALIZE 'JSON 序列化失败'
  cnames_json=$(jq -cn --args '$ARGS.positional' "${dns_cnames[@]}") || fatal SERIALIZE 'JSON 序列化失败'
  jq -n --arg schema "$SCHEMA_VERSION" --arg version "$VERSION" --arg target "$target" --arg sni "$sni" \
    --arg origin_ip "$origin_ip" --arg origin_asn "$origin_asn" --arg origin_org "$origin_org" \
    --arg scope "$selection_scope" --argjson complete "$selection_complete" \
    --arg selection_reason "$selection_reason" --arg summary_reason "$summary_reason" \
    --argjson a "$dns_a_json" --argjson aaaa "$dns_aaaa_json" --argjson cnames "$cnames_json" \
    --slurpfile dns "$workdir/dns.jsonl" --slurpfile endpoints "$endpoints_file" \
    --arg basic "$basic_status" --arg compatibility "$compatibility_status" --arg ancillary "$ancillary_status" \
    --arg overall "$overall" --argjson exit_code "$exit_code" --argjson timeout "$network_timeout" \
    --arg openssl "$openssl_version" --arg curl "$curl_version" \
    '{schema_version:$schema,tool_version:$version,target:$target,sni:$sni,port:443,
      timeout_seconds:$timeout,tools:{openssl:$openssl,curl:$curl},
      origin:{ip:($origin_ip|if .=="" then null else . end),asn:($origin_asn|if .=="" then null else . end),organization:$origin_org,source:"user_supplied_only"},
      selection:{scope:$scope,complete:$complete,limit:16,reason:$selection_reason},dns:{a:$a,aaaa:$aaaa,cnames:$cnames,checks:$dns},
      endpoints:$endpoints,
      risks:[$endpoints[]|.ip as $ip|.checks[]|select(.status=="WARN")|{ip:$ip,id,status,reason}],
      unknowns:([$dns[]|select(.status=="UNKNOWN")|{scope:"dns",id:.type,reason}]+
        [$endpoints[]|.ip as $ip|.checks[]|select(.status=="UNKNOWN")|{scope:$ip,id,reason}]),
      summary:{basic_tls:$basic,compatibility:$compatibility,ancillary:$ancillary,status:$overall,exit_code:$exit_code,reason:$summary_reason}}' || fatal SERIALIZE 'JSON 序列化失败'
}

emit_text() {
  local idx key type
  printf 'reality-target-checker %s\n目标: %s  SNI: %s  TCP: 443\n' "$VERSION" "$target" "$sni"
  for type in A AAAA CNAME; do
    printf '[%-7s] DNS %-5s %s\n' "${statuses["dns:$type"]}" "$type" "${reasons["dns:$type"]}"
  done
  printf 'A: %s\nAAAA: %s\nCNAME: %s\n' "${dns_a[*]:-无}" "${dns_aaaa[*]:-无}" "${dns_cnames[*]:-无}"
  for ((idx = 0; idx < ${#endpoints[@]}; idx++)); do
    printf '\nIP: %s  ASN: %s  %s\n' "${endpoints[$idx]}" "${endpoint_asn[$idx]:-UNKNOWN}" "${endpoint_org[$idx]:-}"
    for key in "${check_keys[@]}"; do
      printf '[%-7s] %-16s %s\n' "${statuses["$idx:$key"]}" "$key" "${reasons["$idx:$key"]}"
    done
    if [[ -n ${cert_after[$idx]:-} ]]; then printf '证书有效期: %s → %s\n' "${cert_before[$idx]}" "${cert_after[$idx]}"; fi
    if [[ -n ${http_location[$idx]:-} ]]; then printf 'Location: %s\n' "${http_location[$idx]}"; fi
  done
  printf '\n基础 TLS: %s | H2/X25519 兼容性: %s | 附加指标: %s\n' "$basic_status" "$compatibility_status" "$ancillary_status"
  printf '最终: %s | 地址集合完整: %s | WARN: %s | UNKNOWN: %s | 退出码: %s\n' "$overall" "$selection_complete" "$warn_count" "$unknown_count" "$exit_code"
  printf '%s\n范围: %s\n' "$summary_reason" "$selection_reason"
  printf '结果仅适用于本次网络路径和已检测 IP；不保证所有 REALITY 实现均可用或抗封锁。\n'
}

main() {
  set -uo pipefail
  export LC_ALL=C
  local arg command='' dependency idx
  json=0 network_timeout=5 family=all target='' sni='' forced_ip='' origin_ip=''
  # Detect JSON before validation so invalid invocations still produce JSON.
  for arg in "$@"; do [[ $arg != --json ]] || json=1; done
  ((BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3))) || fatal DEPENDENCY '需要 Bash 4.3 或更新版本'
  if [[ ${1:-} == discover ]]; then
    shift
    dispatch_discover "$@"
    return $?
  fi
  while (($#)); do
    case $1 in
      --help | -h)
        usage
        return 0
        ;;
      --version)
        printf '%s\n' "$VERSION"
        return 0
        ;;
      --json)
        json=1
        shift
        ;;
      --timeout | --sni | --ip | --origin-ip)
        (($# >= 2)) || fatal USAGE "选项 $1 缺少值"
        case $1 in
          --timeout) network_timeout=$2 ;;
          --sni) sni=$2 ;;
          --ip) forced_ip=$2 ;;
          --origin-ip) origin_ip=$2 ;;
        esac
        [[ -n $2 ]] || fatal USAGE '选项值不能为空'
        shift 2
        ;;
      --ipv4 | --ipv6)
        arg=${1#--ipv}
        [[ $family == all || $family == "$arg" ]] || fatal USAGE '--ipv4 和 --ipv6 不能同时使用'
        family=$arg
        shift
        ;;
      -*) fatal USAGE "未知选项: $1" ;;
      *)
        if [[ -z $command ]]; then command=$1; elif [[ -z $target ]]; then target=$1; else fatal USAGE '存在多余的位置参数'; fi
        shift
        ;;
    esac
  done
  [[ $command == check && -n $target ]] || fatal USAGE '用法: reality-target-checker.sh check DOMAIN [选项]'
  [[ $network_timeout =~ ^([1-9]|[1-5][0-9]|60)$ ]] || fatal USAGE '--timeout 必须为 1..60 的整数'
  valid_domain "$target" || fatal USAGE '目标必须是有效 ASCII 域名（IDN 请使用 punycode），不包含 URL 或端口'
  target=${target%.} target=${target,,}
  sni=${sni:-$target}
  valid_domain "$sni" || fatal USAGE '--sni 必须是有效域名'
  sni=${sni%.} sni=${sni,,}
  if [[ -n $forced_ip ]]; then
    normalize_ip "$forced_ip" || fatal USAGE '--ip 不是有效的 IPv4 / IPv6 地址'
    forced_ip=$IP_NORMALIZED
    [[ $family == all || $family == "$IP_FAMILY" ]] || fatal USAGE '--ip 与地址族选项不一致'
  fi
  if [[ -n $origin_ip ]]; then
    normalize_ip "$origin_ip" || fatal USAGE '--origin-ip 不是有效的 IPv4 / IPv6 地址'
    origin_ip=$IP_NORMALIZED
  fi
  for dependency in bash openssl curl dig timeout mktemp date sed awk grep tr head tail rm; do
    command -v "$dependency" >/dev/null 2>&1 || fatal DEPENDENCY "缺少依赖: $dependency（参见 README）"
  done
  if ((json)); then command -v jq >/dev/null 2>&1 || fatal DEPENDENCY 'JSON 模式需要 jq'; fi
  date -u -d 'Jan 1 2026 GMT' +%s >/dev/null 2>&1 || fatal DEPENDENCY '需要 GNU date（Linux coreutils）'
  umask 077
  workdir=$(mktemp -d "${TMPDIR:-/tmp}/reality-target-checker.XXXXXXXX") || fatal TEMP '无法创建临时目录'
  trap 'rm -rf -- "$workdir"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  declare -gA statuses=() reasons=() asn_cache_number=() asn_cache_org=()
  declare -ga dns_a=() dns_aaaa=() dns_cnames=() endpoints=()
  declare -ga endpoint_asn=() endpoint_org=() cert_before=() cert_after=() http_code=() http_version=() http_location=()
  declare -ga check_keys=(tcp443 tls13 alpn_h2 cert_chain cert_san cert_validity x25519 cert_expiry https_response http_redirect asn same_asn cdn)
  basic_keys='tcp443 tls13 cert_chain cert_san cert_validity'
  selection_scope=dns selection_complete=true origin_asn='' origin_org=''
  selection_reason='评估本次 DNS 回答中所选地址族的全部去重地址'
  ssl_help=$(openssl s_client -help 2>&1)
  openssl_version=$(openssl version | head -1 | clean_text)
  curl_features=$(curl --disable --version)
  curl_version=$(head -1 <<<"$curl_features" | clean_text)
  collect_dns
  select_endpoints
  if [[ -n $origin_ip ]]; then
    asn_lookup "$origin_ip"
    origin_asn=$ASN_NUMBER origin_org=$ASN_ORG
  fi
  for ((idx = 0; idx < ${#endpoints[@]}; idx++)); do check_endpoint "$idx" "${endpoints[$idx]}"; done
  aggregate
  if ((json)); then emit_json; else emit_text; fi
  return "$exit_code"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
