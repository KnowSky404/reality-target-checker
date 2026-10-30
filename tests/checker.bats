#!/usr/bin/env bats
# Bats isolates tests and supplies $stderr; these variables intentionally cross
# process boundaries only through exports.
# shellcheck disable=SC2030,SC2031,SC2154
bats_require_minimum_version 1.5.0

setup_file() {
  /usr/bin/openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$BATS_FILE_TMPDIR/key.pem" -out "$BATS_FILE_TMPDIR/cert.pem" \
    -subj /CN=wrong-cn.test -addext 'subjectAltName=DNS:example.test,DNS:alt.example.test,DNS:*.wild.example.test' \
    -days 365 >/dev/null 2>&1
}

setup() {
  export REPO_ROOT="$BATS_TEST_DIRNAME/.."
  export MOCK_CERT="$BATS_FILE_TMPDIR/cert.pem" MOCK_CASE='' MOCK_LOG="$BATS_TEST_TMPDIR/calls"
  mkdir "$BATS_TEST_TMPDIR/bin"
  for tool in dig openssl curl timeout; do ln -s "$BATS_TEST_DIRNAME/helpers/mock-command" "$BATS_TEST_TMPDIR/bin/$tool"; done
  export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
  checker="$REPO_ROOT/reality-target-checker.sh"
}

check() { run --separate-stderr bash "$checker" check example.test --json --ipv4 "$@"; }
assert_jq() { printf '%s\n' "$output" | jq -e "$1" >/dev/null; }
assert_check() { assert_jq ".endpoints[0].checks | any(.id == \"$1\" and .status == \"$2\")"; }

@test 'help and version work without network' {
  run bash "$checker" --version
  [ "$status" -eq 0 ]
  [ "$output" = 0.2.0 ]
  run bash "$checker" --help
  [ "$status" -eq 0 ]
  [ ! -f "$MOCK_LOG" ]
}

@test 'standalone Bash check reports a missing optional discovery helper as discovery JSON' {
  standalone="$BATS_TEST_TMPDIR/standalone"
  mkdir "$standalone"
  cp "$checker" "$standalone/reality-target-checker.sh"
  run --separate-stderr bash "$standalone/reality-target-checker.sh" discover 192.0.2.0/24 --json
  [ "$status" -eq 2 ]
  assert_jq '.report_type=="discovery" and .tool_version=="0.2.0" and .error.code=="DEPENDENCY" and .summary.exit_code==2'
  [[ $stderr == *'reality-target-discover.py'* ]]
  [ ! -f "$MOCK_LOG" ]
}

@test 'discovery without Python produces dependency JSON before any network operation' {
  isolated="$BATS_TEST_TMPDIR/no-python"
  mkdir "$isolated"
  ln -s "$(command -v dirname)" "$isolated/dirname"
  run --separate-stderr env PATH="$isolated" /bin/bash "$checker" discover 192.0.2.0/24 --json
  [ "$status" -eq 2 ]
  assert_jq '.report_type=="discovery" and .error.code=="DEPENDENCY" and .summary.status=="UNKNOWN"'
  [[ $stderr == *'Python >= 3.9'* ]]
  [ ! -f "$MOCK_LOG" ]
}

@test 'valid handshake keeps CDN uncertainty visible with exit 3 and stable envelope' {
  check --origin-ip 192.0.2.20
  [ "$status" -eq 3 ]
  [ -z "$stderr" ]
  assert_jq '.schema_version=="1.0" and .tool_version=="0.2.0" and .summary.basic_tls=="PASS" and .summary.compatibility=="PASS" and .summary.status=="WARN" and .summary.exit_code==3 and .selection.complete and (.endpoints|length)==1'
  assert_check cdn UNKNOWN
  assert_check same_asn PASS
  assert_check asn PASS
  assert_jq '.endpoints[0].organization | contains("Test Network")'
}

@test 'HTTP1-only ALPN cannot pass H2' {
  export MOCK_CASE=no_h2
  check
  [ "$status" -eq 1 ]
  assert_check alpn_h2 FAIL
  assert_jq '.summary.basic_tls=="PASS" and .summary.compatibility=="FAIL"'
}

@test 'missing ALPN evidence is UNKNOWN' {
  export MOCK_CASE=unknown_alpn
  check
  [ "$status" -eq 2 ]
  assert_check alpn_h2 UNKNOWN
}

@test 'explicit protocol-version alert fails TLS13' {
  export MOCK_CASE=tls12
  check
  [ "$status" -eq 1 ]
  assert_check tls13 FAIL
}

@test 'version banners and verify zero without a completed handshake never pass' {
  export MOCK_CASE=tls_ambiguous
  check
  [ "$status" -eq 2 ]
  assert_check tls13 UNKNOWN
  assert_check cert_chain UNKNOWN
}

@test 'OpenSSL EOF after completed handshake does not erase actual evidence' {
  export MOCK_CASE=eof_after_handshake
  check
  [ "$status" -eq 3 ]
  assert_check tls13 PASS
}

@test 'old OpenSSL capabilities are UNKNOWN, not PASS' {
  export MOCK_CASE=old_openssl
  check
  [ "$status" -eq 2 ]
  assert_check tls13 UNKNOWN
  assert_check x25519 UNKNOWN
}

@test 'untrusted chain fails even if TLS negotiates' {
  export MOCK_CASE=bad_chain
  check
  [ "$status" -eq 1 ]
  assert_check cert_chain FAIL
  assert_check tls13 PASS
}

@test 'SNI controls handshake hostname, HTTPS Host and SAN verification' {
  check --sni alt.example.test
  [ "$status" -eq 3 ]
  assert_check cert_san PASS
  assert_jq '.sni=="alt.example.test"'
  grep -q -- '-servername alt.example.test' "$MOCK_LOG"
  grep -q 'https://alt.example.test/' "$MOCK_LOG"
}

@test 'SAN mismatch fails independently of chain validation' {
  check --sni mismatch.test
  [ "$status" -eq 1 ]
  assert_check cert_san FAIL
  assert_check cert_chain PASS
}

@test 'CN fallback is never accepted in place of SAN' {
  export MOCK_CASE=cn_only
  check --sni wrong-cn.test
  [ "$status" -eq 1 ]
  assert_check cert_san FAIL
}

@test 'wildcard SAN matches exactly one label' {
  check --sni one.wild.example.test
  [ "$status" -eq 3 ]
  assert_check cert_san PASS
  check --sni two.one.wild.example.test
  [ "$status" -eq 1 ]
  assert_check cert_san FAIL
}

@test 'expired and future certificates fail validity' {
  export MOCK_CASE=expired
  check
  [ "$status" -eq 1 ]
  assert_check cert_validity FAIL
  export MOCK_CASE=future
  check
  [ "$status" -eq 1 ]
  assert_check cert_validity FAIL
}

@test 'soon-expiring certificate warns without failing basic TLS' {
  export MOCK_CASE=expiring
  check
  [ "$status" -eq 3 ]
  assert_check cert_validity PASS
  assert_check cert_expiry WARN
}

@test 'X25519 can be confirmed by a constrained second handshake' {
  export MOCK_CASE=force_x25519
  check
  [ "$status" -eq 3 ]
  assert_check x25519 PASS
  grep -q -- '-groups X25519' "$MOCK_LOG"
}

@test 'explicit refusal of constrained X25519 is a compatibility failure' {
  export MOCK_CASE=x25519_fail
  check
  [ "$status" -eq 1 ]
  assert_check x25519 FAIL
}

@test 'unobservable group is UNKNOWN' {
  export MOCK_CASE=unknown_key
  check
  [ "$status" -eq 2 ]
  assert_check x25519 UNKNOWN
}

@test 'HTTP 403 and 405 do not invalidate successful TLS' {
  for code in 403 405; do
    export MOCK_CASE=http$code
    check
    [ "$status" -eq 3 ]
    assert_check https_response PASS
    assert_jq ".summary.basic_tls==\"PASS\" and .endpoints[0].http.status_code==$code"
  done
}

@test 'redirects are recorded, not followed' {
  export MOCK_CASE=redirect
  check
  [ "$status" -eq 3 ]
  assert_check http_redirect WARN
  assert_jq '.endpoints[0].http.location=="https://elsewhere.test/" and .endpoints[0].http.version=="2"'
  run ! grep -q -- '--location' "$MOCK_LOG"
}

@test 'HTTP timeout and wrong remote IP cannot be called successful' {
  for scenario in http_timeout wrong_remote http_error; do
    export MOCK_CASE=$scenario
    check
    [ "$status" -eq 3 ]
    assert_check https_response UNKNOWN
    assert_jq '.summary.basic_tls=="PASS"'
  done
}

@test 'TCP timeout is UNKNOWN; connection refused is FAIL' {
  export MOCK_CASE=tcp_timeout
  check
  [ "$status" -eq 2 ]
  assert_check tcp443 UNKNOWN
  run ! grep -q -- '-servername' "$MOCK_LOG"
  export MOCK_CASE=tcp_refused
  check
  [ "$status" -eq 1 ]
  assert_check tcp443 FAIL
}

@test 'TLS timeout is UNKNOWN' {
  export MOCK_CASE=tls_timeout
  check
  [ "$status" -eq 2 ]
  assert_check tls13 UNKNOWN
}

@test 'all DNS addresses are evaluated and duplicate answers removed' {
  export MOCK_CASE=duplicate
  run --separate-stderr bash "$checker" check example.test --json
  [ "$status" -eq 3 ]
  assert_jq '(.endpoints|length)==2 and (.dns.a|length)==1 and .endpoints[1].family==6'
}

@test 'one failed address cannot be hidden by another good address' {
  export MOCK_CASE=second_ip_fail
  check
  [ "$status" -eq 1 ]
  assert_jq '(.endpoints|length)==2 and .summary.basic_tls=="FAIL"'
}

@test 'partial DNS failure is incomplete, never a full pass' {
  export MOCK_CASE=aaaa_timeout
  run --separate-stderr bash "$checker" check example.test --json
  [ "$status" -eq 2 ]
  assert_jq '.selection.complete==false and .summary.status=="UNKNOWN" and (.endpoints|length)==1'
  check
  [ "$status" -eq 3 ]
  assert_jq '.selection.complete==true'
}

@test 'NXDOMAIN, empty DNS and DNS timeouts never qualify a domain' {
  for scenario in nxdomain nodata dns_timeout; do
    export MOCK_CASE=$scenario
    check
    [ "$status" -eq 2 ]
    assert_jq '(.endpoints|length)==0 and .summary.status=="UNKNOWN"'
  done
}

@test 'explicit IP remains usable when DNS is unavailable and scope is explicit' {
  export MOCK_CASE=dns_timeout
  check --ip 192.0.2.10
  [ "$status" -eq 3 ]
  assert_jq '.selection.scope=="explicit_ip" and .selection.complete and (.dns.checks|all(.status=="UNKNOWN"))'
}

@test 'invalid DNS answers are UNKNOWN and address cap is explicit' {
  export MOCK_CASE=bad_dns
  check
  [ "$status" -eq 2 ]
  assert_jq '.dns.checks | any(.type=="AAAA" and .status=="PASS")'
  export MOCK_CASE=too_many
  check
  [ "$status" -eq 2 ]
  assert_jq '(.endpoints|length)==16 and .selection.complete==false'
}

@test 'IPv6 pin uses bracketed endpoint and full reversed nibbles for ASN' {
  run --separate-stderr bash "$checker" check example.test --json --ipv6 --ip 2001:db8::10 --origin-ip 2001:db8::20
  [ "$status" -eq 3 ]
  assert_jq '.endpoints[0].ip=="2001:0db8:0000:0000:0000:0000:0000:0010" and .endpoints[0].family==6'
  assert_check same_asn PASS
  grep -q 'origin6.asn.cymru.com' "$MOCK_LOG"
  grep -Fq '0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6' "$MOCK_LOG"
}

@test 'no origin autodiscovery, cross-family comparison stays unknown' {
  check
  assert_check same_asn UNKNOWN
  check --origin-ip 2001:db8::20
  assert_check same_asn UNKNOWN
  run ! grep -Eq 'ipify|ifconfig|ipinfo' "$MOCK_LOG"
}

@test 'different ASN is a recommendation warning' {
  export MOCK_CASE=different_asn
  check --origin-ip 192.0.2.20
  [ "$status" -eq 3 ]
  assert_check same_asn WARN
  assert_jq '.summary.basic_tls=="PASS"'
}

@test 'MOAS and unavailable ASN are UNKNOWN instead of guessed' {
  for scenario in moas asn_timeout malformed_asn; do
    export MOCK_CASE=$scenario
    check --origin-ip 192.0.2.20
    [ "$status" -eq 3 ]
    assert_check asn UNKNOWN
    assert_check same_asn UNKNOWN
    assert_jq '.endpoints[0].asn==null'
  done
}

@test 'known shared ASN and CDN CNAME are risks, not automatic TLS failures' {
  for scenario in cdn cname; do
    export MOCK_CASE=$scenario
    check
    [ "$status" -eq 3 ]
    assert_check cdn WARN
    assert_jq '.summary.basic_tls=="PASS" and (.risks|any(.id=="cdn"))'
  done
}

@test 'hostile domain, IP, SNI, timeout and conflicting family fail before networking' {
  # shellcheck disable=SC2016 # Intentionally pass hostile input literally.
  for value in 'https://example.test' 'example.test:443' '-example.test' 'a..test' 'example.test..' 'a/../test' 'x$(touch /tmp/rtc-injected).test' \
    '0x7f000001' '0X7F000001' '0x7f.1' '127.0.0.0x1' '0x7f.0.0.1'; do
    run --separate-stderr bash "$checker" check "$value" --json
    [ "$status" -eq 2 ]
    assert_jq '.error.code=="USAGE"'
    [ ! -f "$MOCK_LOG" ]
  done
  for value in '01.2.3.4' '256.0.0.1' '1:2:3' '1:::2' 'fe80::1%eth0' '1.2.3.4;id'; do
    check --ip "$value"
    [ "$status" -eq 2 ]
    assert_jq '.error.code=="USAGE"'
  done
  check --timeout 0
  [ "$status" -eq 2 ]
  check --timeout 1.5
  [ "$status" -eq 2 ]
  for value in 'x;id' '0x7f000001' '0X7F000001' '0x7f.1' '127.0.0.0x1' '0x7f.0.0.1'; do
    check --sni "$value"
    [ "$status" -eq 2 ]
    assert_jq '.error.code=="USAGE"'
    [ ! -f "$MOCK_LOG" ]
  done
  run bash -c 'source "$1"; valid_domain "$2"' _ "$checker" '0xface.example.test'
  [ "$status" -eq 0 ]
  check --ipv6
  [ "$status" -eq 2 ]
  [ ! -f "$MOCK_LOG" ]
}

@test 'temporary files are removed on normal completion' {
  mkdir "$BATS_TEST_TMPDIR/temp"
  export TMPDIR="$BATS_TEST_TMPDIR/temp"
  check
  [ "$status" -eq 3 ]
  [ -z "$(ls -A "$TMPDIR")" ]
}

@test 'text mode does not need jq and remains readable' {
  run --separate-stderr bash "$checker" check example.test --ipv4
  [ "$status" -eq 3 ]
  [[ $output == *'最终: WARN'* ]]
  [[ $output == *'[PASS'* ]]
}

@test 'missing jq returns dependency JSON but text mode still works' {
  isolated="$BATS_TEST_TMPDIR/isolated"
  mkdir "$isolated"
  for tool in bash openssl curl dig timeout mktemp date sed awk grep tr head tail rm cat; do
    ln -s "$(command -v "$tool")" "$isolated/$tool"
  done
  run --separate-stderr env PATH="$isolated" /bin/bash "$checker" check example.test --json
  [ "$status" -eq 2 ]
  assert_jq '.error.code=="DEPENDENCY" and .summary.status=="UNKNOWN"'
  [ ! -f "$MOCK_LOG" ]
  run --separate-stderr env PATH="$isolated" /bin/bash "$checker" check example.test --ipv4
  [ "$status" -eq 3 ]
  [[ $output == *'最终: WARN'* ]]
}

@test 'domain case and one trailing root dot are normalized' {
  run --separate-stderr bash "$checker" check EXAMPLE.TEST. --json --ipv4
  [ "$status" -eq 3 ]
  assert_jq '.target=="example.test" and .sni=="example.test"'
}
