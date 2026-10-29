#!/usr/bin/env bats
# Bats supplies stderr and isolates exports in each test process.
# shellcheck disable=SC2154,SC2030,SC2031
bats_require_minimum_version 1.5.0

setup() {
  export MOCK_LOG="$BATS_TEST_TMPDIR/calls"
  export MOCK_DOWNLOAD_DIR="$BATS_TEST_TMPDIR/release"
  mkdir "$BATS_TEST_TMPDIR/bin" "$MOCK_DOWNLOAD_DIR"
  ln -s "$BATS_TEST_DIRNAME/helpers/mock-command" "$BATS_TEST_TMPDIR/bin/curl"
  export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
  example="$BATS_TEST_DIRNAME/../examples/installer-integration.sh"
  cat >"$MOCK_DOWNLOAD_DIR/reality-target-checker.sh" <<'EOF'
#!/usr/bin/env bash
printf 'executed\n' >>"$MOCK_LOG"
cat "$MOCK_DOWNLOAD_DIR/result.json"
exit "${FAKE_RC:-3}"
EOF
  export RTC_SHA256
  RTC_SHA256=$(sha256sum "$MOCK_DOWNLOAD_DIR/reality-target-checker.sh")
  RTC_SHA256=${RTC_SHA256%% *}
  printf '%s  reality-target-checker.sh\n' "$RTC_SHA256" >"$MOCK_DOWNLOAD_DIR/SHA256SUMS"
  printf '%s\n' '{"schema_version":"1.0","tool_version":"0.1.0","selection":{"complete":true},"endpoints":[{}],"summary":{"exit_code":3,"status":"WARN","basic_tls":"PASS","compatibility":"PASS"}}' >"$MOCK_DOWNLOAD_DIR/result.json"
  export FAKE_RC=3
}

@test 'installer verifies pinned release then exposes warnings without accepting them' {
  run --separate-stderr bash "$example" example.test 192.0.2.20
  [ "$status" -eq 3 ]
  printf '%s\n' "$output" | jq -e '.summary.status=="WARN"' >/dev/null
  grep -q '^executed' "$MOCK_LOG"
  grep -q '/releases/download/v0.1.0/reality-target-checker.sh' "$MOCK_LOG"
  [[ $stderr == *'需要审阅'* ]]
}

@test 'tampered script is never executed' {
  printf '\n# changed\n' >>"$MOCK_DOWNLOAD_DIR/reality-target-checker.sh"
  run --separate-stderr bash "$example" example.test
  [ "$status" -eq 2 ]
  [ -z "$output" ]
  run ! grep -q '^executed' "$MOCK_LOG"
}

@test 'untrusted release manifest cannot replace the pinned digest' {
  printf '%064d  reality-target-checker.sh\n' 0 >"$MOCK_DOWNLOAD_DIR/SHA256SUMS"
  run --separate-stderr bash "$example" example.test
  [ "$status" -eq 2 ]
  run ! grep -q '^executed' "$MOCK_LOG"
}

@test 'missing pinned digest stops before downloading' {
  unset RTC_SHA256
  run --separate-stderr bash "$example" example.test
  [ "$status" -eq 2 ]
  [ ! -f "$MOCK_LOG" ]
}

@test 'malformed JSON, inconsistent status and unknown schema are rejected' {
  for payload in '{}' 'not-json' '{"schema_version":"2.0"}' '{"schema_version":"1.0","tool_version":"0.1.0","summary":{"exit_code":0,"status":"PASS"}}'; do
    printf '%s\n' "$payload" >"$MOCK_DOWNLOAD_DIR/result.json"
    run --separate-stderr bash "$example" example.test
    [ "$status" -eq 2 ]
  done
}

@test 'network-incomplete result stays incomplete' {
  export FAKE_RC=2
  printf '%s\n' '{"schema_version":"1.0","tool_version":"0.1.0","summary":{"status":"UNKNOWN","exit_code":2}}' >"$MOCK_DOWNLOAD_DIR/result.json"
  run --separate-stderr bash "$example" example.test
  [ "$status" -eq 2 ]
  printf '%s\n' "$output" | jq -e '.summary.status=="UNKNOWN"' >/dev/null
}

@test 'installer distinguishes an all-pass result from a confirmed failure' {
  export FAKE_RC=0
  printf '%s\n' '{"schema_version":"1.0","tool_version":"0.1.0","selection":{"complete":true},"endpoints":[{}],"summary":{"exit_code":0,"status":"PASS","basic_tls":"PASS","compatibility":"PASS"}}' >"$MOCK_DOWNLOAD_DIR/result.json"
  run --separate-stderr bash "$example" example.test
  [ "$status" -eq 0 ]
  export FAKE_RC=1
  printf '%s\n' '{"schema_version":"1.0","tool_version":"0.1.0","summary":{"exit_code":1,"status":"FAIL"}}' >"$MOCK_DOWNLOAD_DIR/result.json"
  run --separate-stderr bash "$example" example.test
  [ "$status" -eq 1 ]
  printf '%s\n' "$output" | jq -e '.summary.status=="FAIL"' >/dev/null
}
