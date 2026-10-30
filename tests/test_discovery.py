"""Offline discovery contract tests; network traffic stays on ephemeral localhost."""

import copy
import concurrent.futures
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "discovery", ROOT / "reality-target-discover.py"
)
discovery = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = discovery
MODULE_SPEC.loader.exec_module(discovery)

IP = "192.0.2.10"
SNI = "example.test"
CURL_NUMERIC_HOSTS = (
    "0x7f000001", "0X7F000001", "0x7f.1", "127.0.0.0x1", "0x7f.0.0.1",
)
CHECK_IDS = (
    "tcp443", "tls13", "alpn_h2", "cert_chain", "cert_san", "cert_validity",
    "x25519", "cert_expiry", "https_response", "http_redirect", "asn",
    "same_asn", "cdn",
)


def checker_report(ip=IP, sni=SNI, status="WARN"):
    """A report shaped like the real pinned-IP Bash checker, with visible risk."""
    report = {
        "schema_version": "1.0", "tool_version": "0.2.0",
        "target": sni, "sni": sni, "port": 443,
        "selection": {"scope": "explicit_ip", "complete": True, "limit": 16},
        "dns": {
            "a": [ip], "aaaa": [], "cnames": [],
            "checks": [{"type": kind, "status": "PASS", "reason": "observed"}
                       for kind in ("A", "AAAA", "CNAME")],
        },
        "endpoints": [{
            "ip": ip, "family": 4, "asn": "64500", "organization": "Test Network",
            "certificate": {"not_before": "2026-01-01", "not_after": "2027-01-01"},
            "http": {"status_code": 200, "version": "2", "location": ""},
            "checks": [{"id": key, "status": "PASS", "reason": "observed"}
                       for key in CHECK_IDS],
        }],
        "risks": [], "unknowns": [],
        "summary": {"basic_tls": "PASS", "compatibility": "PASS",
                    "ancillary": "PASS", "status": "PASS", "exit_code": 0},
    }
    if status == "WARN":
        report["endpoints"][0]["checks"][-1]["status"] = "UNKNOWN"
        report["unknowns"] = [{"scope": ip, "id": "cdn", "reason": "not proven"}]
        report["summary"].update(ancillary="WARN", status="WARN", exit_code=3)
    elif status in ("FAIL", "UNKNOWN"):
        change_check(report, "x25519", status)
        report["summary"].update(compatibility=status, status=status,
                                 exit_code=1 if status == "FAIL" else 2)
    return report


def change_check(report, key, status):
    for item in report["endpoints"][0]["checks"]:
        if item["id"] == key:
            item["status"] = status
            return
    raise AssertionError(key)


def ptr_answer(ip, *names, rcode="NOERROR"):
    owner = ipaddress.ip_address(ip).reverse_pointer
    return (f";; ->>HEADER<<- opcode: QUERY, status: {rcode}, id: 1\n" +
            "".join(f"{owner}. 60 IN PTR {name}\n" for name in names))


def classless_ptr_answer(ip=IP):
    owner = ipaddress.ip_address(ip).reverse_pointer
    return (ptr_answer(ip) +
            f"{owner}. 60 IN CNAME 10.0/25.2.0.192.in-addr.arpa.\n"
            "10.0/25.2.0.192.in-addr.arpa. 60 IN PTR Example.TEST.\n")


def tls_alert_error():
    error = ssl.SSLError(ssl.SSL_ERROR_SSL, "tlsv1 alert unrecognized name")
    error.reason = "TLSV1_ALERT_UNRECOGNIZED_NAME"
    return error


def host_result(ip, names=None, issues=None):
    return {"ip": ip, "tcp": "OPEN", "tls": "CERTIFICATE", "ptr": "COMPLETE",
            "names": {SNI: ["san"]} if names is None else names,
            "wildcards": [], "issues": issues or [], "completed": True}


class ArgumentsAndNames(unittest.TestCase):
    def test_cidr_host_semantics_and_budget(self):
        args = discovery.parse_args(["192.0.2.0/31"])
        self.assertEqual(list(map(str, args.cidr.hosts())), ["192.0.2.0", "192.0.2.1"])
        args = discovery.parse_args(["192.0.2.10/32", "--max-hosts", "1"])
        self.assertEqual(list(map(str, args.cidr.hosts())), [IP])
        args = discovery.parse_args(["192.0.2.0/24"])
        self.assertEqual(len(list(args.cidr.hosts())), 254)

    def test_invalid_scope_and_options_are_rejected(self):
        cases = [
            [], ["2001:db8::/64"], ["192.0.2.1/24"], ["192.0.02.0/24"],
            ["192.0.2.10"], ["192.0.2.0/255.255.255.0"], ["192.0.2.0/024"],
            ["https://example.test/"], ["192.0.2.0/24", "extra"],
            ["192.0.0.0/16"], ["192.0.2.0/31", "--max-hosts", "1"],
            ["192.0.2.0/24", "--max-hosts", "4097"],
            ["192.0.2.0/24", "--concurrency", "0"],
            ["192.0.2.0/24", "--concurrency", "33"],
            ["192.0.2.0/24", "--rate", "101"],
            ["192.0.2.0/24", "--timeout", "0"],
            ["192.0.2.0/24", "--deadline", "3601"],
            ["192.0.2.0/24", "--max-candidates", "0"],
            ["192.0.2.0/24", "--origin-ip", "::1"],
            ["192.0.2.0/24", "--origin-ip", "192.0.02.1"],
        ]
        for argv in cases:
            with self.subTest(argv=argv), mock.patch("sys.stderr"):
                with self.assertRaises((SystemExit, ValueError)):
                    discovery.parse_args(argv)

    def test_name_normalization_never_accepts_shell_or_wildcard_seeds(self):
        self.assertEqual(discovery.normalize_name("WWW.Example.TEST."), "www.example.test")
        self.assertEqual(discovery.normalize_name("xn--bcher-kva.example"), "xn--bcher-kva.example")
        self.assertEqual(discovery.normalize_name("0xface.example.test"), "0xface.example.test")
        for name in ("*.example.test", "192.0.2.1", "https://example.test", "a..test",
                     "bad_name.test", "-bad.test", "bad-.test", "a" * 64 + ".test",
                     "bad\x1b[2J.test", "$(touch /tmp/no).test", "éxample.test", "K.test",
                     *CURL_NUMERIC_HOSTS):
            with self.subTest(name=name):
                self.assertIsNone(discovery.normalize_name(name))

    def test_san_deduplicates_names_and_retains_wildcard_as_evidence(self):
        names, wildcards, truncated = discovery.parse_san(
            "X509v3 Subject Alternative Name:\n"
            " DNS:Example.TEST, DNS:example.test., DNS:*.Wild.TEST, "
            "IP Address:192.0.2.1, DNS:bad_name.test, URI:https://elsewhere.test, " +
            ", ".join(f"DNS:{name}" for name in CURL_NUMERIC_HOSTS) +
            ", DNS:0xface.example.test\n"
        )
        self.assertEqual(names, ["0xface.example.test", SNI])
        self.assertEqual(wildcards, ["*.wild.test"])
        self.assertFalse(truncated)

    def test_san_budget_applies_after_deduplication(self):
        names, _, truncated = discovery.parse_san(
            "X509v3 Subject Alternative Name:\n " +
            ", ".join(f"DNS:n{i}.test" for i in range(20))
        )
        self.assertEqual(len(names), 16)
        self.assertTrue(truncated)
        names, _, truncated = discovery.parse_san(
            ", ".join(["DNS:example.test"] * 30)
        )
        self.assertEqual(names, [SNI])
        self.assertFalse(truncated)

    def test_malformed_san_values_are_not_truncated_into_valid_seeds(self):
        names, wildcards, truncated = discovery.parse_san(
            "X509v3 Subject Alternative Name:\n"
            " DNS:space.test invalid, DNS:tab.test\tinvalid, "
            "DNS:carriage.test\rinvalid, DNS:escape.test\x1b[2J, "
            "DNS:continuation.test\\ninvalid, DNS:*.wild.test invalid, DNS:valid.test\n"
        )
        self.assertEqual(names, ["valid.test"])
        self.assertEqual(wildcards, [])
        self.assertFalse(truncated)

    def test_ptr_accepts_only_correct_owner_and_normalizes(self):
        response = ptr_answer(IP, "Example.TEST.", "example.test.", "bad_name.test.",
                              "0xface.example.test.", *(name + "." for name in CURL_NUMERIC_HOSTS))
        response += "11.2.0.192.in-addr.arpa. 60 IN PTR unrelated.test.\n"
        self.assertEqual(discovery.parse_ptr(response, IP), ["0xface.example.test", SNI])

    def test_failed_or_unstructured_ptr_cannot_supply_names(self):
        for response in (ptr_answer(IP, "example.test.", rcode="SERVFAIL"),
                         "example.test.\n", ptr_answer(IP, "*.example.test.")):
            with self.subTest(response=response):
                try:
                    names = discovery.parse_ptr(response, IP)
                except (ValueError, discovery.DiscoveryError):
                    continue
                self.assertEqual(names, [])

    def test_rfc2317_classless_reverse_alias_is_followed_in_answer(self):
        self.assertEqual(discovery.parse_ptr(classless_ptr_answer(), IP), [SNI])

    def test_ptr_follows_multihop_unordered_aliases_and_ignores_unrelated_data(self):
        owner = ipaddress.ip_address(IP).reverse_pointer
        response = (
            ptr_answer(IP) +
            "final.0/25.2.0.192.in-addr.arpa. 60 IN PTR Example.TEST.\n"
            "unrelated.in-addr.arpa. 60 IN PTR unrelated.test.\n"
            "unrelated-loop.in-addr.arpa. 60 IN CNAME unrelated-loop.in-addr.arpa.\n"
            "step.0/25.2.0.192.in-addr.arpa. 60 IN CNAME FINAL.0/25.2.0.192.in-addr.arpa.\n"
            f"{owner}. 60 IN CNAME STEP.0/25.2.0.192.in-addr.arpa.\n"
        )
        self.assertEqual(discovery.parse_ptr(response, IP), [SNI])

    def test_ptr_rejects_reachable_alias_cycles_conflicts_and_excessive_depth(self):
        owner = ipaddress.ip_address(IP).reverse_pointer
        nodes = [owner] + [f"hop{i}.0/25.2.0.192.in-addr.arpa" for i in range(1, 18)]
        deep_chain = "".join(f"{left}. 60 IN CNAME {right}.\n"
                             for left, right in zip(nodes, nodes[1:]))
        bad_records = [
            f"{owner}. 60 IN CNAME cycle.in-addr.arpa.\n"
            f"cycle.in-addr.arpa. 60 IN CNAME {owner}.\n",
            f"{owner}. 60 IN CNAME one.in-addr.arpa.\n"
            f"{owner}. 60 IN CNAME two.in-addr.arpa.\n",
            f"{owner}. 60 IN CNAME alias.in-addr.arpa.\n"
            f"{owner}. 60 IN PTR example.test.\n",
            deep_chain + f"{nodes[-1]}. 60 IN PTR example.test.\n",
        ]
        for records in bad_records:
            with self.subTest(records=records), self.assertRaises(discovery.DiscoveryError):
                discovery.parse_ptr(ptr_answer(IP) + records, IP)

    def test_ptr_allows_exactly_sixteen_alias_hops(self):
        owner = ipaddress.ip_address(IP).reverse_pointer
        nodes = [owner] + [f"hop{i}.0/25.2.0.192.in-addr.arpa" for i in range(1, 17)]
        records = "".join(f"{left}. 60 IN CNAME {right}.\n"
                          for left, right in zip(nodes, nodes[1:]))
        records += f"{nodes[-1]}. 60 IN PTR example.test.\n"
        self.assertEqual(discovery.parse_ptr(ptr_answer(IP) + records, IP), [SNI])


class CheckerValidation(unittest.TestCase):
    def test_warn_candidate_is_eligible_and_risk_evidence_is_preserved(self):
        report = checker_report()
        before = copy.deepcopy(report)
        self.assertTrue(discovery.validate_report(report, 3, IP, SNI))
        self.assertEqual(report, before)
        self.assertEqual(report["unknowns"][0]["id"], "cdn")

    def test_confirmed_failure_and_unknown_are_not_eligible(self):
        for status, code in (("FAIL", 1), ("UNKNOWN", 2)):
            with self.subTest(status=status):
                self.assertFalse(discovery.validate_report(checker_report(status=status), code, IP, SNI))

    def test_all_pass_is_eligible(self):
        self.assertTrue(discovery.validate_report(checker_report(status="PASS"), 0, IP, SNI))

    def test_wrong_identity_scope_and_returncode_are_rejected(self):
        mutations = [
            lambda r: r.update(schema_version="2.0"),
            lambda r: r.update(target="other.test"),
            lambda r: r.update(sni="other.test"),
            lambda r: r.update(port=8443),
            lambda r: r["selection"].update(scope="dns"),
            lambda r: r["selection"].update(complete=False),
            lambda r: r["selection"].update(complete="true"),
            lambda r: r["endpoints"][0].update(ip="192.0.2.11"),
            lambda r: r["endpoints"].append(copy.deepcopy(r["endpoints"][0])),
            lambda r: r.update(endpoints=[]),
            lambda r: r["summary"].update(exit_code=0),
            lambda r: r["summary"].update(status="PASS"),
        ]
        for mutate in mutations:
            report = checker_report()
            mutate(report)
            with self.subTest(report=report), self.assertRaises(ValueError):
                discovery.validate_report(report, 3, IP, SNI)
        with self.assertRaises(ValueError):
            discovery.validate_report(checker_report(), 0, IP, SNI)

    def test_missing_duplicate_or_contradictory_critical_checks_are_rejected(self):
        report = checker_report()
        report["endpoints"][0]["checks"] = [item for item in report["endpoints"][0]["checks"]
                                             if item["id"] != "tls13"]
        bad_reports = [report]
        report = checker_report()
        report["endpoints"][0]["checks"].append(
            {"id": "tls13", "status": "FAIL", "reason": "conflicting"})
        bad_reports.append(report)
        report = checker_report()
        change_check(report, "cert_san", "FAIL")
        bad_reports.append(report)
        report = checker_report()
        change_check(report, "x25519", "UNKNOWN")
        bad_reports.append(report)
        for report in bad_reports:
            with self.subTest(report=report), self.assertRaises(ValueError):
                discovery.validate_report(report, 3, IP, SNI)

    def test_error_envelopes_and_invalid_types_are_rejected(self):
        for report in (None, [], {}, {"schema_version": "1.0", "error": {"code": "DEPENDENCY"},
                                      "summary": {"status": "UNKNOWN", "exit_code": 2}}):
            with self.subTest(report=report), self.assertRaises(ValueError):
                discovery.validate_report(report, 2, IP, SNI)

    def test_dns_binding_keeps_failed_lookup_distinct_from_different_address(self):
        report = checker_report()
        self.assertEqual(discovery.dns_binding(report, IP), "MATCH")
        report["dns"]["a"] = ["192.0.2.11"]
        self.assertEqual(discovery.dns_binding(report, IP), "DIFFERENT")
        report["dns"]["a"] = []
        self.assertEqual(discovery.dns_binding(report, IP), "DIFFERENT")
        report["dns"]["checks"][0]["status"] = "UNKNOWN"
        self.assertEqual(discovery.dns_binding(report, IP), "UNKNOWN")
        self.assertEqual(discovery.dns_binding({}, IP), "UNKNOWN")


class RuntimeLifecycle(unittest.TestCase):
    def test_subprocess_returns_bytes_and_nonzero_status(self):
        runtime = discovery.Runtime(timeout=1, deadline=3, rate=100)
        try:
            code, out, err = runtime.run(
                [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"]
            )
            self.assertEqual((code, out, err), (3, b"out\n", b"err\n"))
        finally:
            runtime.close()

    def test_deadline_terminates_child_process_group(self):
        with tempfile.TemporaryDirectory(prefix="rtc-discovery-process-") as directory:
            pid_path = Path(directory) / "pid"
            script = (
                "import subprocess, sys, time; from pathlib import Path; "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                "Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(30)"
            )
            runtime = discovery.Runtime(timeout=3, deadline=0.4, rate=100)
            started = time.monotonic()
            try:
                with self.assertRaises(discovery.DiscoveryError):
                    runtime.run([sys.executable, "-c", script, str(pid_path)])
            finally:
                runtime.close()
            self.assertLess(time.monotonic() - started, 2)
            self.assertTrue(pid_path.exists(), "test child never started")
            child_pid = int(pid_path.read_text())
            proc_stat = Path(f"/proc/{child_pid}/stat")
            until = time.monotonic() + 0.5
            while True:
                try:
                    state = proc_stat.read_text().split()[2]
                except FileNotFoundError:
                    break
                if state == "Z":
                    break
                self.assertLess(time.monotonic(), until, "live descendant survived deadline")
                time.sleep(0.01)

    def test_cancelled_runtime_starts_no_child(self):
        runtime = discovery.Runtime(timeout=1, deadline=2, rate=100)
        runtime.cancelled.set()
        try:
            with mock.patch.object(subprocess, "Popen") as popen:
                with self.assertRaises(discovery.DiscoveryError):
                    runtime.run([sys.executable, "-c", "raise SystemExit(0)"])
                popen.assert_not_called()
        finally:
            runtime.close()

    def test_oversized_child_output_is_unknown(self):
        runtime = discovery.Runtime(timeout=2, deadline=3, rate=100)
        try:
            with self.assertRaises(discovery.DiscoveryError):
                runtime.run([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 8388608)"])
        finally:
            runtime.close()

    def test_concurrent_launches_share_rate_budget(self):
        runtime = discovery.Runtime(timeout=1, deadline=3, rate=10)

        def acquire():
            runtime.acquire()
            return time.monotonic()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                starts = sorted(pool.map(lambda _: acquire(), range(4)))
            self.assertGreaterEqual(starts[-1] - starts[0], 0.25)
            self.assertLess(starts[-1] - starts[0], 1)
        finally:
            runtime.close()

    def run_blocked_real_checker(self, *, cancel=False, ignore_term=False):
        """GNU timeout gives dig its own pgrp; all groups and Bash temp need cleanup."""
        with tempfile.TemporaryDirectory(prefix="rtc-discovery-timeout-") as directory:
            directory = Path(directory)
            mock_bin = directory / "bin"
            mock_bin.mkdir()
            checker_tmp = directory / "checker-tmp"
            checker_tmp.mkdir()
            pid_path = directory / "pids"
            dig = mock_bin / "dig"
            dig.write_text(
                "#!/usr/bin/env bash\n" +
                ("trap '' TERM\n" if ignore_term else "") +
                "sleep 30 &\n"
                "sleep_pid=$!\n"
                "printf '%s\\n' \"$PPID\" \"$$\" \"$sleep_pid\" >\"$RTC_TEST_PID_FILE\"\n"
                "wait \"$sleep_pid\"\n"
            )
            dig.chmod(0o755)
            env = {
                "PATH": str(mock_bin) + os.pathsep + os.environ["PATH"],
                "TMPDIR": str(checker_tmp), "RTC_TEST_PID_FILE": str(pid_path),
            }
            runtime = discovery.Runtime(timeout=60, deadline=3 if cancel else 0.6, rate=100)
            observer_stop = threading.Event()

            def cancel_after_dig_starts():
                while not observer_stop.wait(0.01):
                    try:
                        ready = len(pid_path.read_text().split()) == 3
                    except FileNotFoundError:
                        ready = False
                    if ready:
                        runtime.cancelled.set()
                        return

            observer = None
            if cancel:
                observer = threading.Thread(target=cancel_after_dig_starts, daemon=True)
                observer.start()
            started = time.monotonic()
            try:
                try:
                    with mock.patch.dict(os.environ, env):
                        with self.assertRaises(discovery.DiscoveryError):
                            runtime.run([
                                "bash", str(ROOT / "reality-target-checker.sh"), "check", SNI,
                                "--ip", IP, "--json", "--timeout", "60",
                            ])
                finally:
                    observer_stop.set()
                    if observer:
                        observer.join(timeout=1)
                    runtime.close()
                self.assertLess(time.monotonic() - started, 2)
                self.assertTrue(pid_path.exists(), "blocked dig did not start")
                pids = [int(value) for value in pid_path.read_text().split()]
                self.assertEqual(len(pids), 3, "timeout, dig and sleep PIDs were not all recorded")
                until = time.monotonic() + 0.5
                while True:
                    live = []
                    for pid in pids:
                        try:
                            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                        except FileNotFoundError:
                            continue
                        if state != "Z":
                            live.append((pid, state))
                    if not live or time.monotonic() >= until:
                        break
                    time.sleep(0.01)
                self.assertEqual(live, [], "GNU timeout process group survived: %s" % live)
                self.assertEqual(list(checker_tmp.glob("reality-target-checker.*")), [],
                                 "Bash EXIT trap did not remove checker temporary directory")
            finally:
                # A failing regression must not leave its own sleeping processes behind.
                if pid_path.exists():
                    for value in pid_path.read_text().split():
                        try:
                            os.kill(int(value), signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_deadline_cleans_real_checker_timeout_group_and_temp_directory(self):
        self.run_blocked_real_checker()

    def test_cancellation_cleans_term_ignoring_timeout_group_and_temp_directory(self):
        self.run_blocked_real_checker(cancel=True, ignore_term=True)


class ScanContract(unittest.TestCase):
    def run_scan(self, argv, discover=None, report_status="WARN", runtime_deadline=5):
        args = discovery.parse_args(argv)
        runtime = discovery.Runtime(timeout=1, deadline=runtime_deadline, rate=100)
        calls = []

        def run(args, input_data=None, timeout=None):
            calls.append(args)
            ip = args[args.index("--ip") + 1]
            sni = args[args.index("--sni") + 1]
            report = checker_report(ip=ip, sni=sni, status=report_status)
            return report["summary"]["exit_code"], json.dumps(report).encode(), b""

        try:
            with mock.patch.object(discovery, "discover_host", side_effect=discover or (lambda ip, runtime: host_result(ip))), \
                    mock.patch.object(runtime, "run", side_effect=run):
                report = discovery.scan(args, runtime)
            return report, calls
        finally:
            runtime.close()

    def test_pinned_warn_candidates_survive_and_sources_are_kept(self):
        report, calls = self.run_scan(["192.0.2.10/32", "--origin-ip", "192.0.2.20"])
        self.assertEqual(report["report_type"], "discovery")
        self.assertEqual(report["summary"]["exit_code"], 3)
        self.assertTrue(report["scan"]["complete"])
        self.assertEqual(len(report["candidates"]), 1)
        candidate = report["candidates"][0]
        self.assertEqual((candidate["ip"], candidate["sni"]), (IP, SNI))
        self.assertTrue(candidate["eligible"])
        self.assertEqual(candidate["dns_binding"], "MATCH")
        self.assertEqual(candidate["report"]["unknowns"][0]["id"], "cdn")
        self.assertIn("san", candidate["sources"])
        self.assertEqual(len(calls), 1)
        args = calls[0]
        for option in ("--ipv4", "--json"):
            self.assertIn(option, args)
        self.assertEqual(args[args.index("--origin-ip") + 1], "192.0.2.20")

    def test_global_candidate_cap_reports_incomplete_instead_of_silent_loss(self):
        report, calls = self.run_scan(["192.0.2.0/31", "--max-candidates", "1"])
        self.assertFalse(report["scan"]["complete"])
        self.assertEqual(report["summary"]["exit_code"], 2)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(report["candidates"]), 1)

    def test_rejected_candidates_do_not_become_eligible(self):
        report, _ = self.run_scan(["192.0.2.10/32"], report_status="FAIL")
        self.assertFalse(report["candidates"][0]["eligible"])
        self.assertEqual(report["summary"]["exit_code"], 1)
        report, _ = self.run_scan(["192.0.2.10/32"], report_status="UNKNOWN")
        self.assertFalse(report["candidates"][0]["eligible"])
        self.assertEqual(report["summary"]["exit_code"], 2)

    def test_completed_empty_discovery_is_not_an_execution_error(self):
        report, calls = self.run_scan(
            ["192.0.2.0/31"], discover=lambda ip, runtime: host_result(ip, names={})
        )
        self.assertTrue(report["scan"]["complete"])
        self.assertEqual(report["summary"]["exit_code"], 1)
        self.assertEqual(report["candidates"], [])
        self.assertEqual(calls, [])

    def test_deadline_before_dispatch_keeps_uncompleted_hosts_visible(self):
        args = discovery.parse_args(["192.0.2.0/31"])
        runtime = discovery.Runtime(timeout=1, deadline=0, rate=100)
        try:
            with mock.patch.object(discovery, "connect_socket") as connect:
                report = discovery.scan(args, runtime)
            connect.assert_not_called()
            self.assertFalse(report["scan"]["complete"])
            self.assertEqual(report["summary"]["exit_code"], 2)
            self.assertEqual(report["scan"]["hosts_completed"], 0)
            self.assertEqual(len(report["hosts"]), 2)
            self.assertIn("DEADLINE", report["scan"]["reasons"])
        finally:
            runtime.close()

    def test_cancellation_preserves_signal_exit_status(self):
        args = discovery.parse_args(["192.0.2.10/32"])
        runtime = discovery.Runtime(timeout=1, deadline=1, rate=100)
        runtime.signal_number = signal.SIGTERM
        runtime.cancelled.set()
        try:
            with mock.patch.object(discovery, "connect_socket") as connect:
                report = discovery.scan(args, runtime)
            connect.assert_not_called()
            self.assertFalse(report["scan"]["complete"])
            self.assertEqual(report["summary"]["exit_code"], 143)
        finally:
            runtime.close()

    def test_discovery_pool_obeys_concurrency_and_sorts_results(self):
        active = 0
        maximum = 0
        lock = threading.Lock()

        def discover(ip, runtime):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            try:
                time.sleep(0.025)
                return host_result(ip)
            finally:
                with lock:
                    active -= 1

        report, _ = self.run_scan(["192.0.2.0/29", "--concurrency", "2"], discover=discover)
        self.assertEqual(maximum, 2)
        self.assertEqual([item["ip"] for item in report["candidates"]],
                         [f"192.0.2.{i}" for i in range(1, 7)])

    def test_malformed_checker_output_remains_unknown(self):
        args = discovery.parse_args(["192.0.2.10/32"])
        runtime = discovery.Runtime(timeout=1, deadline=2, rate=100)
        try:
            with mock.patch.object(discovery, "discover_host", return_value=host_result(IP)), \
                    mock.patch.object(runtime, "run", return_value=(0, b"not-json", b"")):
                report = discovery.scan(args, runtime)
            self.assertFalse(report["scan"]["complete"])
            self.assertEqual(report["summary"]["exit_code"], 2)
            self.assertFalse(report["candidates"][0]["eligible"])
            self.assertEqual(report["candidates"][0]["error"], "CHECKER_REPORT")
        finally:
            runtime.close()

    def test_unverified_seed_is_retained_when_discovery_exhausts_deadline(self):
        args = discovery.parse_args(["192.0.2.10/32"])
        runtime = discovery.Runtime(timeout=1, deadline=2, rate=100)

        def discover(ip, runtime):
            runtime.deadline = time.monotonic()
            return host_result(ip)

        try:
            with mock.patch.object(discovery, "discover_host", side_effect=discover), \
                    mock.patch.object(runtime, "run") as run:
                report = discovery.scan(args, runtime)
            run.assert_not_called()
            self.assertEqual(len(report["candidates"]), 1)
            candidate = report["candidates"][0]
            self.assertEqual((candidate["ip"], candidate["sni"]), (IP, SNI))
            self.assertFalse(candidate["eligible"])
            self.assertIsNone(candidate["report"])
            self.assertIsNotNone(candidate["error"])
            self.assertFalse(report["scan"]["complete"])
            self.assertEqual(report["summary"]["exit_code"], 2)
        finally:
            runtime.close()


class DiscoveryFallback(unittest.TestCase):
    def test_tls_refusal_still_uses_ptr_seed(self):
        runtime = discovery.Runtime(timeout=1, deadline=2, rate=100)
        connection = mock.MagicMock()
        context = mock.MagicMock()
        context.wrap_socket.side_effect = tls_alert_error()
        try:
            with mock.patch.object(discovery, "connect_socket", return_value=connection), \
                    mock.patch.object(ssl, "SSLContext", return_value=context), \
                    mock.patch.object(runtime, "run", return_value=(0, ptr_answer(IP, "Example.TEST.").encode(), b"")):
                result = discovery.discover_host(IP, runtime)
            self.assertEqual(result["tcp"], "OPEN")
            self.assertEqual(result["names"], {SNI: ["ptr"]})
            self.assertTrue(result["completed"])
            self.assertEqual(result["issues"], [])
        finally:
            runtime.close()

    def test_ptr_name_limit_is_not_silently_complete(self):
        runtime = discovery.Runtime(timeout=1, deadline=2, rate=100)
        connection = mock.MagicMock()
        context = mock.MagicMock()
        context.wrap_socket.side_effect = tls_alert_error()
        response = ptr_answer(IP, *(f"n{i}.test." for i in range(20)))
        try:
            with mock.patch.object(discovery, "connect_socket", return_value=connection), \
                    mock.patch.object(ssl, "SSLContext", return_value=context), \
                    mock.patch.object(runtime, "run", return_value=(0, response.encode(), b"")):
                result = discovery.discover_host(IP, runtime)
            self.assertEqual(len(result["names"]), 16)
            self.assertIn("NAME_LIMIT", result["issues"])
        finally:
            runtime.close()

    def test_classless_ptr_seed_reaches_verification_after_tls_refusal(self):
        args = discovery.parse_args(["192.0.2.10/32"])
        runtime = discovery.Runtime(timeout=1, deadline=2, rate=100)
        connection = mock.MagicMock()
        context = mock.MagicMock()
        context.wrap_socket.side_effect = tls_alert_error()

        def run(command, input_data=None, timeout=None):
            if command[0] == "dig":
                return 0, classless_ptr_answer().encode(), b""
            self.assertEqual(command[0], "bash")
            self.assertEqual(command[command.index("--ip") + 1], IP)
            self.assertEqual(command[command.index("--sni") + 1], SNI)
            return 3, json.dumps(checker_report()).encode(), b""

        try:
            with mock.patch.object(discovery, "connect_socket", return_value=connection), \
                    mock.patch.object(ssl, "SSLContext", return_value=context), \
                    mock.patch.object(runtime, "run", side_effect=run) as mocked_run:
                report = discovery.scan(args, runtime)
            self.assertEqual(mocked_run.call_count, 2, "CNAME following must not launch extra DNS requests")
            self.assertTrue(report["scan"]["complete"])
            self.assertEqual(report["summary"]["exit_code"], 3)
            self.assertEqual(len(report["candidates"]), 1)
            self.assertEqual(report["candidates"][0]["sources"], ["ptr"])
            self.assertTrue(report["candidates"][0]["eligible"])
        finally:
            runtime.close()


class SocketConnections(unittest.TestCase):
    def redirected_socket_factory(self, port):
        """Keep production port 443 logic while using an unprivileged local port."""
        real_socket = socket.socket
        case = self

        class RedirectedSocket:
            def __init__(self, *args, **kwargs):
                self.socket = real_socket(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(self.socket, name)

            def connect_ex(self, address):
                case.assertEqual(address, ("127.0.0.1", 443))
                return self.socket.connect_ex(("127.0.0.1", port))

        return RedirectedSocket

    def test_nonblocking_connect_reaches_ephemeral_local_listener(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        runtime = discovery.Runtime(timeout=1, deadline=2, rate=100)
        try:
            with mock.patch.object(socket, "socket", side_effect=self.redirected_socket_factory(port)):
                connection = discovery.connect_socket("127.0.0.1", runtime)
            with connection.socket:
                self.assertEqual(connection.getpeername(), ("127.0.0.1", port))
        finally:
            runtime.close()
            listener.close()

    def test_nonblocking_connect_reports_local_refusal(self):
        unused = socket.socket()
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
        unused.close()
        runtime = discovery.Runtime(timeout=1, deadline=2, rate=100)
        try:
            with mock.patch.object(socket, "socket", side_effect=self.redirected_socket_factory(port)):
                with self.assertRaises(ConnectionRefusedError):
                    discovery.connect_socket("127.0.0.1", runtime)
        finally:
            runtime.close()

    def test_cancellation_interrupts_unresponsive_tls_with_long_operation_timeout(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(1)
        port = listener.getsockname()[1]
        accepted = threading.Event()
        stop = threading.Event()
        runtime = discovery.Runtime(timeout=60, deadline=5, rate=100)

        def serve():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                accepted.set()
                stop.wait(2)

        def cancel_after_handshake_starts():
            if accepted.wait(1):
                time.sleep(0.1)
                runtime.cancelled.set()

        server = threading.Thread(target=serve, daemon=True)
        canceller = threading.Thread(target=cancel_after_handshake_starts, daemon=True)
        server.start()
        canceller.start()

        def connect(ip, runtime):
            self.assertEqual(ip, IP)
            return socket.create_connection(("127.0.0.1", port), timeout=1)

        started = time.monotonic()
        try:
            with mock.patch.object(discovery, "connect_socket", side_effect=connect), \
                    mock.patch.object(runtime, "run") as run:
                result = discovery.discover_host(IP, runtime)
            self.assertLess(time.monotonic() - started, 1)
            self.assertTrue(accepted.is_set())
            self.assertIn("CANCELLED", result["issues"])
            self.assertFalse(result["completed"])
            self.assertEqual(result["names"], {})
            run.assert_not_called()
        finally:
            runtime.close()
            stop.set()
            listener.close()
            server.join(timeout=2)
            canceller.join(timeout=2)


class LocalDiscoveryTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="rtc-discovery-tls-")
        cls.directory = Path(cls.temp.name)
        cls.cert = cls.directory / "cert.pem"
        cls.key = cls.directory / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(cls.key),
             "-out", str(cls.cert), "-subj", "/CN=untrusted.test", "-addext",
             "subjectAltName=DNS:example.test,DNS:*.wild.test", "-days", "2"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def scan_local_peer(self, serve_connection, *, ptr_names=()):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(1)
        port = listener.getsockname()[1]

        def serve():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(1)
                try:
                    serve_connection(conn)
                except (ssl.SSLError, OSError):
                    pass  # TLS alert rejection and peer close are expected paths.

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        runtime = discovery.Runtime(timeout=1, deadline=3, rate=100)

        def connect(ip, runtime):
            self.assertEqual(ip, IP)
            return socket.create_connection(("127.0.0.1", port), timeout=runtime.operation_timeout())

        def run(command, input_data=None, timeout=None):
            if command[0] == "dig":
                return 0, ptr_answer(IP, *ptr_names).encode(), b""
            self.assertEqual(command[0], "bash")
            return 3, json.dumps(checker_report()).encode(), b""

        try:
            with mock.patch.object(discovery, "connect_socket", side_effect=connect), \
                    mock.patch.object(runtime, "run", side_effect=run):
                return discovery.scan(discovery.parse_args(["192.0.2.10/32"]), runtime)
        finally:
            runtime.close()
            listener.close()
            thread.join(timeout=2)

    def test_premature_tls_eof_with_empty_ptr_is_unknown_incomplete_scan(self):
        def close_after_client_hello(conn):
            conn.recv(65536)
            conn.shutdown(socket.SHUT_WR)

        report = self.scan_local_peer(close_after_client_hello)
        self.assertEqual(report["hosts"][0]["tls"], "UNKNOWN")
        self.assertIn("TLS_HANDSHAKE", report["hosts"][0]["issues"])
        self.assertFalse(report["scan"]["complete"])
        self.assertEqual(report["summary"]["exit_code"], 2)
        self.assertEqual(report["candidates"], [])

    def test_plaintext_protocol_response_is_unknown_incomplete_scan(self):
        def respond_with_http(conn):
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")

        report = self.scan_local_peer(respond_with_http)
        self.assertEqual(report["hosts"][0]["tls"], "UNKNOWN")
        self.assertIn("TLS_HANDSHAKE", report["hosts"][0]["issues"])
        self.assertFalse(report["scan"]["complete"])
        self.assertEqual(report["summary"]["exit_code"], 2)
        self.assertEqual(report["candidates"], [])

    def test_real_unrecognized_name_alert_preserves_complete_ptr_candidate(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server_names = []

        def reject_name(sock, name, ctx):
            server_names.append(name)
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

        context.set_servername_callback(reject_name)

        def reject_handshake(conn):
            with context.wrap_socket(conn, server_side=True):
                self.fail("server unexpectedly accepted no-SNI handshake")

        report = self.scan_local_peer(reject_handshake, ptr_names=("Example.TEST.",))
        self.assertEqual(server_names, [None])
        self.assertEqual(report["hosts"][0]["tls"], "NO_CERTIFICATE")
        self.assertEqual(report["hosts"][0]["issues"], [])
        self.assertTrue(report["scan"]["complete"])
        self.assertEqual(report["summary"]["exit_code"], 3)
        self.assertEqual(len(report["candidates"]), 1)
        self.assertTrue(report["candidates"][0]["eligible"])
        self.assertEqual(report["candidates"][0]["sources"], ["ptr"])

    def test_real_bash_checker_report_is_accepted_through_mock_network(self):
        with tempfile.TemporaryDirectory(prefix="rtc-discovery-checker-") as directory:
            mock_bin = Path(directory) / "bin"
            mock_bin.mkdir()
            for tool in ("dig", "openssl", "curl", "timeout"):
                (mock_bin / tool).symlink_to(ROOT / "tests/helpers/mock-command")
            log = Path(directory) / "calls"
            env = {
                "PATH": str(mock_bin) + os.pathsep + os.environ["PATH"],
                "MOCK_CERT": str(self.cert), "MOCK_CASE": "", "MOCK_LOG": str(log),
            }
            args = discovery.parse_args(["192.0.2.10/32", "--origin-ip", "192.0.2.20"])
            runtime = discovery.Runtime(timeout=1, deadline=5, rate=100)
            try:
                with mock.patch.dict(os.environ, env), \
                        mock.patch.object(discovery, "connect_socket", side_effect=AssertionError("unexpected network")):
                    candidate = discovery.verify_candidate(
                        {"ip": IP, "sni": SNI, "sources": ["san"]}, args, runtime
                    )
                self.assertIsNone(candidate["error"])
                self.assertTrue(candidate["eligible"])
                self.assertEqual(candidate["dns_binding"], "MATCH")
                report = candidate["report"]
                self.assertEqual(report["summary"]["basic_tls"], "PASS")
                self.assertEqual(report["summary"]["compatibility"], "PASS")
                self.assertEqual(report["summary"]["status"], "WARN")
                self.assertEqual(report["summary"]["exit_code"], 3)
                self.assertEqual(report["endpoints"][0]["asn"], "64500")
                self.assertTrue(any(item["id"] == "cdn" for item in report["unknowns"]))
                commands = log.read_text()
                self.assertIn("-connect 192.0.2.10:443 -servername example.test", commands)
                self.assertIn("--resolve example.test:443:192.0.2.10", commands)
            finally:
                runtime.close()

    def test_real_untrusted_default_certificate_yields_seeds_without_sni(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server_names = []
        context.set_servername_callback(lambda sock, name, ctx: server_names.append(name))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)
        port = listener.getsockname()[1]
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with conn:
                    conn.settimeout(1)
                    try:
                        with context.wrap_socket(conn, server_side=True) as tls:
                            tls.recv(1)
                    except (OSError, ssl.SSLError):
                        pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        real_connect = socket.create_connection
        runtime = discovery.Runtime(timeout=1, deadline=4, rate=100)
        real_run = runtime.run

        def run(args, input_data=None, timeout=None):
            if args[0] == "dig":
                return 0, ptr_answer(IP, "Example.TEST.").encode(), b""
            return real_run(args, input_data=input_data, timeout=timeout)

        def connect(ip, runtime):
            self.assertEqual(ip, IP)
            return real_connect(("127.0.0.1", port), timeout=runtime.operation_timeout())

        try:
            with mock.patch.object(discovery, "connect_socket", side_effect=connect), \
                    mock.patch.object(runtime, "run", side_effect=run):
                result = discovery.discover_host(IP, runtime)
            self.assertEqual(result["tcp"], "OPEN")
            self.assertIn(SNI, result["names"])
            self.assertEqual(set(result["names"][SNI]), {"san", "ptr"})
            self.assertIn("*.wild.test", result["wildcards"])
            self.assertNotIn("*.wild.test", result["names"])
            self.assertEqual(server_names, [None])
        finally:
            runtime.close()
            stop.set()
            listener.close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
