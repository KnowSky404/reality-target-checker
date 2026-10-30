"""Offline integration coverage for plans, manifests, samples and saved progress."""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

import test_discovery as baseline


discovery = baseline.discovery
IP, SNI = baseline.IP, baseline.SNI
IP6 = ipaddress.IPv6Address("2001:db8::10").exploded


def measurement(seed, status="WARN", elapsed=100):
    report = baseline.checker_report(ip=seed["ip"], sni=seed["sni"], status=status)
    if ":" in seed["ip"]:
        report["endpoints"][0]["family"] = 6
        report["dns"].update(a=[], aaaa=[seed["ip"]])
    return dict(seed, eligible=status in {"PASS", "WARN"}, dns_binding="MATCH",
                report=report, error=None, elapsed_ms=elapsed, observed_at=time.time(),
                evidence_source="live")


def asn_plan():
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {"asn": 64500, "origin_ip": None, "origin_asns": [], "moas": None, "moas_scope": "origin_ip",
            "status": "PASS", "snapshot_time": now, "retrieved_at": now,
            "query_starttime": now, "query_endtime": now,
            "prefixes_v4": ["192.0.2.0/24"], "prefixes_v6": ["2001:db8::/48"],
            "announced_prefixes": ["192.0.2.0/24", "2001:db8::/48"],
            "source": "RIPEstat / RIPE RIS", "cache_hit": False,
            "issues": [], "limitations": list(discovery.module("sources").RIPE_LIMITATIONS)}


class AdvancedWorkflows(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rtc-workflows-")
        self.directory = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def known(self, *ips):
        path = self.directory / "known.txt"
        path.write_text("\n".join(ips) + "\n")
        return str(path)

    def seeds(self, records):
        path = self.directory / "seeds.json"
        path.write_text(json.dumps(records))
        return str(path)

    def scan(self, argv, *, hosts=None, verify=None, plan=None):
        args = discovery.parse_args(argv)
        runtime = discovery.Runtime(timeout=args.timeout, deadline=10, rate=100)
        host_calls, verify_calls = [], []
        lock = threading.Lock()

        def discover_host(ip, current_runtime):
            with lock:
                host_calls.append(ip)
            return (hosts or (lambda address, _runtime: baseline.host_result(address)))(ip, current_runtime)

        def verify_candidate(seed, current_args, current_runtime):
            with lock:
                verify_calls.append((seed["ip"], seed["sni"]))
            return (verify or (lambda candidate, _args, _runtime: measurement(candidate)))(
                seed, current_args, current_runtime)

        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(discovery, "discover_host", side_effect=discover_host))
                stack.enter_context(mock.patch.object(discovery, "verify_candidate", side_effect=verify_candidate))
                stack.enter_context(mock.patch.object(runtime, "run", side_effect=AssertionError("unexpected network command")))
                if plan is not None:
                    stack.enter_context(mock.patch.object(discovery.module("sources"), "build_asn_plan", return_value=plan))
                discovery.prepare_runtime(args, runtime)
                report = discovery.scan(args, runtime)
            return report, host_calls, verify_calls
        finally:
            discovery.close_runtime(runtime)

    def test_advanced_arguments_preserve_single_sample_default_and_reject_invalid_counts(self):
        path = self.known(IP)
        args = discovery.parse_args(["--known-ips", path])
        self.assertEqual((args.samples, args.sample_interval), (1, 0))
        for argv in (["--known-ips", path, "--samples", "0"],
                     ["--known-ips", path, "--samples", "6"],
                     ["--known-ips", path, "--sample-interval", "61"],
                     ["--known-ips", path, "--resume"]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()):
                with self.assertRaises((SystemExit, ValueError)):
                    discovery.parse_args(argv)

    def test_asn_without_explicit_selection_is_only_a_plan(self):
        report, hosts, checks = self.scan(["--asn", "AS64500"], plan=asn_plan())
        self.assertEqual(report["report_type"], "discovery_plan")
        self.assertEqual((hosts, checks), ([], []))
        self.assertIn("192.0.2.0/24", json.dumps(report))

    def test_plan_only_never_probes_even_a_small_cidr(self):
        report, hosts, checks = self.scan(["192.0.2.0/30", "--plan-only"])
        self.assertEqual(report["report_type"], "discovery_plan")
        self.assertEqual((hosts, checks), ([], []))

    def test_duplicate_ipv6_single_host_selection_uses_one_budget_slot(self):
        report, hosts, checks = self.scan(
            ["2001:db8::10/128", "--include-cidr", "2001:db8::10/128", "--max-hosts", "1"])
        self.assertEqual(hosts, [IP6])
        self.assertEqual(checks, [(IP6, SNI)])
        self.assertEqual(report["scope"]["host_count"], 1)
        self.assertEqual(report["plan"]["targets"], [IP6])

    def test_late_asn_metadata_cannot_report_a_successful_plan_or_start_targets(self):
        sources = discovery.module("sources")

        def late_response(*args, **kwargs):
            kwargs["runtime"].deadline = time.monotonic() - 1
            return asn_plan()

        for selection in (["--plan-only"], ["--include-cidr", "192.0.2.0/30"]):
            output = io.StringIO()
            with self.subTest(selection=selection), \
                    mock.patch.object(sources, "build_asn_plan", side_effect=late_response), \
                    mock.patch.object(discovery, "connect_socket") as connect, \
                    mock.patch.object(discovery.Runtime, "run", side_effect=AssertionError("unexpected command")), \
                    redirect_stdout(output), redirect_stderr(io.StringIO()):
                code = discovery.main(["--asn", "AS64500", "--json", *selection])
            self.assertEqual(code, 2)
            connect.assert_not_called()
            report = json.loads(output.getvalue())
            self.assertEqual(report["summary"]["status"], "UNKNOWN")
            self.assertEqual(report["error"]["code"], "DEADLINE")

    def test_moas_is_not_arbitrarily_reduced_to_one_asn(self):
        plan = asn_plan()
        plan.update(asn=None, origin_ip=IP, origin_asns=[64500, 64501], moas=True,
                    status="UNKNOWN", prefixes_v4=[], prefixes_v6=[],
                    issues=["MOAS_REQUIRES_EXPLICIT_ASN"])
        report, hosts, checks = self.scan(["--asn-from-ip", IP], plan=plan)
        self.assertEqual(report["summary"]["exit_code"], 2)
        self.assertEqual((hosts, checks), ([], []))
        self.assertIn("MOAS_REQUIRES_EXPLICIT_ASN", json.dumps(report))

    def test_selected_asn_prefix_does_not_expand_to_the_whole_asn(self):
        report, hosts, _ = self.scan(
            ["--asn", "AS64500", "--include-cidr", "192.0.2.0/30"], plan=asn_plan())
        self.assertEqual(set(hosts), {"192.0.2.1", "192.0.2.2"})
        self.assertTrue(report["scan"]["complete"])

    def test_manifest_limits_cidr_to_known_addresses_and_filters_outside_addresses(self):
        path = self.known("192.0.2.10", "192.0.2.11", "198.51.100.10", "2001:db8::10")
        report, hosts, _ = self.scan(["192.0.2.0/24", "--known-ips", path])
        self.assertEqual(set(hosts), {"192.0.2.10", "192.0.2.11"})
        self.assertEqual({candidate["ip"] for candidate in report["candidates"]}, set(hosts))

    def test_asn_manifest_probes_only_matching_known_ipv4_and_ipv6(self):
        path = self.known(IP, "2001:db8::10", "198.51.100.20", "2001:db9::20")
        report, hosts, _ = self.scan(["--asn", "AS64500", "--known-ips", path], plan=asn_plan())
        self.assertEqual(set(hosts), {IP, IP6})
        self.assertTrue(all(candidate["eligible"] for candidate in report["candidates"]))

    def test_empty_asn_announcement_keeps_manifest_filtering_active(self):
        plan = asn_plan()
        plan.update(prefixes_v4=[], prefixes_v6=[], announced_prefixes=[])
        known = self.known(IP, "2001:db8::10")
        seeds = self.seeds([{"ip": IP, "sni": SNI}])
        for manifest in (["--known-ips", known], ["--seeds", seeds]):
            with self.subTest(manifest=manifest):
                report, hosts, checks = self.scan(["--asn", "AS64500", *manifest], plan=plan)
                self.assertEqual((hosts, checks), ([], []))
                self.assertEqual(report.get("plan", report)["targets"], [])

    def assert_invalid_saved_asn_plan_is_unknown(self, invalid):
        path = self.known(IP)
        checkpoint = str(self.directory / "invalid-asn-plan.sqlite")
        argv = ["--asn", "AS64500", "--known-ips", path, "--checkpoint", checkpoint]
        state = discovery.module("state")
        original_put = state.Checkpoint.put

        def save_invalid_plan(store, kind, key, payload):
            if kind == "meta" and key == "asn_plan":
                payload = invalid
            return original_put(store, kind, key, payload)

        with mock.patch.object(state.Checkpoint, "put", new=save_invalid_plan):
            self.scan(argv, plan=asn_plan())
        output = io.StringIO()
        with mock.patch.object(discovery.module("sources"), "build_asn_plan", return_value=asn_plan()), \
                mock.patch.object(discovery, "connect_socket") as connect, \
                mock.patch.object(discovery.Runtime, "run", side_effect=AssertionError("unexpected command")), \
                redirect_stdout(output), redirect_stderr(io.StringIO()):
            code = discovery.main(argv + ["--resume", "--json"])
        self.assertEqual(code, 2)
        connect.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertEqual(report["summary"]["status"], "UNKNOWN")
        self.assertEqual(report["error"]["code"], "STATE_PLAN")

    def test_malformed_saved_asn_plan_is_a_state_error_without_a_crash(self):
        self.assert_invalid_saved_asn_plan_is_unknown([])

    def test_saved_plan_for_another_asn_cannot_authorize_the_manifest(self):
        invalid = asn_plan()
        invalid["asn"] = 64501
        # The IP remains within these prefixes: rejecting only by membership
        # would miss the mismatched ASN provenance.
        self.assert_invalid_saved_asn_plan_is_unknown(invalid)

    def test_nullable_origin_lookup_in_explicit_asn_checkpoint_restores_normally(self):
        plan = dict(asn_plan(), origin_lookup=None)
        sources = discovery.module("sources")
        self.assertIs(sources.validate_asn_plan(plan, asn=64500), plan)
        checkpoint = str(self.directory / "nullable-origin.sqlite")
        argv = ["--asn", "AS64500", "--known-ips", self.known(IP), "--checkpoint", checkpoint]
        self.scan(argv, plan=plan)
        with mock.patch.object(sources, "build_asn_plan", side_effect=AssertionError("valid checkpoint was refetched")) as provider:
            report, hosts, checks = self.scan(argv + ["--resume"])
        provider.assert_not_called()
        self.assertEqual((hosts, checks), ([], []))
        self.assertIsNone(report["plan"]["asn"]["origin_lookup"])
        self.assertEqual(report["summary"]["exit_code"], 3)
        self.assertTrue(report["candidates"][0]["eligible"])

    def test_composite_asn_plan_does_not_refresh_older_origin_lookup_evidence(self):
        now = float(int(time.time()))

        def utc(stamp):
            return datetime.fromtimestamp(stamp, timezone.utc).isoformat().replace("+00:00", "Z")

        plan = asn_plan()
        plan.update(origin_ip=IP, origin_asns=[64500], moas=False, cache_hit=True,
                    origin_prefix="192.0.2.0/24", snapshot_time=utc(now - 7200),
                    retrieved_at=utc(now), query_starttime=utc(now - 86400), query_endtime=utc(now),
                    origin_lookup={"retrieved_at": utc(now - 59), "cache_hit": True,
                                   "prefix": "192.0.2.0/24", "asns": [64500], "dump_interval_hours": 8})
        sources = discovery.module("sources")
        self.assertIs(sources.validate_asn_plan(plan, origin_ip=IP, now=now), plan)
        checkpoint = str(self.directory / "composite-asn.sqlite")
        argv = ["--asn-from-ip", IP, "--known-ips", self.known(IP),
                "--checkpoint", checkpoint, "--state-ttl", "60"]
        with mock.patch.object(discovery.time, "time", return_value=now):
            self.scan(argv, plan=plan)
        fresh = dict(plan, retrieved_at=utc(now + 2), query_endtime=utc(now + 2), cache_hit=False,
                     origin_lookup=dict(plan["origin_lookup"], retrieved_at=utc(now + 2), cache_hit=False))
        with mock.patch.object(discovery.time, "time", return_value=now + 2), \
                mock.patch.object(sources, "build_asn_plan", return_value=fresh) as provider:
            report, hosts, checks = self.scan(argv + ["--resume"])
        provider.assert_called_once()
        self.assertEqual((hosts, checks), ([], []))
        self.assertEqual(report["plan"]["asn"]["origin_lookup"]["retrieved_at"], utc(now + 2))
        self.assertEqual(report["plan"]["asn"]["snapshot_time"], utc(now - 7200))
        self.assertTrue(report["candidates"][0]["eligible"])

    def test_imported_concrete_sni_can_fill_an_empty_default_certificate(self):
        path = self.seeds([{"ip": IP, "sni": "Imported.TEST.", "source": "fixture"}])
        report, hosts, checks = self.scan(
            ["--seeds", path], hosts=lambda ip, runtime: baseline.host_result(ip, names={}))
        self.assertLessEqual(set(hosts), {IP})
        self.assertEqual(checks, [(IP, "imported.test")])
        candidate = report["candidates"][0]
        self.assertTrue(candidate["eligible"])
        self.assertTrue(candidate["sources"])

    def test_known_ipv6_validation_uses_ipv6_checker_and_aaaa_binding(self):
        args = discovery.parse_args(["--known-ips", self.known("2001:db8::10")])
        runtime = discovery.Runtime(timeout=1, deadline=5, rate=100)
        commands = []

        def run(command, input_data=None, timeout=None):
            commands.append(command)
            candidate = {"ip": IP6, "sni": SNI, "sources": ["san"]}
            result = measurement(candidate)
            return 3, json.dumps(result["report"]).encode(), b""

        try:
            with mock.patch.object(discovery, "discover_host", return_value=baseline.host_result(IP6)), \
                    mock.patch.object(runtime, "run", side_effect=run):
                report = discovery.scan(args, runtime)
            self.assertEqual(len(commands), 1)
            self.assertIn("--ipv6", commands[0])
            self.assertNotIn("--ipv4", commands[0])
            candidate = report["candidates"][0]
            self.assertEqual(candidate["ip"], IP6)
            self.assertEqual(candidate["dns_binding"], "MATCH")
            self.assertTrue(candidate["eligible"])
        finally:
            runtime.close()

    def test_budget_failure_precedes_any_probe(self):
        ips = list(ipaddress.IPv4Network("198.18.0.0/23").hosts())[:257]
        path = self.known(*map(str, ips))
        output = io.StringIO()
        with mock.patch.object(discovery, "connect_socket") as connect, \
                mock.patch.object(discovery.Runtime, "run", side_effect=AssertionError("unexpected command")), \
                redirect_stdout(output), redirect_stderr(io.StringIO()):
            code = discovery.main(["--known-ips", path, "--max-hosts", "256", "--json"])
        self.assertEqual(code, 2)
        connect.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["summary"]["exit_code"], 2)

    def test_kernel_is_only_run_for_basic_candidates_and_unknown_is_not_eligible(self):
        args = discovery.parse_args(["--known-ips", self.known(IP), "--kernel", "xray"])
        kernel = discovery.module("kernel")
        seed = {"ip": IP, "sni": SNI, "sources": ["san"]}
        for base_status, called in (("FAIL", False), ("WARN", True)):
            runtime = discovery.Runtime(timeout=1, deadline=5, rate=100)
            report = measurement(seed, base_status)["report"]
            try:
                with mock.patch.object(runtime, "run", return_value=(report["summary"]["exit_code"],
                                                                        json.dumps(report).encode(), b"")), \
                        mock.patch.object(kernel, "verify", return_value={"status": "UNKNOWN", "error": "KERNEL_HTTP",
                                                                         "elapsed_ms": 10, "kernel": "xray"}) as verify:
                    result = discovery.verify_candidate(seed, args, runtime)
                self.assertFalse(result["eligible"])
                self.assertEqual(verify.called, called)
                if called:
                    self.assertEqual(result["kernel"]["status"], "UNKNOWN")
                    self.assertTrue(result["error"])
            finally:
                runtime.close()

    def test_every_sample_is_retained_and_one_failure_prevents_eligibility(self):
        outcomes = iter(zip(("WARN", "FAIL", "WARN"), (300, 100, 200)))

        def verify(seed, args, runtime):
            status, elapsed = next(outcomes)
            return measurement(seed, status, elapsed)

        report, _, calls = self.scan(["192.0.2.10/32", "--samples", "3"], verify=verify)
        candidate = report["candidates"][0]
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(candidate["measurements"]), 3)
        self.assertFalse(candidate["eligible"])
        self.assertEqual([item["report"]["summary"]["status"] for item in candidate["measurements"]],
                         ["WARN", "FAIL", "WARN"])
        stats = candidate["statistics"]
        self.assertEqual((stats["planned"], stats["completed"], stats["passed"]), (3, 3, 2))
        self.assertAlmostEqual(stats["success_rate"], 2 / 3)
        self.assertEqual((stats["median_ms"], stats["spread_ms"]), (200, 200))
        self.assertEqual(report["summary"]["exit_code"], 1)

    def test_ranking_uses_sample_latency_and_spread_before_numeric_ip(self):
        timings = {"192.0.2.10": iter([300, 300, 300]),
                   "192.0.2.11": iter([200, 200, 200]),
                   "192.0.2.12": iter([180, 200, 220])}
        path = self.known(*timings)

        def verify(seed, args, runtime):
            return measurement(seed, elapsed=next(timings[seed["ip"]]))

        report, _, _ = self.scan(["--known-ips", path, "--samples", "3"], verify=verify)
        self.assertEqual([candidate["ip"] for candidate in report["candidates"]],
                         ["192.0.2.11", "192.0.2.12", "192.0.2.10"])

    def test_seed_cache_avoids_discovery_but_never_replaces_live_verification(self):
        argv = ["--known-ips", self.known(IP), "--cache-dir", str(self.directory / "cache")]
        first, first_hosts, first_checks = self.scan(argv)
        second, second_hosts, second_checks = self.scan(argv)
        self.assertEqual(first_hosts, [IP])
        self.assertEqual(second_hosts, [])
        self.assertEqual((len(first_checks), len(second_checks)), (1, 1))
        self.assertTrue(first["candidates"][0]["eligible"])
        self.assertEqual(second["candidates"][0]["measurements"][0]["evidence_source"], "live")

    def test_empty_discovery_is_not_negative_cached(self):
        argv = ["--known-ips", self.known(IP), "--cache-dir", str(self.directory / "cache")]
        empty = lambda ip, runtime: baseline.host_result(ip, names={})
        first, first_hosts, _ = self.scan(argv, hosts=empty)
        second, second_hosts, _ = self.scan(argv, hosts=empty)
        self.assertEqual((first_hosts, second_hosts), ([IP], [IP]))
        self.assertEqual((first["summary"]["exit_code"], second["summary"]["exit_code"]), (1, 1))

    def test_malformed_cached_host_evidence_is_unknown_without_a_crash(self):
        state = discovery.module("state")
        original_put = state.Cache.put
        path = self.known(IP)
        for index, (field, invalid) in enumerate((("tcp", ["OPEN"]), ("wildcards", ["not-a-wildcard.test"]),
                                                 ("observed_at", time.time() + 3600))):
            cache = str(self.directory / ("invalid-host-" + str(index)))

            def save_invalid_host(store, kind, key, payload):
                if isinstance(payload, dict) and payload.get("ip") == IP and "names" in payload:
                    payload = dict(payload, **{field: invalid})
                return original_put(store, kind, key, payload)

            with self.subTest(field=field), mock.patch.object(state.Cache, "put", new=save_invalid_host):
                self.scan(["--known-ips", path, "--cache-dir", cache])
            report, hosts, checks = self.scan(["--known-ips", path, "--cache-dir", cache])
            self.assertEqual((hosts, checks), ([], []))
            self.assertEqual(report["summary"]["exit_code"], 2)
            self.assertFalse(report["scan"]["complete"])
            self.assertIn("STATE_HOST", report["scan"]["reasons"])

    def test_cached_host_is_saved_to_checkpoint_for_resume_without_cache(self):
        path = self.known(IP)
        cached = ["--known-ips", path, "--cache-dir", str(self.directory / "cache")]
        first, _, _ = self.scan(cached)
        checkpoint = str(self.directory / "from-cache.sqlite")
        second, second_hosts, _ = self.scan(cached + ["--checkpoint", checkpoint])
        resumed, resumed_hosts, resumed_checks = self.scan(
            ["--known-ips", path, "--checkpoint", checkpoint, "--resume"])
        self.assertEqual(second_hosts, [])
        self.assertEqual((resumed_hosts, resumed_checks), ([], []))
        self.assertEqual(second["hosts"][0]["evidence_source"], "cache")
        self.assertEqual(resumed["hosts"][0]["evidence_source"], "checkpoint")
        self.assertEqual(resumed["hosts"][0]["observed_at"], first["hosts"][0]["observed_at"])

    def test_cache_to_checkpoint_copy_does_not_refresh_host_evidence_age(self):
        path = self.known(IP)
        cache = str(self.directory / "cache")
        checkpoint = str(self.directory / "aged-host.sqlite")
        now = time.time()
        with mock.patch.object(discovery.time, "time", return_value=now):
            first, _, _ = self.scan(["--known-ips", path, "--cache-dir", cache])
        with mock.patch.object(discovery.time, "time", return_value=now + 10):
            copied, copied_hosts, _ = self.scan(
                ["--known-ips", path, "--cache-dir", cache, "--checkpoint", checkpoint])
        self.assertEqual(copied_hosts, [])
        self.assertEqual(copied["hosts"][0]["observed_at"], first["hosts"][0]["observed_at"])
        # DB persistence happened ten seconds after the real host observation.
        # At resume the DB row is fresh, while its underlying evidence is stale.
        with mock.patch.object(discovery.time, "time", return_value=now + 20):
            resumed, hosts, checks = self.scan(
                ["--known-ips", path, "--checkpoint", checkpoint, "--resume", "--state-ttl", "15"])
        self.assertEqual(hosts, [IP])
        self.assertEqual(checks, [])  # The independently newer sample remains valid.
        self.assertEqual(resumed["hosts"][0]["evidence_source"], "live")
        self.assertEqual(resumed["hosts"][0]["observed_at"], now + 20)

    def test_checkpoint_sample_age_uses_original_evidence_not_write_time(self):
        path = self.known(IP)
        checkpoint = str(self.directory / "aged-sample.sqlite")
        argv = ["--known-ips", path, "--checkpoint", checkpoint, "--state-ttl", "10"]
        now = time.time()

        def older_observation(seed, args, runtime):
            value = measurement(seed)
            value["observed_at"] = now - 30
            return value

        with mock.patch.object(discovery.time, "time", return_value=now):
            first, _, _ = self.scan(argv, verify=older_observation)
        with mock.patch.object(discovery.time, "time", return_value=now + 1):
            resumed, hosts, checks = self.scan(argv + ["--resume"])
        self.assertEqual(hosts, [])
        self.assertEqual(len(checks), 1)
        self.assertEqual(first["candidates"][0]["measurements"][0]["observed_at"], now - 30)
        sample = resumed["candidates"][0]["measurements"][0]
        self.assertEqual(sample["evidence_source"], "live")
        self.assertEqual(sample["observed_at"], now + 1)

    def test_checkpoint_write_failure_keeps_successful_probe_evidence(self):
        path = self.known(IP)
        checkpoint = str(self.directory / "write-failure.sqlite")
        state = discovery.module("state")
        original_put = state.Checkpoint.put

        def fail_measurement_write(store, kind, key, payload):
            if isinstance(payload, dict) and payload.get("report") is not None:
                raise state.StateError("STATE_WRITE")
            return original_put(store, kind, key, payload)

        with mock.patch.object(state.Checkpoint, "put", new=fail_measurement_write):
            report, _, checks = self.scan(["--known-ips", path, "--checkpoint", checkpoint])
        self.assertEqual(checks, [(IP, SNI)])
        self.assertEqual(report["summary"]["exit_code"], 2)
        self.assertFalse(report["scan"]["complete"])
        sample = report["candidates"][0]["measurements"][0]
        self.assertEqual(sample["error"], "STATE_WRITE")
        self.assertEqual(sample["report"]["summary"]["basic_tls"], "PASS")
        self.assertEqual(sample["report"]["summary"]["compatibility"], "PASS")
        self.assertEqual(sample["evidence_source"], "live")
        self.assertIsNotNone(sample["observed_at"])
        self.assertEqual(sample["dns_binding"], "MATCH")

    def test_checkpoint_reuses_completed_samples_with_original_observation_time(self):
        checkpoint = str(self.directory / "checkpoint.sqlite")
        argv = ["--known-ips", self.known(IP), "--samples", "2", "--checkpoint", checkpoint]
        first, _, first_checks = self.scan(argv)
        second, second_hosts, second_checks = self.scan(argv + ["--resume"])
        self.assertEqual((len(first_checks), second_hosts, second_checks), (2, [], []))
        original = first["candidates"][0]["measurements"]
        resumed = second["candidates"][0]["measurements"]
        self.assertEqual([sample["observed_at"] for sample in resumed],
                         [sample["observed_at"] for sample in original])
        self.assertTrue(all(sample["evidence_source"] == "checkpoint" for sample in resumed))
        self.assertTrue(second["candidates"][0]["eligible"])

    def test_unknown_checkpoint_sample_is_retried(self):
        checkpoint = str(self.directory / "checkpoint.sqlite")
        argv = ["--known-ips", self.known(IP), "--checkpoint", checkpoint]
        first, _, _ = self.scan(argv, verify=lambda seed, args, runtime: measurement(seed, "UNKNOWN"))
        second, _, checks = self.scan(argv + ["--resume"])
        self.assertEqual(first["summary"]["exit_code"], 2)
        self.assertEqual(len(checks), 1)
        self.assertTrue(second["candidates"][0]["eligible"])
        self.assertEqual(second["candidates"][0]["measurements"][0]["evidence_source"], "live")

    def test_interrupted_scan_resumes_only_missing_samples(self):
        checkpoint = str(self.directory / "checkpoint.sqlite")
        argv = ["--known-ips", self.known(IP), "--samples", "3", "--checkpoint", checkpoint]
        count = 0

        def interrupt(seed, args, runtime):
            nonlocal count
            count += 1
            if count == 1:
                return measurement(seed)
            runtime.cancelled.set()
            return dict(seed, eligible=False, report=None, dns_binding="UNKNOWN", error="CANCELLED", elapsed_ms=0)

        first, _, _ = self.scan(argv, verify=interrupt)
        self.assertFalse(first["scan"]["complete"])
        second, hosts, checks = self.scan(argv + ["--resume"])
        self.assertEqual(hosts, [])
        self.assertEqual(len(checks), 2)
        self.assertTrue(second["candidates"][0]["eligible"])
        self.assertEqual(second["candidates"][0]["measurements"][0]["observed_at"],
                         first["candidates"][0]["measurements"][0]["observed_at"])

    def test_stopped_samples_remain_pending_without_reading_or_writing_state(self):
        args = discovery.parse_args(["192.0.2.10/32", "--samples", "5"])
        seed = {"ip": IP, "sni": SNI, "sources": ["san"]}
        for reason in ("CANCELLED", "DEADLINE"):
            runtime = discovery.Runtime(timeout=1, deadline=10, rate=100)
            store = mock.Mock()
            runtime.checkpoint = store
            if reason == "CANCELLED":
                runtime.cancelled.set()
            else:
                runtime.deadline = time.monotonic() - 1
            try:
                with self.subTest(reason=reason), mock.patch.object(discovery, "verify_candidate") as verify:
                    candidate = discovery.measure_candidate(seed, args, runtime)
                verify.assert_not_called()
                store.get_record.assert_not_called()
                store.put.assert_not_called()
                self.assertFalse(candidate["eligible"])
                self.assertEqual(len(candidate["measurements"]), 5)
                self.assertEqual(candidate["statistics"]["completed"], 0)
                self.assertTrue(all(value["evidence_source"] == "not_started"
                                    and value["error"] == reason and value["report"] is None
                                    for value in candidate["measurements"]))
            finally:
                runtime.close()

    def test_large_stopped_queue_does_not_checkpoint_unstarted_placeholders(self):
        records = [{"ip": str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("192.0.2.1")) + index)),
                    "sni": SNI} for index in range(128)]
        path = self.seeds(records)
        args = discovery.parse_args(["--seeds", path, "--samples", "5", "--concurrency", "1",
                                     "--max-hosts", "128", "--max-candidates", "128"])
        for reason in ("CANCELLED", "DEADLINE"):
            runtime = discovery.Runtime(timeout=1, deadline=10, rate=100)
            store = mock.Mock()
            store.get_record.return_value = None
            runtime.checkpoint = store

            def stop_without_starting(seed, current_args, current_runtime):
                if reason == "CANCELLED":
                    current_runtime.cancelled.set()
                else:
                    current_runtime.deadline = time.monotonic() - 1
                return dict(seed, eligible=False, dns_binding="UNKNOWN", report=None,
                            error=reason, observed_at=None, evidence_source="not_started", elapsed_ms=0)

            try:
                with self.subTest(reason=reason), \
                        mock.patch.object(discovery, "verify_candidate", side_effect=stop_without_starting) as verify, \
                        mock.patch.object(discovery, "connect_socket") as connect:
                    report = discovery.scan(args, runtime)
                self.assertEqual(verify.call_count, 1)
                connect.assert_not_called()
                sample_reads = [call for call in store.get_record.call_args_list if call.args[0] == "sample"]
                sample_writes = [call for call in store.put.call_args_list if call.args[0] == "sample"]
                self.assertEqual(len(sample_reads), 1)
                self.assertEqual(sample_writes, [])
                self.assertEqual(len(report["candidates"]), 128)
                self.assertTrue(all(len(candidate["measurements"]) == 5 for candidate in report["candidates"]))
                self.assertEqual(report["summary"]["exit_code"], 2)
                self.assertFalse(report["scan"]["complete"])
            finally:
                runtime.close()

    def test_inflight_completed_evidence_is_saved_even_when_stop_arrives(self):
        path = self.known(IP)
        for reason in ("CANCELLED", "DEADLINE"):
            checkpoint = str(self.directory / (reason.lower() + "-inflight.sqlite"))
            argv = ["--known-ips", path, "--checkpoint", checkpoint, "--samples", "5", "--concurrency", "1"]

            def complete_then_stop(seed, args, runtime):
                value = measurement(seed)
                if reason == "CANCELLED":
                    runtime.cancelled.set()
                else:
                    runtime.deadline = time.monotonic() - 1
                return value

            with self.subTest(reason=reason):
                first, _, first_checks = self.scan(argv, verify=complete_then_stop)
                self.assertEqual(len(first_checks), 1)
                self.assertFalse(first["scan"]["complete"])
                completed = first["candidates"][0]["measurements"][0]
                self.assertIsNotNone(completed["report"])
                self.assertEqual(completed["evidence_source"], "live")
                self.assertEqual(first["candidates"][0]["statistics"]["completed"], 1)
                resumed, hosts, checks = self.scan(argv + ["--resume"])
                self.assertEqual(hosts, [])
                self.assertEqual(len(checks), 4)
                saved = resumed["candidates"][0]["measurements"][0]
                self.assertEqual(saved["evidence_source"], "checkpoint")
                self.assertEqual(saved["observed_at"], completed["observed_at"])
                self.assertEqual(saved["report"], completed["report"])
                self.assertTrue(resumed["candidates"][0]["eligible"])

    def test_changed_manifest_cannot_resume_a_different_scope(self):
        checkpoint = str(self.directory / "checkpoint.sqlite")
        path = self.known(IP)
        argv = ["--known-ips", path, "--checkpoint", checkpoint]
        self.scan(argv)
        Path(path).write_text("198.51.100.20\n")
        state_error = discovery.module("state").StateError
        try:
            report, hosts, checks = self.scan(
                argv + ["--resume"],
                hosts=lambda *_: self.fail("scope mismatch performed a discovery probe"),
                verify=lambda *_: self.fail("scope mismatch performed a verification"))
        except (state_error, discovery.DiscoveryError, ValueError):
            return
        self.assertEqual(report["summary"]["exit_code"], 2)
        self.assertEqual((hosts, checks), ([], []))

    def assert_resume_refused_without_probes(self, argv):
        state_error = discovery.module("state").StateError
        try:
            report, hosts, checks = self.scan(
                argv,
                hosts=lambda *_: self.fail("state mismatch performed a discovery probe"),
                verify=lambda *_: self.fail("state mismatch performed a verification"))
        except (state_error, discovery.DiscoveryError, ValueError):
            return
        self.assertEqual(report["summary"]["exit_code"], 2)
        self.assertEqual((hosts, checks), ([], []))

    def test_measurement_timeout_or_sample_count_changes_cannot_reuse_checkpoint(self):
        for option, value in (("--timeout", "4"), ("--samples", "2")):
            with self.subTest(option=option):
                checkpoint = str(self.directory / (option.removeprefix("--") + ".sqlite"))
                argv = ["--known-ips", self.known(IP), "--checkpoint", checkpoint]
                self.scan(argv)
                self.assert_resume_refused_without_probes(argv + ["--resume", option, value])

    def test_changed_trust_roots_cannot_reuse_checkpoint(self):
        trust = self.directory / "ca.pem"
        trust.write_text("fixture trust revision one")
        checkpoint = str(self.directory / "trust.sqlite")
        argv = ["--known-ips", self.known(IP), "--checkpoint", checkpoint]
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": str(trust)}):
            self.scan(argv)
            trust.write_text("fixture trust revision two with different contents")
            self.assert_resume_refused_without_probes(argv + ["--resume"])

    def test_each_ca_directory_change_invalidates_checkpoint(self):
        directories = [self.directory / "ca-one", self.directory / "ca-two"]
        for directory in directories:
            directory.mkdir()
        with mock.patch.dict(os.environ, {"SSL_CERT_DIR": os.pathsep.join(map(str, directories))}):
            for index, directory in enumerate(directories):
                for action in ("change", "remove"):
                    with self.subTest(directory=index, action=action):
                        certificate = directory / "fixture.pem"
                        certificate.write_text("original trust root")
                        checkpoint = str(self.directory / ("trust-%d-%s.sqlite" % (index, action)))
                        argv = ["--known-ips", self.known(IP), "--checkpoint", checkpoint]
                        self.scan(argv)
                        if action == "change":
                            certificate.write_text("replacement trust root with different contents")
                        else:
                            certificate.unlink()
                        self.assert_resume_refused_without_probes(argv + ["--resume"])

    def test_operational_deadline_rate_and_concurrency_can_change_on_resume(self):
        checkpoint = str(self.directory / "operational.sqlite")
        argv = ["--known-ips", self.known(IP), "--checkpoint", checkpoint, "--samples", "2",
                "--deadline", "2", "--rate", "1", "--concurrency", "1"]
        first, _, _ = self.scan(argv)
        second, hosts, checks = self.scan(argv + ["--resume", "--deadline", "60", "--rate", "100",
                                                "--concurrency", "2"])
        self.assertEqual((hosts, checks), ([], []))
        self.assertTrue(second["candidates"][0]["eligible"])
        self.assertEqual(second["scope"]["limits"]["deadline"], 60)
        self.assertEqual([sample["observed_at"] for sample in first["candidates"][0]["measurements"]],
                         [sample["observed_at"] for sample in second["candidates"][0]["measurements"]])

    def test_state_errors_are_unknown_and_never_completed_empty_discovery(self):
        path = self.known(IP)
        checkpoint = self.directory / "corrupt.sqlite"
        checkpoint.write_bytes(b"not SQLite")
        checkpoint.chmod(0o600)
        cache = self.directory / "corrupt-cache"
        cache.mkdir(mode=0o700)
        (cache / "cache.sqlite").write_bytes(b"not SQLite")
        (cache / "cache.sqlite").chmod(0o600)
        for state_args in (["--checkpoint", str(checkpoint), "--resume"], ["--cache-dir", str(cache)]):
            output = io.StringIO()
            with self.subTest(state_args=state_args), \
                    mock.patch.object(discovery, "connect_socket") as connect, \
                    mock.patch.object(discovery.Runtime, "run", side_effect=AssertionError("unexpected command")), \
                    redirect_stdout(output), redirect_stderr(io.StringIO()):
                code = discovery.main(["--known-ips", path, "--json", *state_args])
            self.assertEqual(code, 2)
            connect.assert_not_called()
            report = json.loads(output.getvalue())
            self.assertEqual(report["summary"]["status"], "UNKNOWN")
            self.assertTrue(report["error"]["code"].startswith("STATE_"))


class RealIPv6Workflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="rtc-workflows-tls-")
        cls.directory = Path(cls.temp.name)
        cls.cert = cls.directory / "cert.pem"
        cls.key = cls.directory / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(cls.key),
                        "-out", str(cls.cert), "-subj", "/CN=untrusted.test", "-addext",
                        "subjectAltName=DNS:example.test", "-days", "2"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_ipv6_tls_and_ptr_discovery_uses_the_ipv6_socket_family(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable")
        try:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.bind(("::1", 0))
        except OSError:
            if "listener" in locals():
                listener.close()
            self.skipTest("IPv6 loopback unavailable")
        listener.listen()
        listener.settimeout(1)
        port = listener.getsockname()[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server_names = []
        context.set_servername_callback(lambda sock, name, ctx: server_names.append(name))

        def serve():
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            with connection:
                connection.settimeout(1)
                try:
                    with context.wrap_socket(connection, server_side=True) as tls:
                        tls.recv(1)
                except (OSError, ssl.SSLError):
                    pass

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        original_socket = socket.socket
        case = self
        families = []

        class RedirectedSocket:
            def __init__(self, family, *args, **kwargs):
                families.append(family)
                self.socket = original_socket(family, *args, **kwargs)

            def __getattr__(self, name):
                return getattr(self.socket, name)

            def __enter__(self):
                return self

            def __exit__(self, *_exception):
                self.socket.close()

            def connect_ex(self, address):
                case.assertEqual(address, (IP6, 443))
                return self.socket.connect_ex(("::1", port))

        runtime = discovery.Runtime(timeout=1, deadline=5, rate=100)
        real_run = runtime.run

        def run(command, input_data=None, timeout=None):
            if command[0] == "dig":
                return 0, baseline.ptr_answer(IP6, SNI + ".").encode(), b""
            return real_run(command, input_data=input_data, timeout=timeout)

        try:
            with mock.patch.object(socket, "socket", side_effect=RedirectedSocket), \
                    mock.patch.object(runtime, "run", side_effect=run):
                host = discovery.discover_host(IP6, runtime)
            self.assertEqual(families, [socket.AF_INET6])
            self.assertEqual(host["ip"], IP6)
            self.assertEqual(host["tcp"], "OPEN")
            self.assertEqual(host["tls"], "CERTIFICATE")
            self.assertEqual(set(host["names"][SNI]), {"san", "ptr"})
            self.assertEqual(host["issues"], [])
            self.assertEqual(server_names, [None])
        finally:
            runtime.close()
            listener.close()
            server.join(timeout=2)

    def test_actual_bash_ipv6_report_satisfies_coordinator_contract(self):
        with tempfile.TemporaryDirectory(prefix="rtc-workflows-mock-") as directory:
            root = Path(directory)
            mock_bin = root / "bin"
            mock_bin.mkdir()
            for tool in ("dig", "openssl", "curl", "timeout"):
                (mock_bin / tool).symlink_to(baseline.ROOT / "tests/helpers/mock-command")
            args = discovery.parse_args(["2001:db8::10/128", "--origin-ip", "2001:db8::20"])
            runtime = discovery.Runtime(timeout=1, deadline=5, rate=100)
            environment = {"PATH": str(mock_bin) + os.pathsep + os.environ["PATH"],
                           "MOCK_CERT": str(self.cert), "MOCK_CASE": "", "MOCK_LOG": str(root / "calls")}
            try:
                with mock.patch.dict(os.environ, environment):
                    result = discovery.verify_candidate({"ip": IP6, "sni": SNI, "sources": ["san"]}, args, runtime)
                self.assertIsNone(result["error"])
                self.assertTrue(result["eligible"])
                self.assertEqual(result["dns_binding"], "MATCH")
                report = result["report"]
                self.assertEqual(report["endpoints"][0]["ip"], IP6)
                self.assertEqual(report["endpoints"][0]["family"], 6)
                self.assertIn(IP6, report["dns"]["aaaa"])
                self.assertTrue(any(check["id"] == "same_asn" and check["status"] == "PASS"
                                    for check in report["endpoints"][0]["checks"]))
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
