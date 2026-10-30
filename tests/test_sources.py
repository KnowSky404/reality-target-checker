"""Offline source contracts; no provider account or Internet connection needed."""

import copy
import importlib.util
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sources", ROOT / "reality-target-sources.py")
sources = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sources)
NOW = 1793318400.0  # 2026-10-30T00:00:00Z
IP = "192.0.2.10"
V6 = ipaddress.IPv6Address("2001:db8::10").exploded


def stamp(offset=0):
    return sources._utc(NOW + offset)


def announcement(prefix, start=-86400, end=0):
    return {"prefix": prefix, "timelines": [{"starttime": stamp(start), "endtime": stamp(end)}]}


def prefixes_payload(prefixes=None):
    return {"status": "ok", "data": {
        "resource": "AS64500", "query_starttime": stamp(-86400),
        "query_endtime": stamp(), "latest_time": stamp(-600),
        "prefixes": prefixes if prefixes is not None else [announcement("192.0.2.0/24")],
    }}


class Runtime:
    timeout = 3

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []
        self.acquisitions = 0

    def acquire(self):
        self.acquisitions += 1

    def remaining(self):
        return 20

    def run(self, command, input_data=None, timeout=None, output_limit=None):
        self.calls.append((command, timeout, output_limit))
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply if isinstance(reply, tuple) else (0, json.dumps(reply).encode(), b"")


class Cache:
    def __init__(self):
        self.items = {}

    def get(self, namespace, key):
        return copy.deepcopy(self.items.get((namespace, key)))

    def put(self, namespace, key, payload):
        self.items[(namespace, key)] = copy.deepcopy(payload)


class AddressInputs(unittest.TestCase):
    def test_ipv4_is_canonical_and_ipv6_is_expanded(self):
        self.assertEqual(sources.canonical_ip(IP), IP)
        for value in ("2001:db8::10", "2001:DB8:0:0:0:0:0:10"):
            self.assertEqual(sources.canonical_ip(value), V6)
        for value in ("192.0.02.10", "0x7f000001", "127.1", "[::1]", "fe80::1%eth0",
                      "https://example.test", "192.0.2.10:443", 3221225994, None):
            with self.subTest(value=value), self.assertRaises(sources.SourceError):
                sources.canonical_ip(value)

    def test_prefixes_require_network_alignment_and_numeric_prefix_length(self):
        self.assertEqual(str(sources.parse_network("2001:DB8::/32")), "2001:db8::/32")
        self.assertEqual(str(sources.parse_network("192.0.2.0/31")), "192.0.2.0/31")
        for value in ("192.0.2.1/24", "192.0.02.0/24", "192.0.2.0/024", "192.0.2.0/255.255.255.0",
                      "2001:db8::1/64", "fe80::%eth0/64", "::/129", "::/000", "192.0.2.10"):
            with self.subTest(value=value), self.assertRaises(sources.SourceError):
                sources.parse_network(value)

    def test_known_ip_file_is_finite_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "known.txt"
            path.write_text("# explicit addresses\n192.0.2.10\n2001:db8::10\n2001:DB8::10\n")
            self.assertEqual(sources.load_known_ips(path), [IP, V6])
            with self.assertRaises(sources.SourceError):
                sources.load_known_ips(path, max_ips=1)
            path.write_text("2001:db8::/64\n")
            with self.assertRaises(sources.SourceError):
                sources.load_known_ips(path)

    def test_oversized_input_is_rejected_before_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            with path.open("wb") as file:
                file.truncate(sources.MAX_SOURCE_BYTES + 1)
            with self.assertRaises(sources.SourceError):
                sources.load_known_ips(path)


class ImportedSeeds(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def load(self, data, format="generic", filename="seeds.json", **kwargs):
        path = self.directory / filename
        path.write_text(data if isinstance(data, str) else json.dumps(data))
        return sources.load_seeds(path, format=format, now=NOW, **kwargs)

    def test_jsonl_merges_duplicate_pairs_and_preserves_latest_observation(self):
        values = [
            {"ip": IP, "sni": "Example.TEST.", "observed_at": stamp(-3600)},
            {"ip": IP, "sni": "example.test", "observed_at": stamp(-1800)},
            {"ip": "2001:db8::10", "domain": "v6.example.test"},
        ]
        result = self.load("\n".join(json.dumps(value) for value in values), filename="seeds.jsonl")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], {"ip": IP, "sni": "example.test", "sources": ["import:generic"], "observed_at": stamp(-1800)})
        self.assertEqual(result[1]["ip"], V6)

    def test_csv_accepts_explicit_domain_without_interpreting_host_urls(self):
        result = self.load("ip,domain,host\n192.0.2.10,example.test,https://ignored.test:8443/\n", filename="seeds.csv")
        self.assertEqual(result[0]["sni"], "example.test")
        for text in ("ip,host\n192.0.2.10,https://example.test/\n",
                     "ip,sni,sni\n192.0.2.10,example.test,other.test\n",
                     "ip,sni\n192.0.2.10,example.test,extra\n"):
            with self.subTest(text=text), self.assertRaises(sources.SourceError):
                self.load(text, filename="seeds.csv")

    def test_conflicting_or_numeric_names_are_rejected_not_silently_dropped(self):
        for record in (
                {"ip": IP, "sni": "a.test", "domain": "b.test"},
                {"ip": IP, "sni": "0x7f000001"},
                {"ip": IP, "sni": "0x7f.0.0.1"},
                {"ip": IP, "sni": "bad_name.test"},
                {"ip": IP, "sni": "$(touch /tmp/no).test"},
                {"ip": "https://example.test", "sni": "example.test"}):
            with self.subTest(record=record), self.assertRaises(sources.SourceError):
                self.load(record)
        self.assertEqual(self.load({"ip": IP, "sni": "0xface.example.test"})[0]["sni"], "0xface.example.test")

    def test_caller_hostname_validator_is_used(self):
        validator = mock.Mock(return_value=None)
        with self.assertRaises(sources.SourceError):
            self.load({"ip": IP, "sni": "example.test"}, normalize_name=validator)
        validator.assert_called_once_with("example.test")

    def test_explicit_provenance_is_preserved_as_imported_metadata(self):
        result = self.load([
            {"ip": IP, "sni": "example.test", "source": "dnsdb"},
            {"ip": IP, "sni": "example.test", "sources": ["customer-list", "san"]},
        ])
        self.assertEqual(result[0]["sources"], ["import:customer-list", "import:dnsdb", "import:generic", "import:san"])
        with self.assertRaises(sources.SourceError):
            self.load({"ip": IP, "sni": "example.test", "source": "bad\x1b[2J"})

    def test_fractional_observation_times_compare_chronologically(self):
        values = [
            {"ip": IP, "sni": "example.test", "observed_at": stamp(-300)},
            {"ip": IP, "sni": "example.test", "observed_at": stamp(-299.5)},
        ]
        for records in (values, list(reversed(values))):
            with self.subTest(records=records):
                result = self.load(records)
                self.assertEqual(result[0]["observed_at"], stamp(-299.5))

    def test_seed_budget_and_future_observation_are_explicit_errors(self):
        with self.assertRaises(sources.SourceError):
            self.load([{"ip": IP, "sni": "a.test"}, {"ip": IP, "sni": "b.test"}], max_seeds=1)
        with self.assertRaises(sources.SourceError):
            self.load({"ip": IP, "sni": "a.test", "observed_at": stamp(3600)})
        with self.assertRaises(sources.SourceError):
            self.load('{"ip":"192.0.2.10","ip":"127.0.0.1","sni":"a.test"}')

    def test_wildcards_are_not_expanded_or_accepted_as_concrete_names(self):
        result = self.load({"host": {"ip": IP, "dns": {"names": ["*.example.test", "www.example.test"]}}}, format="censys")
        self.assertEqual([item["sni"] for item in result], ["www.example.test"])
        with self.assertRaises(sources.SourceError):
            self.load({"ip": IP, "sni": "*.example.test"})

    def test_censys_current_and_legacy_host_shapes(self):
        values = {"result": {"hits": [
            {"host": {"ip": IP, "dns": {"names": ["dns.example.test"]}, "services": [
                {"port": 443, "cert": {"names": ["cert.example.test"]}, "scan_time": stamp(-300)},
                {"port": 8443, "cert": {"names": ["other-port.test"]}},
            ]}},
            {"ip": "2001:db8::10", "services": [{"port": 443, "tls": {"certificates": {
                "leaf_data": {"names": ["legacy.example.test"]}}}}]},
        ]}}
        result = self.load(values, format="censys")
        self.assertEqual({item["sni"] for item in result}, {"dns.example.test", "cert.example.test", "legacy.example.test"})
        self.assertEqual(next(item for item in result if item["sni"] == "cert.example.test")["observed_at"], stamp(-300))
        self.assertTrue(all(item["sources"] == ["import:censys"] for item in result))

    def test_censys_csv_fields_and_incomplete_pagination_are_handled_explicitly(self):
        result = self.load('host.ip,host.dns.names\n192.0.2.10,"[""example.test""]"\n', format="censys", filename="export.csv")
        self.assertEqual(result[0]["sni"], "example.test")
        with self.assertRaisesRegex(sources.SourceError, "PAGINATION"):
            self.load({"result": {"hits": [{"host": {"ip": IP}}], "links": {"next": "token"}}}, format="censys")

    def test_censys_complete_counts_are_checked_before_seed_deduplication(self):
        record = {"host": {"ip": IP, "dns": {"names": ["example.test"]}}}
        self.assertEqual(self.load({"result": {"hits": [], "total": 0}}, format="censys"), [])
        result = self.load({"result": {"hits": [record, record], "total": 2, "links": {"next": None}}}, format="censys")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["sni"], "example.test")

    def test_censys_partial_results_require_complete_export_without_next_token(self):
        record = {"host": {"ip": IP, "dns": {"names": ["example.test"]}}}
        for hits, total in (([], 1), ([record], 200), ([record] * 100, 200)):
            with self.subTest(count=len(hits), total=total), self.assertRaisesRegex(sources.SourceError, "^SEED_PAGINATION$"):
                self.load({"result": {"hits": hits, "total": total, "links": {"next": None}}}, format="censys")

    def test_censys_invalid_or_contradictory_totals_are_source_errors(self):
        record = {"host": {"ip": IP, "dns": {"names": ["example.test"]}}}
        for total in (0, -1, True, False, [], {}, "1", None, 1.0):
            with self.subTest(total=total), self.assertRaisesRegex(sources.SourceError, "^SEED_COUNT$"):
                self.load({"result": {"hits": [record], "total": total}}, format="censys")

    def test_censys_finite_lists_and_jsonl_do_not_require_total(self):
        records = [
            {"host": {"ip": IP, "dns": {"names": ["a.test"]}}},
            {"host": {"ip": IP, "dns": {"names": ["b.test"]}}},
        ]
        for data in (records, "\n".join(json.dumps(record) for record in records), {"result": {"hits": records}}):
            with self.subTest(data=data):
                result = self.load(data, format="censys")
                self.assertEqual([item["sni"] for item in result], ["a.test", "b.test"])

    def test_shodan_banner_fields_are_seeds_not_protocol_evidence(self):
        result = self.load({"ip_str": IP, "port": 443, "timestamp": stamp(-300),
                            "hostnames": ["ptr.example.test"], "_shodan": {"options": {"hostname": "sni.example.test"}},
                            "ssl": {"cert": {"subject": {"CN": "cn.example.test"},
                                               "extensions": [{"name": "subjectAltName", "data": "DNS:san.example.test, DNS:*.example.test"}]}}}, format="shodan")
        self.assertEqual({item["sni"] for item in result}, {"ptr.example.test", "sni.example.test", "cn.example.test", "san.example.test"})
        self.assertTrue(all(item["observed_at"] == stamp(-300) for item in result))
        self.assertTrue(all("eligible" not in item and item["sources"] == ["import:shodan"] for item in result))

    def test_shodan_complete_counts_are_checked_before_seed_deduplication(self):
        record = {"ip_str": IP, "hostnames": ["example.test"]}
        self.assertEqual(self.load({"matches": [], "total": 0}, format="shodan"), [])
        result = self.load({"matches": [record, record], "total": 2}, format="shodan")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["sni"], "example.test")

    def test_shodan_partial_results_require_complete_export(self):
        record = {"ip_str": IP, "hostnames": ["example.test"]}
        for matches, total in (([], 1), ([record], 2), ([record] * 100, 200)):
            with self.subTest(count=len(matches), total=total), self.assertRaisesRegex(sources.SourceError, "^SEED_PAGINATION$"):
                self.load({"matches": matches, "total": total}, format="shodan")

    def test_shodan_invalid_or_contradictory_totals_are_source_errors(self):
        record = {"ip_str": IP, "hostnames": ["example.test"]}
        for total in (0, -1, True, False, [], {}, "1", None, 1.0):
            with self.subTest(total=total), self.assertRaisesRegex(sources.SourceError, "^SEED_COUNT$"):
                self.load({"matches": [record], "total": total}, format="shodan")

    def test_shodan_finite_lists_and_jsonl_do_not_require_total(self):
        records = [
            {"ip_str": IP, "hostnames": ["a.test"]},
            {"ip_str": IP, "hostnames": ["b.test"]},
        ]
        for data in (records, "\n".join(json.dumps(record) for record in records), {"matches": records}):
            with self.subTest(data=data):
                result = self.load(data, format="shodan")
                self.assertEqual([item["sni"] for item in result], ["a.test", "b.test"])

    def test_history_a_and_aaaa_do_not_expand_unrelated_records(self):
        result = self.load([
            {"rrname": "Example.TEST.", "rrtype": "A", "rdata": [IP], "time_last": NOW - 300},
            {"rrname": "v6.test", "rrtype": "AAAA", "rdata": "2001:db8::10"},
        ], format="dns")
        self.assertEqual([(item["ip"], item["sni"]) for item in result], [(IP, "example.test"), (V6, "v6.test")])
        with self.assertRaises(sources.SourceError):
            self.load({"rrname": "example.test", "rrtype": "CNAME", "rdata": "elsewhere.test"}, format="dns")
        with self.assertRaises(sources.SourceError):
            self.load({"rrname": "example.test", "rrtype": "AAAA", "rdata": IP}, format="dns")

    def test_malformed_dns_record_types_raise_source_errors(self):
        for kind in ([], {}, None, 1, 1.5, True, False):
            with self.subTest(kind=kind), self.assertRaisesRegex(sources.SourceError, "SEED_DNS_TYPE"):
                self.load({"rrname": "example.test", "rrtype": kind, "rdata": IP}, format="dns")
        for kind, address in (("A", IP), ("AAAA", "2001:db8::10")):
            with self.subTest(kind=kind):
                result = self.load({"rrname": "example.test", "rrtype": kind, "rdata": address}, format="dns")
                self.assertEqual(result[0]["ip"], sources.canonical_ip(address))


class AsnPlans(unittest.TestCase):
    def test_explicit_window_uses_latest_snapshot_and_retains_announcements(self):
        payload = prefixes_payload([
            announcement("192.0.2.0/25"), announcement("192.0.2.128/25"),
            announcement("192.0.2.0/25"), announcement("198.51.100.0/24", -7200, -3600),
            announcement("2001:db8::/33"), announcement("2001:db8:8000::/33"),
        ])
        runtime = Runtime([payload])
        plan = sources.build_asn_plan("AS64500", runtime=runtime, now=NOW)
        self.assertEqual(plan["prefixes_v4"], ["192.0.2.0/24"])
        self.assertEqual(plan["prefixes_v6"], ["2001:db8::/32"])
        self.assertEqual(len(plan["announced_prefixes"]), 4)
        self.assertEqual(plan["snapshot_time"], stamp(-600))
        self.assertIsNone(plan["moas"])
        self.assertEqual(plan["moas_scope"], "origin_ip")
        self.assertNotIn("198.51.100.0/24", plan["announced_prefixes"])
        command, timeout, output_limit = runtime.calls[0]
        self.assertEqual(timeout, 3)
        self.assertEqual(output_limit, sources.MAX_SOURCE_BYTES)
        self.assertNotIn("--location", command)
        self.assertNotIn("--proxy", command)
        self.assertNotIn("--noproxy", command)
        query = parse_qs(urlparse(command[-1]).query)
        self.assertEqual(query["resource"], ["AS64500"])
        self.assertEqual(query["starttime"], [str(int(NOW) - 86400)])
        self.assertEqual(query["endtime"], [str(int(NOW))])
        self.assertTrue(command[-1].startswith(sources.RIPE_BASE))

    def test_fractional_clock_uses_provider_supported_integer_seconds(self):
        runtime = Runtime([prefixes_payload()])
        plan = sources.build_asn_plan(64500, runtime=runtime, now=NOW + 0.123456)
        query = parse_qs(urlparse(runtime.calls[0][0][-1]).query)
        self.assertEqual(query["starttime"], [str(int(NOW) - 86400)])
        self.assertEqual(query["endtime"], [str(int(NOW))])
        self.assertEqual(plan["retrieved_at"], stamp(0.123456))
        self.assertEqual(plan["snapshot_time"], stamp(-600))

    def test_origin_asn_is_not_an_implicit_choice_for_moas(self):
        runtime = Runtime([{"status": "ok", "data": {"asns": [64501, 64500], "prefix": "192.0.2.0/24"}}])
        plan = sources.build_asn_plan(origin_ip=IP, runtime=runtime, now=NOW)
        self.assertEqual(plan["status"], "UNKNOWN")
        self.assertIsNone(plan["asn"])
        self.assertEqual(plan["origin_asns"], [64500, 64501])
        self.assertTrue(plan["moas"])
        self.assertEqual(len(runtime.calls), 1)

    def test_single_origin_asn_and_explicit_moas_choice_keep_evidence(self):
        for origins in ([64500], [64500, 64501]):
            with self.subTest(origins=origins):
                runtime = Runtime([{"status": "ok", "data": {"asns": origins, "prefix": "192.0.2.0/24"}}, prefixes_payload()])
                plan = sources.build_asn_plan(asn=64500 if len(origins) > 1 else None,
                                              origin_ip=IP, runtime=runtime, now=NOW)
                self.assertEqual(plan["asn"], 64500)
                self.assertEqual(plan["status"], "PASS")
                self.assertEqual(plan["origin_lookup"]["dump_interval_hours"], 8)
                self.assertEqual(plan["moas"], len(origins) > 1)

    def test_unrouted_origin_does_not_invent_a_scope(self):
        plan = sources.build_asn_plan(origin_ip=IP, runtime=Runtime([{"status": "ok", "data": {"asns": [], "prefix": ""}}]), now=NOW)
        self.assertEqual(plan["status"], "UNKNOWN")
        self.assertEqual(plan["prefixes_v4"], [])

    def test_cache_retains_actual_snapshot_and_retrieval_time(self):
        cache = Cache()
        first = sources.build_asn_plan(64500, runtime=Runtime([prefixes_payload()]), cache=cache, now=NOW)
        runtime = Runtime([])
        second = sources.build_asn_plan(64500, runtime=runtime, cache=cache, now=NOW + 60)
        self.assertEqual(runtime.calls, [])
        self.assertEqual(second["retrieved_at"], first["retrieved_at"])
        self.assertEqual(second["snapshot_time"], first["snapshot_time"])
        self.assertTrue(second["cache_hit"])
        refreshed = prefixes_payload()
        refreshed["data"].update(query_starttime=stamp(86400), query_endtime=stamp(2 * 86400), latest_time=stamp(2 * 86400))
        refreshed["data"]["prefixes"] = [announcement("192.0.2.0/24", 86400, 2 * 86400)]
        runtime = Runtime([refreshed])
        third = sources.build_asn_plan(64500, runtime=runtime, cache=cache, now=NOW + 2 * 86400)
        self.assertEqual(len(runtime.calls), 1)
        self.assertFalse(third["cache_hit"])
        self.assertEqual(third["retrieved_at"], stamp(2 * 86400))
        with self.assertRaisesRegex(sources.SourceError, "STALE"):
            sources.build_asn_plan(64500, runtime=Runtime([prefixes_payload()]), now=NOW + 2 * 86400)

    def test_invalid_provider_response_is_never_written_to_cache(self):
        for payload in ({"status": "error", "data": {}}, prefixes_payload()):
            if payload.get("status") == "ok":
                payload["data"]["resource"] = "AS64501"
            cache = Cache()
            with self.subTest(payload=payload), self.assertRaises(sources.SourceError):
                sources.build_asn_plan(64500, runtime=Runtime([payload]), cache=cache, now=NOW)
            self.assertEqual(cache.items, {})

    def test_stale_future_inconsistent_and_malformed_snapshots_fail_closed(self):
        mutations = [
            lambda p: p["data"].update(latest_time=stamp(-2 * 86400)),
            lambda p: p["data"].update(latest_time=stamp(3600)),
            lambda p: p["data"].update(query_starttime=stamp(1)),
            lambda p: p["data"].update(resource="AS64501"),
            lambda p: p["data"].pop("latest_time"),
            lambda p: p["data"]["prefixes"][0].update(prefix="192.0.2.1/24"),
            lambda p: p["data"]["prefixes"][0]["timelines"][0].update(endtime=stamp(3600)),
            lambda p: p["data"].update(next="https://unrelated.test/next"),
            lambda p: p.update(status="error"),
        ]
        for mutate in mutations:
            payload = prefixes_payload()
            mutate(payload)
            with self.subTest(payload=payload), self.assertRaises(sources.SourceError):
                sources.build_asn_plan(64500, runtime=Runtime([payload]), now=NOW)

    def test_network_failures_and_invalid_responses_are_sanitized(self):
        for reply in ((22, b"", b"secret details"), (0, b"not-json", b""), RuntimeError("CANCELLED")):
            with self.subTest(reply=reply), self.assertRaises(sources.SourceError) as raised:
                sources.build_asn_plan(64500, runtime=Runtime([reply]), now=NOW)
            self.assertNotIn("secret details", str(raised.exception))

    def test_selected_prefixes_preserve_user_host_enumeration(self):
        plan = sources.build_asn_plan(64500, runtime=Runtime([prefixes_payload()]), now=NOW)
        selected = sources.select_prefixes(plan, ["192.0.2.0/31", "192.0.2.2/31", "192.0.2.0/31"])
        self.assertEqual(selected, ["192.0.2.0/31", "192.0.2.2/31"])
        self.assertEqual({str(ip) for prefix in selected for ip in ipaddress.ip_network(prefix).hosts()},
                         {"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"})
        for prefixes in (["192.0.0.0/16"], ["198.51.100.0/24"], ["2001:db8::/64"]):
            with self.subTest(prefixes=prefixes), self.assertRaises(sources.SourceError):
                sources.select_prefixes(plan, prefixes)
        self.assertTrue(sources.ip_in_prefixes(IP, plan["prefixes_v4"]))
        self.assertFalse(sources.ip_in_prefixes("198.51.100.10", plan["prefixes_v4"]))

    def test_restored_plan_stays_bound_to_requested_asn_and_keeps_observation_time(self):
        plan = sources.build_asn_plan(64500, runtime=Runtime([prefixes_payload()]), now=NOW)
        compact = {key: value for key, value in plan.items() if key != "announced_prefixes"}
        before = copy.deepcopy(compact)
        self.assertIs(sources.validate_asn_plan(compact, asn=64500, now=NOW + 60), compact)
        self.assertEqual(compact, before)
        with self.assertRaisesRegex(sources.SourceError, "STATE_PLAN"):
            sources.validate_asn_plan(compact, asn=64501, now=NOW + 60)
        with self.assertRaisesRegex(sources.SourceError, "RIPE_STALE_SNAPSHOT"):
            sources.validate_asn_plan(compact, asn=64500, now=NOW + 2 * 86400)

    def test_large_finite_selection_uses_complete_coverage_without_filling_gaps(self):
        base = int(ipaddress.IPv4Address("11.0.0.0"))
        prefixes = [str(ipaddress.IPv4Address(base + 512 * index)) + "/24" for index in range(sources.MAX_PREFIXES - 1)]
        chosen = [str(ipaddress.IPv4Address(base + 512 * index + 1)) + "/32" for index in range(4096)]
        plan = {"status": "PASS", "prefixes_v4": prefixes, "prefixes_v6": ["2001:db8::/32"]}
        result = sources.select_prefixes(plan, chosen + ["2001:db8::/128"])
        self.assertEqual(result, chosen + ["2001:db8::/128"])
        with self.assertRaisesRegex(sources.SourceError, "OUT_OF_SCOPE"):
            sources.select_prefixes(plan, [str(ipaddress.IPv4Address(base + 256)) + "/32"])
        with self.assertRaisesRegex(sources.SourceError, "OUT_OF_SCOPE"):
            sources.select_prefixes(plan, ["11.0.0.0/23"])
        with self.assertRaisesRegex(sources.SourceError, "OUT_OF_SCOPE"):
            sources.select_prefixes(plan, ["2001:db9::/32"])

    def test_adjacent_announced_coverage_and_selected_hosts_semantics_are_independent(self):
        plan = {"status": "PASS", "prefixes_v4": ["192.0.2.0/25", "192.0.2.128/25"], "prefixes_v6": []}
        self.assertEqual(sources.select_prefixes(plan, ["192.0.2.0/24"]), ["192.0.2.0/24"])
        self.assertEqual(sources.select_prefixes(plan, ["192.0.2.0/31", "192.0.2.2/31"]),
                         ["192.0.2.0/31", "192.0.2.2/31"])

    def test_bad_restored_plan_shape_scope_family_and_future_time_are_rejected(self):
        original = sources.build_asn_plan(64500, runtime=Runtime([prefixes_payload()]), now=NOW)
        mutations = [
            lambda p: p.update(status="UNKNOWN"),
            lambda p: p.update(asn=64501),
            lambda p: p.update(asn=True),
            lambda p: p.update(origin_ip=IP),
            lambda p: p.update(origin_asns=[64500]),
            lambda p: p.update(moas=False),
            lambda p: p.update(source="Unverified Source"),
            lambda p: p.update(issues=["\x1b[2J"]),
            lambda p: p.update(snapshot_time=stamp(1)),
            lambda p: p.update(retrieved_at=stamp(1)),
            lambda p: p.update(snapshot_time=NOW),
            lambda p: p.update(query_endtime=stamp(-7200)),
            lambda p: p.update(prefixes_v4=["2001:db8::/32"]),
            lambda p: p.update(prefixes_v6=["192.0.2.0/24"]),
            lambda p: p.update(prefixes_v4=["192.0.2.1/24"]),
            lambda p: p.update(prefixes_v4="192.0.2.0/24"),
            lambda p: p.pop("prefixes_v6"),
            lambda p: p.update(prefixes_v4=["192.0.2.0/24"] * (sources.MAX_PREFIXES + 1)),
        ]
        for mutate in mutations:
            plan = copy.deepcopy(original)
            mutate(plan)
            with self.subTest(mutate=mutate), self.assertRaisesRegex(sources.SourceError, "STATE_PLAN"):
                sources.validate_asn_plan(plan, asn=64500, now=NOW)
        for value in ([], None, 123):
            with self.subTest(value=value), self.assertRaisesRegex(sources.SourceError, "STATE_PLAN"):
                sources.validate_asn_plan(value, asn=64500, now=NOW)

    def test_restored_origin_context_and_moas_must_match_the_request(self):
        def origin_plan(origins, explicit=None):
            return sources.build_asn_plan(asn=explicit, origin_ip=IP, runtime=Runtime([
                {"status": "ok", "data": {"asns": origins, "prefix": "192.0.2.0/24"}}, prefixes_payload(),
            ]), now=NOW)
        single = origin_plan([64500])
        self.assertIs(sources.validate_asn_plan(single, origin_ip=IP, now=NOW), single)
        with self.assertRaisesRegex(sources.SourceError, "STATE_PLAN"):
            sources.validate_asn_plan(single, origin_ip="192.0.2.11", now=NOW)
        multi = origin_plan([64500, 64501], explicit=64500)
        self.assertIs(sources.validate_asn_plan(multi, asn=64500, origin_ip=IP, now=NOW), multi)
        with self.assertRaisesRegex(sources.SourceError, "STATE_PLAN"):
            sources.validate_asn_plan(multi, origin_ip=IP, now=NOW)
        for mutate in (
                lambda p: p.update(origin_asns=[64501]),
                lambda p: p.update(moas=True),
                lambda p: p["origin_lookup"].update(asns=[64501]),
                lambda p: p["origin_lookup"].update(retrieved_at=stamp(1)),
                lambda p: p.update(origin_prefix="198.51.100.0/24")):
            value = copy.deepcopy(single)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaisesRegex(sources.SourceError, "STATE_PLAN"):
                sources.validate_asn_plan(value, origin_ip=IP, now=NOW)


if __name__ == "__main__":
    unittest.main()
