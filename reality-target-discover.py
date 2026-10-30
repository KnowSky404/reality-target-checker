#!/usr/bin/env python3
"""Bounded IPv4 HTTPS candidate discovery; final trust checks stay in Bash."""

import argparse
import bisect
import concurrent.futures
import errno
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import ssl
import stat
import statistics
import subprocess
import sys
import tempfile
import threading
import time


VERSION = "0.3.0"
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_NAMES_PER_IP = 16
CHECKER = Path(__file__).resolve().with_name("reality-target-checker.sh")
BASIC = {"tcp443", "tls13", "cert_chain", "cert_san", "cert_validity"}
COMPATIBILITY = {"alpn_h2", "x25519"}
ANCILLARY = {"cert_expiry", "https_response", "http_redirect", "asn", "same_asn", "cdn"}
STATUSES = {"PASS", "WARN", "FAIL", "UNKNOWN"}
EXPECTED_TLS_REJECTIONS = {
    "SSLV3_ALERT_HANDSHAKE_FAILURE", "TLSV1_UNRECOGNIZED_NAME",
    "TLSV1_ALERT_UNRECOGNIZED_NAME", "TLSV1_ALERT_PROTOCOL_VERSION",
    "TLSV1_ALERT_NO_APPLICATION_PROTOCOL", "TLSV13_ALERT_CERTIFICATE_REQUIRED",
    "TLSV1_ALERT_ACCESS_DENIED", "TLSV1_ALERT_INSUFFICIENT_SECURITY",
}
_MODULE_LOCK = threading.RLock()


class DiscoveryError(Exception):
    """A bounded operation could not produce reliable evidence."""


def module(name):
    with _MODULE_LOCK:
        return _module(name)


def _module(name):
    key = "rtc_" + name
    if key not in sys.modules:
        path = Path(__file__).resolve().with_name("reality-target-" + name + ".py")
        spec = importlib.util.spec_from_file_location(key, path)
        if spec is None or spec.loader is None:
            raise DiscoveryError("DEPENDENCY")
        loaded = importlib.util.module_from_spec(spec)
        sys.modules[key] = loaded
        try:
            spec.loader.exec_module(loaded)
        except (ImportError, OSError):
            sys.modules.pop(key, None)
            raise DiscoveryError("DEPENDENCY") from None
    return sys.modules[key]


def canonical_ip(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("IP")
    address = ipaddress.ip_address(value)
    if address.version == 4 and str(address) != value:
        raise ValueError("IP")
    return str(address) if address.version == 4 else address.exploded


def finite_number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def normalize_name(value):
    if not isinstance(value, str) or not value.isascii():
        return None
    name = value.removesuffix(".").lower()
    if not 1 <= len(name) <= 253:
        return None
    if re.fullmatch(r"[0-9.]+", name):
        return None
    # curl interprets inet_aton-style hex/mixed hosts as IPs, bypassing --resolve.
    if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}", name):
        return None
    labels = name.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in labels):
        return None
    return name


def parse_san(text):
    names, wildcards = set(), set()
    for value in re.findall(r"(?:^|[,\n])[ \t]*DNS:([^,\n]*)", text):
        value = value.strip(" \t\r")
        if value.startswith("*."):
            base = normalize_name(value[2:])
            if base:
                wildcards.add("*." + base)
        else:
            name = normalize_name(value)
            if name:
                names.add(name)
    truncated = max(len(names), len(wildcards)) > MAX_NAMES_PER_IP
    return (sorted(names)[:MAX_NAMES_PER_IP],
            sorted(wildcards)[:MAX_NAMES_PER_IP], truncated)


def parse_ptr(text, ip):
    match = re.search(r"status: ([A-Z]+)", text)
    if not match or match[1] not in {"NOERROR", "NXDOMAIN"}:
        raise DiscoveryError("PTR_RESPONSE")
    if match[1] == "NXDOMAIN":
        return []
    owner = ipaddress.ip_address(ip).reverse_pointer
    aliases, ptrs = {}, {}
    for line in text.splitlines():
        fields = line.split()
        if (len(fields) != 5 or not fields[1].isdigit() or fields[2] != "IN"
                or not fields[0].isascii() or not fields[4].isascii()):
            continue
        record_owner = fields[0].removesuffix(".").lower()
        if fields[3] == "CNAME":
            # RFC 2317 reverse owners may contain '/', unlike website SNI names.
            target = fields[4].removesuffix(".").lower()
            aliases.setdefault(record_owner, set()).add(target)
        elif fields[3] == "PTR":
            name = normalize_name(fields[4])
            if name:
                ptrs.setdefault(record_owner, set()).add(name)
    visited = set()
    for depth in range(17):
        if owner in visited:
            raise DiscoveryError("PTR_CNAME_LOOP")
        visited.add(owner)
        targets = aliases.get(owner, set())
        if len(targets) > 1 or (targets and owner in ptrs):
            raise DiscoveryError("PTR_CNAME_CONFLICT")
        if not targets:
            return sorted(ptrs.get(owner, set()))
        if depth == 16:
            raise DiscoveryError("PTR_CNAME_LIMIT")
        owner = next(iter(targets))
    return []


def _aggregate(statuses):
    return "FAIL" if "FAIL" in statuses else "UNKNOWN" if "UNKNOWN" in statuses else "PASS"


def validate_report(report, returncode, ip, sni):
    """Reject malformed or contradictory checker evidence before accepting it."""
    try:
        if (not isinstance(report, dict) or "error" in report
                or report["schema_version"] != "1.0"
                or not isinstance(report["tool_version"], str)
                or report["target"] != sni or report["sni"] != sni
                or report["port"] != 443
                or report["selection"]["scope"] != "explicit_ip"
                or report["selection"]["complete"] is not True
                or not isinstance(report["endpoints"], list)
                or len(report["endpoints"]) != 1):
            raise ValueError
        endpoint = report["endpoints"][0]
        family = ipaddress.ip_address(ip).version
        if canonical_ip(endpoint["ip"]) != canonical_ip(ip) or endpoint["family"] != family:
            raise ValueError
        checks = endpoint["checks"]
        if not isinstance(checks, list):
            raise ValueError
        values = {item["id"]: item["status"] for item in checks}
        if (len(values) != len(checks) or not (BASIC | COMPATIBILITY | ANCILLARY) <= values.keys()
                or any(value not in STATUSES for value in values.values())
                or any(values[key] == "WARN" for key in BASIC | COMPATIBILITY)):
            raise ValueError
        dns = report["dns"]
        if not isinstance(dns["a"], list):
            raise ValueError
        for address in dns["a"]:
            if str(ipaddress.IPv4Address(address)) != address:
                raise ValueError
        if not isinstance(dns["aaaa"], list):
            raise ValueError
        for address in dns["aaaa"]:
            if canonical_ip(address) != address or ipaddress.ip_address(address).version != 6:
                raise ValueError
        dns_checks = {item["type"]: item["status"] for item in dns["checks"]}
        if (not {"A", "AAAA", "CNAME"} <= dns_checks.keys()
                or len(dns_checks) != len(dns["checks"])
                or any(value not in STATUSES for value in dns_checks.values())):
            raise ValueError
        basic = _aggregate([values[key] for key in BASIC])
        compatibility = _aggregate([values[key] for key in COMPATIBILITY])
        ancillary = "PASS" if (all(values[key] == "PASS" for key in ANCILLARY)
                               and all(value == "PASS" for value in dns_checks.values())) else "WARN"
        if "FAIL" in (basic, compatibility):
            status, code = "FAIL", 1
        elif "UNKNOWN" in (basic, compatibility):
            status, code = "UNKNOWN", 2
        elif ancillary == "WARN":
            status, code = "WARN", 3
        else:
            status, code = "PASS", 0
        summary = report["summary"]
        if (type(returncode) is not int or type(summary["exit_code"]) is not int
                or returncode != code or summary["exit_code"] != code
                or summary["status"] != status or summary["basic_tls"] != basic
                or summary["compatibility"] != compatibility or summary["ancillary"] != ancillary
                or not isinstance(report["risks"], list) or not isinstance(report["unknowns"], list)):
            raise ValueError
        return basic == compatibility == "PASS"
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise ValueError("CHECKER_REPORT") from error


def dns_binding(report, ip):
    try:
        checks = {item["type"]: item["status"] for item in report["dns"]["checks"]}
        family = ipaddress.ip_address(ip).version
        if checks.get("A" if family == 4 else "AAAA") != "PASS":
            return "UNKNOWN"
        addresses = report["dns"]["a" if family == 4 else "aaaa"]
        return "MATCH" if canonical_ip(ip) in {canonical_ip(value) for value in addresses} else "DIFFERENT"
    except (KeyError, TypeError, ValueError):
        return "UNKNOWN"


class Runtime:
    """Shared deadline, cancellable launch pacing, and owned process groups."""

    def __init__(self, timeout, deadline, rate):
        self.timeout = timeout
        self.started = time.monotonic()
        self.deadline = self.started + deadline
        self.rate = rate
        self.cancelled = threading.Event()
        self.signal_number = None
        self._lock = threading.Lock()
        self._next_start = self.started
        self._processes = set()

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())

    def check(self):
        if self.cancelled.is_set():
            raise DiscoveryError("CANCELLED")
        if self.remaining() <= 0:
            raise DiscoveryError("DEADLINE")

    def operation_timeout(self):
        self.check()
        return min(self.timeout, self.remaining())

    def acquire(self):
        self.check()
        with self._lock:
            launch = max(time.monotonic(), self._next_start)
            self._next_start = launch + 1.0 / self.rate
        while time.monotonic() < launch:
            self.check()
            self.cancelled.wait(min(0.05, launch - time.monotonic(), self.remaining()))
        self.check()

    @staticmethod
    def _session_groups(session):
        # GNU timeout creates another process group but stays in our session.
        groups = {session}
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                fields = (entry / "stat").read_bytes().rsplit(b")", 1)[1].split()
                if int(fields[3]) == session:
                    groups.add(int(fields[2]))
            except (OSError, ValueError, IndexError):
                continue
        return groups

    @staticmethod
    def _signal_groups(groups, number):
        for group in groups:
            try:
                os.killpg(group, number)
            except ProcessLookupError:
                pass

    @classmethod
    def _terminate(cls, process):
        groups = cls._session_groups(process.pid)
        cls._signal_groups(groups - {process.pid}, signal.SIGTERM)
        cls._signal_groups({process.pid}, signal.SIGTERM)
        try:
            process.wait(timeout=0.3)
        except subprocess.TimeoutExpired:
            # Kill stubborn probes first; Bash can then run its pending EXIT trap.
            groups.update(cls._session_groups(process.pid))
            cls._signal_groups(groups - {process.pid}, signal.SIGKILL)
            try:
                process.wait(timeout=0.3)
            except subprocess.TimeoutExpired:
                cls._signal_groups({process.pid}, signal.SIGKILL)
        groups.update(cls._session_groups(process.pid))
        cls._signal_groups(groups, signal.SIGKILL)
        process.wait()

    def run(self, args, input_data=None, timeout=None, output_limit=MAX_OUTPUT_BYTES, env=None):
        self.check()
        end = min(self.deadline, time.monotonic() + (self.timeout if timeout is None else timeout))
        with tempfile.TemporaryFile() as stdin, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            if input_data:
                stdin.write(input_data)
                stdin.seek(0)
            try:
                process = subprocess.Popen(args, stdin=stdin, stdout=stdout, stderr=stderr,
                                           start_new_session=True, env=env)
            except OSError as error:
                raise DiscoveryError("PROCESS_START") from error
            with self._lock:
                self._processes.add(process)
            try:
                while True:
                    self.check()
                    if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > output_limit:
                        raise DiscoveryError("OUTPUT_LIMIT")
                    if time.monotonic() >= end:
                        raise DiscoveryError("OPERATION_TIMEOUT")
                    try:
                        process.wait(timeout=min(0.05, end - time.monotonic()))
                        break
                    except subprocess.TimeoutExpired:
                        pass
                if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > output_limit:
                    raise DiscoveryError("OUTPUT_LIMIT")
                stdout.seek(0)
                stderr.seek(0)
                return process.returncode, stdout.read(output_limit), stderr.read(output_limit)
            finally:
                self._terminate(process)
                with self._lock:
                    self._processes.discard(process)

    def close(self):
        with self._lock:
            processes = list(self._processes)
        for process in processes:
            self._terminate(process)


def wait_socket(connection, runtime, end, writing=False):
    runtime.check()
    remaining = min(end - time.monotonic(), runtime.remaining())
    if remaining <= 0:
        raise TimeoutError("SOCKET_TIMEOUT")
    select.select([] if writing else [connection], [connection] if writing else [],
                  [connection], min(0.05, remaining))


def connect_socket(ip, runtime):
    """Connect without blocking cancellation for the full operation timeout."""
    runtime.check()
    family = socket.AF_INET if ipaddress.ip_address(ip).version == 4 else socket.AF_INET6
    connection = socket.socket(family, socket.SOCK_STREAM)
    end = min(runtime.deadline, time.monotonic() + runtime.timeout)
    try:
        connection.setblocking(False)
        code = connection.connect_ex((ip, 443))
        if code not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
            raise OSError(code, os.strerror(code))
        while code:
            wait_socket(connection, runtime, end, writing=True)
            _, writable, exceptional = select.select([], [connection], [connection], 0)
            if writable or exceptional:
                code = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if code:
                    raise OSError(code, os.strerror(code))
        return connection
    except BaseException:
        connection.close()
        raise


def discover_host(ip, runtime):
    result = {"ip": ip, "tcp": "UNKNOWN", "tls": "NOT_ATTEMPTED", "ptr": "NOT_ATTEMPTED",
              "names": {}, "wildcards": [], "issues": [], "completed": False}
    try:
        runtime.acquire()
        try:
            connection = connect_socket(ip, runtime)
        except ConnectionRefusedError:
            result.update(tcp="CLOSED", completed=True)
            return result
        except (TimeoutError, OSError) as error:
            result["issues"].append("CONNECT_TIMEOUT" if isinstance(error, TimeoutError) else "CONNECT_ERROR")
            result["completed"] = True
            return result
        result["tcp"] = "OPEN"
        cert = None
        # Discovery only: untrusted SANs are seeds. Bash independently verifies trust.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with connection:
                connection.setblocking(False)
                end = min(runtime.deadline, time.monotonic() + runtime.timeout)
                with context.wrap_socket(connection, server_hostname=None, do_handshake_on_connect=False) as tls:
                    while True:
                        runtime.check()
                        if time.monotonic() >= end:
                            raise TimeoutError("TLS_TIMEOUT")
                        try:
                            tls.do_handshake()
                            break
                        except ssl.SSLWantReadError:
                            wait_socket(tls, runtime, end)
                        except ssl.SSLWantWriteError:
                            wait_socket(tls, runtime, end, writing=True)
                    cert = tls.getpeercert(binary_form=True)
                    result["tls"] = "CERTIFICATE" if cert else "NO_CERTIFICATE"
        except ssl.SSLError as error:
            reason = getattr(error, "reason", None) or ""
            if reason in EXPECTED_TLS_REJECTIONS:
                result["tls"] = "NO_CERTIFICATE"
            else:
                result["tls"] = "UNKNOWN"
                result["issues"].append("TLS_HANDSHAKE")
        except (TimeoutError, OSError) as error:
            result["tls"] = "UNKNOWN"
            result["issues"].append("TLS_TIMEOUT" if isinstance(error, TimeoutError) else "TLS_IO")
        if cert:
            result["tls"] = "CERTIFICATE"
            try:
                if len(cert) > MAX_OUTPUT_BYTES:
                    raise DiscoveryError("CERTIFICATE_LIMIT")
                code, output, _ = runtime.run(["openssl", "x509", "-inform", "DER", "-noout", "-ext", "subjectAltName"], cert)
                if code:
                    raise DiscoveryError("CERTIFICATE_PARSE")
                names, result["wildcards"], truncated = parse_san(output.decode("utf-8", "replace"))
                result["names"] = {name: ["san"] for name in names}
                if truncated:
                    result["issues"].append("NAME_LIMIT")
            except DiscoveryError as error:
                result["issues"].append(str(error))
        try:
            code, output, _ = runtime.run(["dig", "-r", "+time=" + str(runtime.timeout), "+tries=1",
                                           "+nosearch", "+noall", "+answer", "+comments", "-x", ip])
            if code:
                raise DiscoveryError("PTR_QUERY")
            for name in parse_ptr(output.decode("utf-8", "replace"), ip):
                result["names"].setdefault(name, []).append("ptr")
            result["ptr"] = "COMPLETE"
        except DiscoveryError as error:
            result["ptr"] = "UNKNOWN"
            result["issues"].append(str(error))
        if len(result["names"]) > MAX_NAMES_PER_IP:
            result["issues"].append("NAME_LIMIT")
        result["names"] = {name: sorted(set(result["names"][name]))
                           for name in sorted(result["names"])[:MAX_NAMES_PER_IP]}
        result["completed"] = True
    except DiscoveryError as error:
        result["issues"].append(str(error))
    return result


def verify_candidate(candidate, args, runtime):
    result = dict(candidate, eligible=False, dns_binding="UNKNOWN", report=None, error=None,
                  observed_at=None, evidence_source="not_started", elapsed_ms=0)
    started = None
    try:
        runtime.acquire()
        started = time.monotonic()
        result["evidence_source"] = "live"
        family = ipaddress.ip_address(candidate["ip"]).version
        command = ["bash", str(CHECKER), "check", candidate["sni"], "--sni", candidate["sni"],
                   "--ip", candidate["ip"], "--ipv" + str(family), "--json", "--timeout", str(args.timeout)]
        if args.origin_ip:
            command += ["--origin-ip", args.origin_ip]
        code, output, _ = runtime.run(command, timeout=runtime.remaining())
        report = json.loads(output)
        result["eligible"] = validate_report(report, code, candidate["ip"], candidate["sni"])
        result["report"] = report
        result["dns_binding"] = dns_binding(report, candidate["ip"])
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        if getattr(args, "kernel", None) and result["eligible"]:
            result["kernel"] = module("kernel").verify(candidate["ip"], candidate["sni"], runtime, args.kernel_bin)
            if result["kernel"]["status"] != "PASS":
                result["eligible"] = False
                result["error"] = "KERNEL_UNKNOWN"
    except (DiscoveryError, ValueError, UnicodeError) as error:
        result["error"] = str(error) if isinstance(error, DiscoveryError) else "CHECKER_REPORT"
    if started is not None:
        result["observed_at"] = time.time()
        if not result["elapsed_ms"]:
            result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def ip_sort(ip):
    address = ipaddress.ip_address(ip)
    return address.version, int(address)


def _inputs(args):
    known, seeds = [], []
    if args.known_ips or args.seeds:
        sources = module("sources")
        if args.known_ips:
            known = sources.load_known_ips(args.known_ips)
        if args.seeds:
            seeds = sources.load_seeds(args.seeds, args.seed_format, normalize_name=normalize_name)
    return {"known": known, "seeds": seeds}


def _union_host_count(networks):
    intervals = sorted((int(net.network_address) + (net.prefixlen < 31),
                        int(net.broadcast_address) - (net.prefixlen < 31))
                       for net in networks if net.version == 4)
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return sum(end - start + 1 for start, end in merged)


def _scope_index(networks):
    result = {}
    for family in (4, 6):
        merged = []
        for start, end in sorted((int(net.network_address), int(net.broadcast_address))
                                 for net in networks if net.version == family):
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        result[family] = ([start for start, _ in merged], [end for _, end in merged])
    return result


def _scope_contains(address, index):
    starts, ends = index[address.version]
    position = bisect.bisect_right(starts, int(address)) - 1
    return position >= 0 and int(address) <= ends[position]


def _state_get(store, kind, key):
    if store is None:
        return None
    try:
        return store.get_record(kind, key)
    except Exception as error:
        if error.__class__.__name__ != "StateError":
            raise
        raise DiscoveryError(str(error)) from error


def _state_put(store, kind, key, payload):
    if store is None:
        return
    try:
        store.put(kind, key, payload)
    except Exception as error:
        if error.__class__.__name__ != "StateError":
            raise
        raise DiscoveryError(str(error)) from error


def build_plan(args, runtime):
    guarded = bool(args.plan_only or args.asn or args.asn_from_ip or args.known_ips or args.seeds or args.include_cidr)
    if guarded:
        runtime.check()
    inputs = getattr(runtime, "inputs", None) or _inputs(args)
    asn = None
    if args.asn or args.asn_from_ip:
        saved = _state_get(getattr(runtime, "checkpoint", None), "meta", "asn_plan")
        if saved:
            sources = module("sources")
            try:
                asn = sources.validate_asn_plan(saved["payload"], asn=args.asn, origin_ip=args.asn_from_ip)
                acquisitions = [asn["retrieved_at"]]
                origin_lookup = asn.get("origin_lookup")
                if origin_lookup is not None:
                    acquisitions.append(origin_lookup["retrieved_at"])
                if any(time.time() - sources._timestamp(stamp) > args.state_ttl for stamp in acquisitions):
                    asn = None
                else:
                    asn = dict(asn, evidence_source="checkpoint")
            except sources.SourceError as error:
                if str(error) != "RIPE_STALE_SNAPSHOT":
                    raise DiscoveryError("STATE_PLAN") from error
                asn = None
        if asn is None:
            asn = module("sources").build_asn_plan(asn=args.asn, origin_ip=args.asn_from_ip,
                                                    runtime=runtime, cache=getattr(runtime, "cache", None))
            if asn["status"] == "PASS":
                compact = {key: value for key, value in asn.items() if key != "announced_prefixes"}
                _state_put(getattr(runtime, "checkpoint", None), "meta", "asn_plan", compact)
    selected = ([args.cidr] if args.cidr else []) + args.include_cidr
    networks = list(dict.fromkeys(selected))
    if asn and asn["status"] == "PASS" and networks:
        module("sources").select_prefixes(asn, [str(value) for value in networks])
    allowed = networks
    if asn and not allowed:
        allowed = [ipaddress.ip_network(value) for value in asn["prefixes_v4"] + asn["prefixes_v6"]]
    allowed_index = _scope_index(allowed)
    if guarded:
        runtime.check()
    manifest = bool(args.known_ips or args.seeds)
    requires_selection = bool(asn and not networks and not manifest)
    targets, excluded = set(), []
    if manifest:
        provided = set(inputs["known"]) | {seed["ip"] for seed in inputs["seeds"]}
        for index, value in enumerate(sorted(provided, key=ip_sort)):
            if index % 128 == 0:
                runtime.check()
            ip = ipaddress.ip_address(value)
            if (networks or asn) and not _scope_contains(ip, allowed_index):
                excluded.append(value)
            else:
                targets.add(value)
        proposed = len(targets)
    else:
        proposed = _union_host_count(networks) + sum(net.version == 6 and net.prefixlen == 128 for net in networks)
        if proposed <= args.max_hosts and not requires_selection:
            for net in networks:
                if net.version == 4:
                    targets.update(str(value) for value in net.hosts())
                elif net.prefixlen == 128:
                    targets.add(net.network_address.exploded)
    needs_ipv6 = bool(not manifest and any(net.version == 6 and net.prefixlen != 128 for net in networks))
    within_budget = proposed <= args.max_hosts
    if not args.plan_only and not requires_selection:
        if not within_budget:
            raise DiscoveryError("HOST_BUDGET_EXCEEDED")
        if needs_ipv6:
            raise DiscoveryError("IPV6_KNOWN_IPS_REQUIRED")
    seeds = [seed for seed in inputs["seeds"] if seed["ip"] in targets]
    if asn and asn["status"] != "PASS":
        status, code = "UNKNOWN", 2
        targets, seeds = set(), []
    elif not within_budget or needs_ipv6:
        status, code = "WARN", 3
    else:
        status, code = "PASS", 0
    if guarded:
        runtime.check()
    return {"schema_version": "1.0", "report_type": "discovery_plan", "tool_version": VERSION,
            "asn": asn, "requires_selection": requires_selection,
            "scope": {"cidr": str(args.cidr) if args.cidr else None,
                      "prefixes": [str(net) for net in networks], "selection": "manifest" if manifest else "cidr_hosts",
                      "host_count": proposed, "within_budget": within_budget, "requires_known_ipv6": needs_ipv6,
                      "origin_ip": args.origin_ip, "excluded_input_ips": excluded,
                      "limits": {key: getattr(args, key) for key in
                                 ("max_hosts", "concurrency", "rate", "timeout", "deadline", "max_candidates", "samples")}},
            "targets": sorted(targets, key=ip_sort), "seeds": seeds,
            "summary": {"status": status, "exit_code": code}}


def _validate_host(host, ip):
    try:
        if (not isinstance(host, dict) or host["ip"] != ip or type(host["completed"]) is not bool
                or not isinstance(host["names"], dict) or len(host["names"]) > MAX_NAMES_PER_IP
                or not isinstance(host["issues"], list) or len(host["issues"]) > 32
                or host["tcp"] not in {"OPEN", "CLOSED", "UNKNOWN"}
                or host["tls"] not in {"CERTIFICATE", "NO_CERTIFICATE", "NOT_ATTEMPTED", "UNKNOWN"}
                or host["ptr"] not in {"COMPLETE", "NOT_ATTEMPTED", "UNKNOWN"}
                or not isinstance(host["wildcards"], list) or len(host["wildcards"]) > MAX_NAMES_PER_IP):
            raise ValueError
        for name, sources in host["names"].items():
            if normalize_name(name) != name or not isinstance(sources, list) or not 1 <= len(sources) <= 16:
                raise ValueError
            if any(not isinstance(source, str) or not re.fullmatch(r"[a-z0-9:_-]{1,64}", source) for source in sources):
                raise ValueError
        if any(not isinstance(issue, str) or not re.fullmatch(r"[A-Z0-9_]{1,64}", issue) for issue in host["issues"]):
            raise ValueError
        for wildcard in host["wildcards"]:
            if not isinstance(wildcard, str) or not wildcard.startswith("*.") or normalize_name(wildcard[2:]) != wildcard[2:]:
                raise ValueError
        stamp = host.get("observed_at")
        if not finite_number(stamp) or not 0 < stamp <= time.time():
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise DiscoveryError("STATE_HOST") from None
    return host


def host_task(ip, names, args, runtime):
    checkpoint = getattr(runtime, "checkpoint", None)
    cache = getattr(runtime, "cache", None)
    result = None
    try:
        if names:
            result = {"ip": ip, "tcp": "UNKNOWN", "tls": "NOT_ATTEMPTED", "ptr": "NOT_ATTEMPTED",
                      "names": names, "wildcards": [], "issues": [], "completed": True,
                      "evidence_source": "import", "observed_at": None}
            if len(names) > MAX_NAMES_PER_IP:
                result["names"] = {name: names[name] for name in sorted(names)[:MAX_NAMES_PER_IP]}
                result["issues"].append("NAME_LIMIT")
        else:
            for store, source, kind in ((checkpoint, "checkpoint", "host"), (cache, "cache", "hosts:" + VERSION)):
                saved = _state_get(store, kind, ip)
                if saved:
                    host = _validate_host(saved["payload"], ip)
                    ttl = args.state_ttl if source == "checkpoint" else args.cache_ttl
                    if time.time() - host["observed_at"] > ttl:
                        continue
                    if host["completed"] and not host["issues"] and (host["names"] or source == "checkpoint"):
                        result = dict(host, evidence_source=source)
                        if source == "cache":
                            _state_put(checkpoint, "host", ip, result)
                        return result
            result = discover_host(ip, runtime)
            result.update(evidence_source="live" if result["completed"] else "not_started",
                          observed_at=time.time() if result["completed"] else None)
            if result["completed"] and not result["issues"] and result["names"]:
                _state_put(cache, "hosts:" + VERSION, ip, result)
        if result["completed"]:
            _state_put(checkpoint, "host", ip, result)
        return result
    except DiscoveryError as error:
        if result is not None:
            result["issues"].append(str(error))
            result["completed"] = False
            return result
        return {"ip": ip, "tcp": "UNKNOWN", "tls": "UNKNOWN", "ptr": "UNKNOWN",
                "names": {name: names[name] for name in sorted(names)[:MAX_NAMES_PER_IP]},
                "wildcards": [], "issues": [str(error)], "completed": False,
                "evidence_source": "not_started", "observed_at": None}


def _restored_measurement(record, seed, args):
    value = record["payload"]
    try:
        if not isinstance(value, dict) or value["ip"] != seed["ip"] or value["sni"] != seed["sni"]:
            raise ValueError
        if value.get("error") or value.get("report") is None:
            return None
        report = value["report"]
        eligible = validate_report(report, report["summary"]["exit_code"], seed["ip"], seed["sni"])
        if report["summary"]["status"] == "UNKNOWN":
            return None
        if args.kernel and eligible:
            eligible = value["kernel"]["status"] == "PASS"
            if not eligible:
                return None
        if (type(value["eligible"]) is not bool or value["eligible"] != eligible
                or not finite_number(value["elapsed_ms"])
                or not 0 <= value["elapsed_ms"] < 86400000
                or not finite_number(value["observed_at"])
                or not 0 < value["observed_at"] <= time.time()):
            raise ValueError
        if time.time() - value["observed_at"] > args.state_ttl:
            return None
        return dict(value, evidence_source="checkpoint", dns_binding=dns_binding(report, seed["ip"]))
    except (KeyError, TypeError, ValueError):
        raise DiscoveryError("STATE_MEASUREMENT") from None


def measure_candidate(seed, args, runtime):
    measurements = []
    checkpoint = getattr(runtime, "checkpoint", None)
    for index in range(args.samples):
        key = json.dumps([seed["ip"], seed["sni"], index], separators=(",", ":"))
        value = None
        try:
            saved = _state_get(checkpoint, "sample", key)
            value = _restored_measurement(saved, seed, args) if saved else None
            if value is None:
                if index and args.sample_interval:
                    previous = measurements[-1].get("observed_at")
                    delay = max(0, args.sample_interval - (time.time() - previous)) if previous else args.sample_interval
                    end = time.monotonic() + delay
                    while time.monotonic() < end:
                        runtime.check()
                        runtime.cancelled.wait(min(0.05, end - time.monotonic()))
                value = verify_candidate(seed, args, runtime)
                _state_put(checkpoint, "sample", key, value)
        except DiscoveryError as error:
            if value is not None:
                value = dict(value, eligible=False, error=str(error))
            else:
                value = dict(seed, eligible=False, dns_binding="UNKNOWN", report=None, error=str(error),
                             elapsed_ms=0, observed_at=None, evidence_source="not_started")
        measurements.append(value)
    result = dict(measurements[-1])
    result["measurements"] = measurements
    passed = sum(value["eligible"] for value in measurements)
    times = [value["elapsed_ms"] for value in measurements if value["report"] is not None]
    result["eligible"] = passed == args.samples
    result["statistics"] = {"planned": args.samples, "completed": sum(value["report"] is not None for value in measurements),
                            "passed": passed, "success_rate": passed / args.samples,
                            "median_ms": statistics.median(times) if times else None,
                            "spread_ms": max(times) - min(times) if times else None,
                            "metric": "checker_wall_ms"}
    return result


def scan(args, runtime):
    plan = build_plan(args, runtime)
    if args.plan_only or plan["requires_selection"] or plan["summary"]["exit_code"] == 2:
        return plan
    imported = {}
    for seed in plan["seeds"]:
        imported.setdefault(seed["ip"], {}).setdefault(seed["sni"], set()).update(seed["sources"])
    imported = {ip: {name: sorted(sources) for name, sources in names.items()} for ip, names in imported.items()}
    # All enumeration and input budgets are checked before a target job starts.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        hosts = list(pool.map(lambda ip: host_task(ip, imported.get(ip, {}), args, runtime), plan["targets"]))
    hosts.sort(key=lambda item: ip_sort(item["ip"]))
    seeds = [{"ip": host["ip"], "sni": name, "sources": sources}
             for host in hosts for name, sources in sorted(host["names"].items())]
    reasons = sorted({issue for host in hosts for issue in host["issues"]})
    discovered_count = len(seeds)
    if discovered_count > args.max_candidates:
        reasons.append("CANDIDATE_LIMIT")
        seeds = seeds[:args.max_candidates]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        candidates = list(pool.map(lambda seed: measure_candidate(seed, args, runtime), seeds))
    for candidate in candidates:
        reasons.extend(value["error"] for value in candidate["measurements"] if value["error"])
    if runtime.cancelled.is_set():
        reasons.append("CANCELLED")
    elif runtime.remaining() <= 0:
        reasons.append("DEADLINE")
    reasons = sorted(set(reasons))
    complete = not reasons and all(host["completed"] for host in hosts)
    def rank(item):
        values = item["statistics"]
        measured = (-values["success_rate"],
                    values["median_ms"] if values["median_ms"] is not None else float("inf"),
                    values["spread_ms"] if values["spread_ms"] is not None else float("inf")) if args.samples > 1 else ()
        return (not item["eligible"], *measured, ip_sort(item["ip"]), item["sni"])
    candidates.sort(key=rank)
    eligible = [item for item in candidates if item["eligible"]]
    unknown = any(value["error"] or value["report"]["summary"]["status"] == "UNKNOWN"
                  for item in candidates for value in item["measurements"])
    if runtime.signal_number:
        status, code = "UNKNOWN", 128 + runtime.signal_number
    elif not complete or unknown:
        status, code = "UNKNOWN", 2
    elif not eligible:
        status, code = "NO_CANDIDATES", 1
    elif any(value["report"]["summary"]["status"] == "WARN"
             for item in eligible for value in item["measurements"]):
        status, code = "WARN", 3
    else:
        status, code = "PASS", 0
    return {"schema_version": "1.0", "report_type": "discovery", "tool_version": VERSION,
            "scope": plan["scope"], "plan": plan,
            "scan": {"complete": complete, "coverage": "best_effort", "hosts_completed": sum(host["completed"] for host in hosts),
                     "candidates_discovered": discovered_count,
                     "candidates_checked": sum(any(value["report"] is not None for value in item["measurements"]) for item in candidates),
                     "elapsed_ms": round((time.monotonic() - runtime.started) * 1000), "reasons": reasons},
            "hosts": hosts, "candidates": candidates,
            "summary": {"status": status, "exit_code": code, "eligible_count": len(eligible)}}


def host_count(network):
    return network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2


def _integer(low, high):
    def parse(value):
        if not re.fullmatch(r"[0-9]+", value) or not low <= int(value) <= high:
            raise argparse.ArgumentTypeError("必须是 %s..%s 的整数" % (low, high))
        return int(value)
    return parse


def parse_args(argv):
    parser = argparse.ArgumentParser(description="REALITY 范围计划、有限候选发现与固定 IP/SNI 复核（best effort）")
    parser.add_argument("cidr", nargs="?", help="严格对齐的 CIDR；IPv6 仅已知地址或 /128")
    parser.add_argument("--json", action="store_true", help="仅向 stdout 输出独立 discovery JSON")
    parser.add_argument("--origin-ip", help="用户确认的公网源 IP，仅用于 ASN 比较")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--asn", help="ASN 或 AS 前缀；未选择范围时仅输出计划")
    source.add_argument("--asn-from-ip", help="查询指定 IP 的 origin ASN，不自动作为 VPS 源 IP")
    parser.add_argument("--include-cidr", action="append", default=[], help="明确选择的 CIDR，可重复")
    parser.add_argument("--known-ips", help="每行一个 IPv4/IPv6 的有限地址清单")
    parser.add_argument("--seeds", help="离线候选 JSON、JSONL 或 CSV")
    parser.add_argument("--seed-format", choices=("generic", "censys", "shodan", "dns"), default="generic")
    parser.add_argument("--plan-only", action="store_true", help="仅生成范围计划，不连接目标端口")
    parser.add_argument("--cache-dir", help="显式启用 SQLite 元数据/正向种子缓存的私有目录")
    parser.add_argument("--checkpoint", help="持久任务 SQLite 文件，新任务不覆盖已有文件")
    parser.add_argument("--resume", action="store_true", help="恢复同一任务的已完成工作")
    parser.add_argument("--kernel", choices=("xray",), help="可选临时 Xray REALITY 端到端自检")
    parser.add_argument("--kernel-bin", default="xray", help="已安装 Xray 的可执行文件")
    for name, default, low, high, description in (
            ("max-hosts", 256, 1, 4096, "主机预算，超出则在网络操作前拒绝"),
            ("concurrency", 8, 1, 32, "并发任务上限"),
            ("rate", 10, 1, 100, "每秒启动发现/复核任务数，非内部请求数"),
            ("timeout", 3, 1, 60, "单次网络操作超时秒数"),
            ("deadline", 300, 1, 3600, "整次任务时间预算秒数"),
            ("max-candidates", 256, 1, 4096, "全局候选 IP/SNI 对预算"),
            ("samples", 1, 1, 5, "每候选采样次数，多次采样后按稳定性/耗时排序"),
            ("sample-interval", 0, 0, 60, "同一候选采样间隔秒数"),
            ("cache-ttl", 3600, 1, 86400, "缓存最长年龄秒数"),
            ("state-ttl", 3600, 1, 86400, "恢复证据最长年龄秒数")):
        parser.add_argument("--" + name, type=_integer(low, high), default=default,
                            help=description + "（默认 %(default)s）")
    args = parser.parse_args(argv)
    if len(args.include_cidr) > 4096:
        parser.error("--include-cidr 最多 4096 个范围")
    def network(value):
        if "%" in value or "/" not in value:
            raise ValueError
        address, mask = value.rsplit("/", 1)
        canonical_ip(address)
        if not re.fullmatch(r"0|[1-9][0-9]{0,2}", mask):
            raise ValueError
        return ipaddress.ip_network(value, strict=True)
    try:
        args.cidr = network(args.cidr) if args.cidr else None
        args.include_cidr = list(dict.fromkeys(network(value) for value in args.include_cidr))
        if args.origin_ip is not None:
            args.origin_ip = canonical_ip(args.origin_ip)
        if args.asn_from_ip is not None:
            args.asn_from_ip = canonical_ip(args.asn_from_ip)
        if args.asn:
            match = re.fullmatch(r"(?:AS)?([1-9][0-9]{0,9})", args.asn.upper())
            if not match or int(match[1]) > 4294967295:
                raise ValueError
            args.asn = int(match[1])
    except ValueError:
        parser.error("需要严格对齐的 CIDR、有效 IP 或 1..4294967295 的 ASN")
    networks = list(dict.fromkeys(([args.cidr] if args.cidr else []) + args.include_cidr))
    if not (networks or args.asn or args.asn_from_ip or args.known_ips or args.seeds):
        parser.error("需要 CIDR、ASN 或明确的地址/候选清单")
    if args.resume and not args.checkpoint:
        parser.error("--resume 需要 --checkpoint")
    if args.seed_format != "generic" and not args.seeds:
        parser.error("--seed-format 需要 --seeds")
    if (args.asn or args.asn_from_ip) and not (networks or args.known_ips or args.seeds):
        args.plan_only = True
    if (not args.plan_only and not (args.known_ips or args.seeds)
            and any(net.version == 6 and net.prefixlen != 128 for net in networks)):
        parser.error("IPv6 前缀仅过滤已知地址；请提供 --known-ips/--seeds 或单个 /128")
    if (not args.plan_only and not (args.known_ips or args.seeds)
            and _union_host_count(networks) + sum(net.version == 6 and net.prefixlen == 128 for net in networks) > args.max_hosts):
        parser.error("网段主机数超过 --max-hosts，未开始扫描")
    return args


def _file_hash(path, limit):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            details = os.fstat(stream.fileno())
            if not stat.S_ISREG(details.st_mode) or details.st_size > limit:
                raise DiscoveryError("INPUT_FILE_LIMIT")
            digest = hashlib.sha256()
            total = 0
            for chunk in iter(lambda: stream.read(65536), b""):
                total += len(chunk)
                if total > limit:
                    raise DiscoveryError("INPUT_FILE_LIMIT")
                digest.update(chunk)
            return digest.hexdigest()
    except OSError as error:
        raise DiscoveryError("INPUT_FILE") from error


def _trust_identity():
    names = ("SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "OPENSSL_CONF", "OPENSSL_MODULES")
    paths = {value for value in (os.environ.get(name) for name in names if name != "SSL_CERT_DIR") if value}
    defaults = ssl.get_default_verify_paths()
    paths.update(value for value in (defaults.cafile, "/etc/ssl/certs/ca-certificates.crt") if value)
    for directories in (os.environ.get("SSL_CERT_DIR"), defaults.capath):
        if directories:
            paths.update(path or "." for path in directories.split(os.pathsep))
    result = {"environment": {name: os.environ.get(name) for name in names}, "files": {}}
    def identity(path):
        try:
            value = os.stat(path)
            return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]
        except (OSError, ValueError):
            return None
    for path in sorted(paths):
        result["files"][path] = identity(path)
        try:
            if os.path.isdir(path):
                children = sorted(os.listdir(path))
                if len(children) > 4096:
                    raise DiscoveryError("TRUST_DIRECTORY_LIMIT")
                result["files"][path + "/"] = {name: identity(os.path.join(path, name)) for name in children}
        except OSError:
            result["files"][path + "/"] = None
    return result


def _fingerprint(args, input_hashes):
    semantic = {key: getattr(args, key) for key in
                ("asn", "asn_from_ip", "origin_ip", "seed_format", "max_hosts", "max_candidates",
                 "timeout", "samples", "sample_interval", "kernel")}
    semantic["cidrs"] = sorted(set(str(net) for net in ([args.cidr] if args.cidr else []) + args.include_cidr))
    semantic["inputs"] = input_hashes
    semantic["trust"] = _trust_identity()
    semantic["programs"] = {file.name: _file_hash(file, 8 * MAX_OUTPUT_BYTES)
                            for file in [CHECKER, Path(__file__).resolve(),
                                         *Path(__file__).resolve().parent.glob("reality-target-*.py")]}
    if args.kernel:
        executable = shutil.which(args.kernel_bin)
        if not executable:
            raise DiscoveryError("KERNEL_DEPENDENCY")
        semantic["kernel_binary"] = _file_hash(executable, 256 * MAX_OUTPUT_BYTES)
    return hashlib.sha256(json.dumps(semantic, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def prepare_runtime(args, runtime):
    runtime._resources = []
    hashes = {key: _file_hash(getattr(args, key), 4 * MAX_OUTPUT_BYTES)
              for key in ("known_ips", "seeds") if getattr(args, key)}
    runtime.inputs = _inputs(args)
    if hashes != {key: _file_hash(getattr(args, key), 4 * MAX_OUTPUT_BYTES) for key in hashes}:
        raise DiscoveryError("INPUT_CHANGED")
    if args.kernel:
        module("kernel")
        if not shutil.which(args.kernel_bin):
            raise DiscoveryError("KERNEL_DEPENDENCY")
    runtime.cache = runtime.checkpoint = None
    if args.cache_dir:
        runtime.cache = module("state").Cache(Path(args.cache_dir) / "cache.sqlite", ttl=args.cache_ttl,
                                               entry_limit=8 * MAX_OUTPUT_BYTES)
        runtime._resources.append(runtime.cache)
    if args.checkpoint:
        runtime.checkpoint = module("state").Checkpoint(args.checkpoint, _fingerprint(args, hashes),
                                                         resume=args.resume, ttl=args.state_ttl)
        runtime._resources.append(runtime.checkpoint)


def close_runtime(runtime):
    runtime.close()
    resources = getattr(runtime, "_resources", [])
    runtime._resources = []
    for resource in reversed(resources):
        resource.close()


def error_report(code):
    return {"schema_version": "1.0", "report_type": "discovery", "tool_version": VERSION,
            "error": {"code": code}, "summary": {"status": "UNKNOWN", "exit_code": 2}}


def emit_text(report):
    if report["report_type"] == "discovery_plan":
        print("范围计划: %s | 选定主机: %s | 预算内: %s" %
              (report["summary"]["status"], report["scope"]["host_count"], report["scope"]["within_budget"]))
        if report["asn"]:
            plan = report["asn"]
            print("ASN: %s | 快照: %s | 来源: %s" % (plan["asn"], plan["snapshot_time"], plan["source"]))
            print("Origin ASN: %s | MOAS: %s" % (plan["origin_asns"], plan["moas"]))
            print("IPv4 公告: " + ", ".join(plan["prefixes_v4"]))
            print("IPv6 公告: " + ", ".join(plan["prefixes_v6"]))
            if plan["issues"]:
                print("来源提示: " + ", ".join(plan["issues"]))
        print("选定范围: " + ", ".join(report["scope"]["prefixes"]))
        if report["requires_selection"]:
            print("提供 --include-cidr 或有限 --known-ips/--seeds 清单后执行。")
        print("此报告为范围计划；IPv6 仅处理已知地址，BGP 观测不保证实时独占归属。")
        return
    print("发现状态: %s | 合格候选: %s | 执行完整: %s" %
          (report["summary"]["status"], report["summary"]["eligible_count"], report["scan"]["complete"]))
    print("发现覆盖为 best effort；固定 IP/SNI 可用不代表域名当前 DNS 位于该网段。")
    for candidate in report["candidates"]:
        status = candidate["report"]["summary"]["status"] if candidate["report"] else "UNKNOWN"
        print("%s  %s  %s  eligible=%s  DNS=%s" %
              (candidate["ip"], candidate["sni"], status, candidate["eligible"], candidate["dns_binding"]))
        stats = candidate["statistics"]
        print("  样本: %s/%s 通过 | checker 中位耗时: %s ms | 波动: %s ms" %
              (stats["passed"], stats["planned"], stats["median_ms"], stats["spread_ms"]))
    if report["scan"]["reasons"]:
        print("未完成原因: " + ", ".join(report["scan"]["reasons"]))
    if report["summary"]["exit_code"] == 3:
        print("基础与兼容性通过的候选仍有附加风险或未知项，需审阅 JSON 中的原始报告。")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = parse_args(argv)
    except SystemExit as error:
        if error.code and "--json" in argv:
            print(json.dumps(error_report("USAGE")))
        return error.code
    dependencies = (("curl",) if args.asn or args.asn_from_ip else ()) if args.plan_only else (
        "bash", "openssl", "dig", "jq", "curl", "timeout", "mktemp", "date", "sed", "awk", "grep", "tr", "head", "tail", "rm")
    if ((not args.plan_only and (not CHECKER.is_file() or not Path("/proc/self/stat").is_file()))
            or any(shutil.which(tool) is None for tool in dependencies)):
        print("discover: 缺少检查器或运行依赖，参见 README", file=sys.stderr)
        if args.json:
            print(json.dumps(error_report("DEPENDENCY")))
        return 2
    runtime = Runtime(args.timeout, args.deadline, args.rate)
    def cancel(number, _frame):
        runtime.signal_number = number
        runtime.cancelled.set()
    previous = {number: signal.signal(number, cancel) for number in (signal.SIGINT, signal.SIGTERM)}
    report = None
    try:
        prepare_runtime(args, runtime)
        report = scan(args, runtime)
    except (DiscoveryError, OSError, ValueError) as error:
        code = str(error)
        code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) else "DISCOVERY_INPUT"
        print("discover: " + code, file=sys.stderr)
        report = error_report(code)
    except Exception as error:
        if error.__class__.__name__ != "StateError":
            raise
        print("discover: " + str(error), file=sys.stderr)
        report = error_report(str(error))
    finally:
        close_runtime(runtime)
        for number, handler in previous.items():
            signal.signal(number, handler)
    if runtime.signal_number:
        report["summary"].update(status="UNKNOWN", exit_code=128 + runtime.signal_number)
    if args.json:
        print(json.dumps(report, ensure_ascii=True))
    elif "error" not in report:
        emit_text(report)
    return report["summary"]["exit_code"]


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        print("discover requires Python >= 3.9", file=sys.stderr)
        if "--json" in sys.argv:
            print(json.dumps(error_report("DEPENDENCY")))
        sys.exit(2)
    sys.exit(main())
