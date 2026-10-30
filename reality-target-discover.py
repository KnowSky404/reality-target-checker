#!/usr/bin/env python3
"""Bounded IPv4 HTTPS candidate discovery; final trust checks stay in Bash."""

import argparse
import concurrent.futures
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


VERSION = "0.2.0"
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_NAMES_PER_IP = 16
CHECKER = Path(__file__).resolve().with_name("reality-target-checker.sh")
BASIC = {"tcp443", "tls13", "cert_chain", "cert_san", "cert_validity"}
COMPATIBILITY = {"alpn_h2", "x25519"}
ANCILLARY = {"cert_expiry", "https_response", "http_redirect", "asn", "same_asn", "cdn"}
STATUSES = {"PASS", "WARN", "FAIL", "UNKNOWN"}


class DiscoveryError(Exception):
    """A bounded operation could not produce reliable evidence."""


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
    owner = ipaddress.IPv4Address(ip).reverse_pointer
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
        if endpoint["ip"] != ip or endpoint["family"] != 4:
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
        if checks.get("A") != "PASS":
            return "UNKNOWN"
        return "MATCH" if ip in report["dns"]["a"] else "DIFFERENT"
    except (KeyError, TypeError):
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
                fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
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

    def run(self, args, input_data=None, timeout=None):
        self.check()
        end = min(self.deadline, time.monotonic() + (self.timeout if timeout is None else timeout))
        with tempfile.TemporaryFile() as stdin, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            if input_data:
                stdin.write(input_data)
                stdin.seek(0)
            try:
                process = subprocess.Popen(args, stdin=stdin, stdout=stdout, stderr=stderr,
                                           start_new_session=True)
            except OSError as error:
                raise DiscoveryError("PROCESS_START") from error
            with self._lock:
                self._processes.add(process)
            try:
                while True:
                    self.check()
                    if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > MAX_OUTPUT_BYTES:
                        raise DiscoveryError("OUTPUT_LIMIT")
                    if time.monotonic() >= end:
                        raise DiscoveryError("OPERATION_TIMEOUT")
                    try:
                        process.wait(timeout=min(0.05, end - time.monotonic()))
                        break
                    except subprocess.TimeoutExpired:
                        pass
                if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > MAX_OUTPUT_BYTES:
                    raise DiscoveryError("OUTPUT_LIMIT")
                stdout.seek(0)
                stderr.seek(0)
                return process.returncode, stdout.read(MAX_OUTPUT_BYTES), stderr.read(MAX_OUTPUT_BYTES)
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
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
            # OpenSSL's historical unrecognized_name reason omits "ALERT".
            if "_ALERT_" in reason or reason == "TLSV1_UNRECOGNIZED_NAME":
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
    result = dict(candidate, eligible=False, dns_binding="UNKNOWN", report=None, error=None)
    started = time.monotonic()
    try:
        runtime.acquire()
        command = ["bash", str(CHECKER), "check", candidate["sni"], "--sni", candidate["sni"],
                   "--ip", candidate["ip"], "--ipv4", "--json", "--timeout", str(args.timeout)]
        if args.origin_ip:
            command += ["--origin-ip", args.origin_ip]
        code, output, _ = runtime.run(command, timeout=runtime.remaining())
        report = json.loads(output)
        result["eligible"] = validate_report(report, code, candidate["ip"], candidate["sni"])
        result["report"] = report
        result["dns_binding"] = dns_binding(report, candidate["ip"])
    except (DiscoveryError, ValueError, UnicodeError) as error:
        result["error"] = str(error) if isinstance(error, DiscoveryError) else "CHECKER_REPORT"
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def scan(args, runtime):
    # The bounded input budget also bounds queued futures and retained evidence.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        hosts = list(pool.map(lambda ip: discover_host(str(ip), runtime), args.cidr.hosts()))
    hosts.sort(key=lambda item: int(ipaddress.IPv4Address(item["ip"])))
    seeds = [{"ip": host["ip"], "sni": name, "sources": sources}
             for host in hosts for name, sources in sorted(host["names"].items())]
    reasons = sorted({issue for host in hosts for issue in host["issues"]})
    discovered_count = len(seeds)
    if discovered_count > args.max_candidates:
        reasons.append("CANDIDATE_LIMIT")
        seeds = seeds[:args.max_candidates]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        candidates = list(pool.map(lambda seed: verify_candidate(seed, args, runtime), seeds))
    for candidate in candidates:
        if candidate["error"]:
            reasons.append(candidate["error"])
    if runtime.cancelled.is_set():
        reasons.append("CANCELLED")
    elif runtime.remaining() <= 0:
        reasons.append("DEADLINE")
    reasons = sorted(set(reasons))
    complete = not reasons and all(host["completed"] for host in hosts)
    candidates.sort(key=lambda item: (not item["eligible"], int(ipaddress.IPv4Address(item["ip"])), item["sni"]))
    eligible = [item for item in candidates if item["eligible"]]
    unknown = any(item["error"] or item["report"]["summary"]["status"] == "UNKNOWN" for item in candidates)
    if runtime.signal_number:
        status, code = "UNKNOWN", 128 + runtime.signal_number
    elif not complete or unknown:
        status, code = "UNKNOWN", 2
    elif not eligible:
        status, code = "NO_CANDIDATES", 1
    elif any(item["report"]["summary"]["status"] == "WARN" for item in eligible):
        status, code = "WARN", 3
    else:
        status, code = "PASS", 0
    return {"schema_version": "1.0", "report_type": "discovery", "tool_version": VERSION,
            "scope": {"cidr": str(args.cidr), "host_count": host_count(args.cidr),
                      "origin_ip": args.origin_ip,
                      "limits": {key: getattr(args, key) for key in
                                 ("max_hosts", "concurrency", "rate", "timeout", "deadline", "max_candidates")}},
            "scan": {"complete": complete, "coverage": "best_effort", "hosts_completed": sum(host["completed"] for host in hosts),
                     "candidates_discovered": discovered_count, "candidates_checked": sum(item["report"] is not None for item in candidates),
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
    parser = argparse.ArgumentParser(description="指定 IPv4 网段的 REALITY 候选发现（best effort，固定 IP/SNI 复核）")
    parser.add_argument("cidr", help="严格对齐的 IPv4 CIDR，不自动扩大范围")
    parser.add_argument("--json", action="store_true", help="仅向 stdout 输出独立 discovery JSON")
    parser.add_argument("--origin-ip", help="用户确认的 IPv4 公网源 IP，仅用于 ASN 比较")
    for name, default, low, high, description in (
            ("max-hosts", 256, 1, 4096, "主机预算，超出则在网络操作前拒绝"),
            ("concurrency", 8, 1, 32, "并发任务上限"),
            ("rate", 10, 1, 100, "每秒启动发现/复核任务数，非内部请求数"),
            ("timeout", 3, 1, 60, "单次网络操作超时秒数"),
            ("deadline", 300, 1, 3600, "整次任务时间预算秒数"),
            ("max-candidates", 256, 1, 4096, "全局候选 IP/SNI 对预算")):
        parser.add_argument("--" + name, type=_integer(low, high), default=default,
                            help=description + "（默认 %(default)s）")
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r"[0-9.]+/(?:0|[1-9][0-9]?)", args.cidr):
            raise ValueError
        network = ipaddress.IPv4Network(args.cidr, strict=True)
        if str(network) != args.cidr:
            raise ValueError
        args.cidr = network
        if args.origin_ip is not None:
            origin = str(ipaddress.IPv4Address(args.origin_ip))
            if origin != args.origin_ip:
                raise ValueError
            args.origin_ip = origin
    except ValueError:
        parser.error("需要严格对齐的 IPv4 CIDR 和有效 IPv4 --origin-ip")
    if host_count(args.cidr) > args.max_hosts:
        parser.error("网段主机数超过 --max-hosts，未开始扫描")
    return args


def error_report(code):
    return {"schema_version": "1.0", "report_type": "discovery", "tool_version": VERSION,
            "error": {"code": code}, "summary": {"status": "UNKNOWN", "exit_code": 2}}


def emit_text(report):
    print("发现状态: %s | 合格候选: %s | 执行完整: %s" %
          (report["summary"]["status"], report["summary"]["eligible_count"], report["scan"]["complete"]))
    print("发现覆盖为 best effort；固定 IP/SNI 可用不代表域名当前 DNS 位于该网段。")
    for candidate in report["candidates"]:
        status = candidate["report"]["summary"]["status"] if candidate["report"] else "UNKNOWN"
        print("%s  %s  %s  eligible=%s  DNS=%s" %
              (candidate["ip"], candidate["sni"], status, candidate["eligible"], candidate["dns_binding"]))
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
    dependencies = ("bash", "openssl", "dig", "jq", "curl", "timeout", "mktemp", "date",
                    "sed", "awk", "grep", "tr", "head", "tail", "rm")
    if (not CHECKER.is_file() or not Path("/proc/self/stat").is_file()
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
    try:
        report = scan(args, runtime)
        if args.json:
            print(json.dumps(report, ensure_ascii=True))
        else:
            emit_text(report)
        return report["summary"]["exit_code"]
    finally:
        runtime.close()
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        print("discover requires Python >= 3.9", file=sys.stderr)
        if "--json" in sys.argv:
            print(json.dumps(error_report("DEPENDENCY")))
        sys.exit(2)
    sys.exit(main())
