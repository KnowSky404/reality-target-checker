"""Offline integration tests for the optional kernel runner, using a fake Xray.

These tests exercise generated configuration, real subprocess lifetimes, and
the local control sockets. They do not assert that a mock is a real REALITY
implementation, and never download or contact a public endpoint.
"""

import base64
import concurrent.futures
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


kernel = load_module("kernel_test_runner", "reality-target-kernel.py")
discovery = load_module("kernel_test_discovery", "reality-target-discover.py")
PRIVATE = base64.urlsafe_b64encode(b"p" * 32).decode().rstrip("=")
PUBLIC = base64.urlsafe_b64encode(b"k" * 32).decode().rstrip("=")


FAKE_XRAY = r'''#!/usr/bin/env python3
import base64, json, os, signal, socket, subprocess, sys, time
from pathlib import Path

def record(value):
    with open(os.environ["FAKE_LOG"], "a") as output:
        output.write(json.dumps(value) + "\n")

assert not any(key.upper().startswith(("XRAY_", "V2RAY_", "XRAY.", "V2RAY.")) for key in os.environ)
assert "SSLKEYLOGFILE" not in os.environ
mode = os.environ.get("FAKE_XRAY_MODE", "")
if sys.argv[1:] == ["version"]:
    record({"event": "version", "time": time.monotonic()})
    print("Xray 26.10.29 (offline fake for runner tests)")
    sys.exit(0)
if sys.argv[1:] == ["x25519"]:
    if mode == "bad_keys":
        print("PrivateKey: invalid\nPassword (PublicKey): secret-malformed")
        sys.exit(0)
    private = base64.urlsafe_b64encode(b"p" * 32).decode().rstrip("=")
    public = base64.urlsafe_b64encode(b"k" * 32).decode().rstrip("=")
    print("PrivateKey: " + private)
    print("Password (PublicKey): " + public)
    print("Hash32: " + public)
    sys.exit(0)
assert sys.argv[1] == "run"
path = Path(sys.argv[sys.argv.index("-config") + 1])
empty = Path(sys.argv[sys.argv.index("-confdir") + 1])
assert empty.is_dir() and not list(empty.iterdir())
assert path.parent.stat().st_mode & 0o777 == 0o700
assert path.stat().st_mode & 0o777 == 0o600
config = json.loads(path.read_text())
entry = config["inbounds"][0]
assert entry["listen"] == "127.0.0.1"
record({"event": "config", "test": "-test" in sys.argv, "config": config,
        "path": str(path), "pid": os.getpid(), "time": time.monotonic()})
if "-test" in sys.argv:
    sys.exit(23 if mode == "config_error" else 0)
if mode == "exit":
    sys.exit(23)
listener = socket.socket()
listener.bind((entry["listen"], entry["port"]))
listener.listen()
listener.settimeout(0.05)
child = None
if mode == "descendant" and entry["protocol"] == "socks":
    ready = str(Path(os.environ["FAKE_LOG"]).with_suffix(".child-ready"))
    child = subprocess.Popen([sys.executable, "-c", "import os,signal,sys,time; from pathlib import Path; os.setpgrp(); signal.signal(signal.SIGTERM,signal.SIG_IGN); Path(sys.argv[1]).write_text('ready'); time.sleep(30)", ready])
    until = time.monotonic() + 1
    while not Path(ready).exists() and time.monotonic() < until:
        time.sleep(0.01)
    assert Path(ready).exists()
    record({"event": "descendant", "pid": child.pid})
def stop(number, frame):
    record({"event": "stop", "pid": os.getpid(), "time": time.monotonic()})
    listener.close()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
started = time.monotonic()
while True:
    if mode == "exit_midrequest" and time.monotonic() - started > 0.15:
        sys.exit(23)
    try:
        conn, _ = listener.accept()
    except socket.timeout:
        continue
    with conn:
        try:
            conn.sendall(b"runner-fixture")
        except OSError:
            pass
'''


FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, re, socket, sys, time
args = sys.argv[1:]
data = sys.stdin.read()
with open(os.environ["FAKE_LOG"], "a") as output:
    output.write(json.dumps({"event":"curl", "args":args, "stdin":data, "time":time.monotonic()}) + "\n")
assert args[0] == "--disable"
assert args[args.index("--config") + 1] == "-"
assert re.fullmatch(r'proxy-user = "[0-9a-f]+:[0-9a-f]+"\n', data)
assert args[args.index("--noproxy") + 1] == ""
proxy = args[args.index("--proxy") + 1]
assert proxy.startswith("socks5://127.0.0.1:")
with socket.create_connection(("127.0.0.1", int(proxy.rsplit(":",1)[1])), timeout=1) as control:
    assert control.recv(100) == b"runner-fixture"
time.sleep(float(os.environ.get("FAKE_CURL_DELAY", "0")))
if os.environ.get("FAKE_CURL_ERROR"):
    print("SENSITIVE-KERNEL-LOG", file=sys.stderr)
    sys.exit(28)
print(os.environ.get("FAKE_HTTP_STATUS", "204"), end="")
'''


def process_alive(pid):
    path = Path("/proc") / str(pid) / "stat"
    try:
        return path.read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


class KeysAndConfiguration(unittest.TestCase):
    def test_current_and_legacy_key_formats(self):
        for output in (
                f"PrivateKey: {PRIVATE}\nPassword (PublicKey): {PUBLIC}\nHash32: {PUBLIC}\n",
                f"Private key: {PRIVATE}\nPublic key: {PUBLIC}\n",
                f"PrivateKey: {PRIVATE}\nPassword: {PUBLIC}\n"):
            with self.subTest(output=output):
                self.assertEqual(kernel.parse_keys(output.encode()), (PRIVATE, PUBLIC))

    def test_malformed_duplicate_and_noncanonical_keys_are_rejected(self):
        for output in (b"", b"PrivateKey: invalid\nPassword: invalid\n",
                       f"PrivateKey: {PRIVATE}\nPublic key: {PUBLIC}\nPassword: {PRIVATE}\n".encode(),
                       f"PrivateKey: {PRIVATE}\nPublic key: {PUBLIC[:-1]}B\n".encode()):
            with self.subTest(output=output), self.assertRaises((kernel.KernelError, UnicodeError)):
                kernel.parse_keys(output)

    def test_configuration_allows_only_pinned_ip_port_and_loopback_controls(self):
        for ip in ("192.0.2.10", "2001:db8::10"):
            address = ipaddress.ip_address(ip)
            server, client = kernel._configs(address, "example.test", 42001, 42002,
                                             PRIVATE, PUBLIC, "test-user-id", "abcd", "local-user", "local-pass")
            with self.subTest(ip=ip):
                for config in (server, client):
                    self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
                    self.assertEqual(config["outbounds"][0]["protocol"], "blackhole")
                    rule = config["routing"]["rules"][0]
                    self.assertEqual(rule["ip"], [ip + ("/32" if address.version == 4 else "/128")])
                    self.assertEqual((rule["port"], rule["network"]), ("443", "tcp"))
                reality = server["inbounds"][0]["streamSettings"]["realitySettings"]
                self.assertEqual(reality["target"], reality["dest"])
                self.assertEqual(reality["target"], ("[" + ip + "]" if address.version == 6 else ip) + ":443")
                self.assertEqual(reality["serverNames"], ["example.test"])
                outbound = client["outbounds"][1]
                self.assertEqual(outbound["settings"]["vnext"][0]["address"], "127.0.0.1")
                settings = outbound["streamSettings"]["realitySettings"]
                self.assertEqual(settings["password"], settings["publicKey"])
                self.assertEqual(settings["fingerprint"], "chrome")
                self.assertEqual(client["inbounds"][0]["settings"]["auth"], "password")


class KernelRunner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rtc-kernel-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin with spaces"
        self.bin.mkdir()
        self.binary = self.bin / "xray"
        self.binary.write_text(FAKE_XRAY)
        self.binary.chmod(0o755)
        (self.bin / "curl").write_text(FAKE_CURL)
        (self.bin / "curl").chmod(0o755)
        self.log = self.root / "calls.jsonl"
        self.environ = mock.patch.dict(os.environ, {
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"], "FAKE_LOG": str(self.log),
            "FAKE_XRAY_MODE": "", "FAKE_CURL_DELAY": "0", "FAKE_CURL_ERROR": "", "FAKE_HTTP_STATUS": "204",
            "XRAY_LOCATION_CONFDIR": str(self.root / "private-configs"),
            "V2RAY_LOCATION_CONFIG": str(self.root / "private-config.json"),
            "SSLKEYLOGFILE": str(self.root / "keylog-must-not-exist"),
        })
        self.environ.start()
        self.addCleanup(self.environ.stop)
        self.runtime = discovery.Runtime(timeout=1, deadline=6, rate=100)
        self.addCleanup(self.runtime.close)

    def records(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def assert_cleaned(self):
        records = self.records()
        pids = {item["pid"] for item in records if "pid" in item}
        until = time.monotonic() + 0.6
        while any(process_alive(pid) for pid in pids) and time.monotonic() < until:
            time.sleep(0.01)
        self.assertFalse([pid for pid in pids if process_alive(pid)], "kernel process survived cleanup")
        self.assertEqual(self.runtime._processes, set())
        for item in records:
            if "path" in item:
                self.assertFalse(Path(item["path"]).parent.exists(), "temporary kernel credentials survived cleanup")

    def trigger_during_request(self, action):
        stopped, triggered = threading.Event(), threading.Event()
        timestamps = []
        def watch():
            until = time.monotonic() + 5
            while not stopped.is_set() and time.monotonic() < until:
                try:
                    ready = any(item["event"] == "curl" for item in self.records())
                except json.JSONDecodeError:
                    ready = False
                if ready:
                    time.sleep(0.08)
                    timestamps.append(time.monotonic())
                    action()
                    triggered.set()
                    return
                stopped.wait(0.01)
        thread = threading.Thread(target=watch, daemon=True)
        thread.start()
        self.addCleanup(stopped.set)
        self.addCleanup(thread.join, 0.5)
        return triggered, timestamps

    def test_fake_kernel_exercises_ephemeral_configuration_and_proxy_request(self):
        result = kernel.verify("192.0.2.10", "example.test", self.runtime, self.binary)
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["kernel_version"], "26.10.29")
        self.assertEqual(result["http_status"], 204)
        configs = [item for item in self.records() if item["event"] == "config"]
        self.assertEqual(len(configs), 4)
        self.assertEqual(sum(item["test"] for item in configs), 2)
        server, client = (next(item["config"] for item in configs if item["path"].endswith(name))
                          for name in ("server.json", "client.json"))
        identity = server["inbounds"][0]["settings"]["clients"][0]["id"]
        self.assertEqual(identity, client["outbounds"][1]["settings"]["vnext"][0]["users"][0]["id"])
        curl = next(item for item in self.records() if item["event"] == "curl")
        args = curl["args"]
        self.assertEqual(args[args.index("--resolve") + 1], "example.test:443:192.0.2.10")
        self.assertEqual(args[-1], "https://example.test/")
        for option in ("--http1.1", "--head", "--socks5-basic"):
            self.assertIn(option, args)
        for option in ("--insecure", "-k", "--location", "-L", "--proxy-user"):
            self.assertNotIn(option, args)
        output = json.dumps(result)
        self.assertNotIn(identity, output)
        self.assertNotIn(PRIVATE, output)
        self.assertNotIn(PUBLIC, output)
        self.assertNotIn("SENSITIVE-KERNEL-LOG", output)
        self.assert_cleaned()

    def test_ipv6_destination_stays_literal_and_bracketed(self):
        result = kernel.verify("2001:db8::10", "example.test", self.runtime, self.binary)
        self.assertEqual(result["status"], "PASS", result)
        curl = next(item for item in self.records() if item["event"] == "curl")
        self.assertEqual(curl["args"][curl["args"].index("--resolve") + 1], "example.test:443:[2001:db8::10]")
        self.assert_cleaned()

    def test_valid_http_error_response_is_still_end_to_end_evidence(self):
        with mock.patch.dict(os.environ, {"FAKE_HTTP_STATUS": "403"}):
            result = kernel.verify("192.0.2.10", "example.test", self.runtime, self.binary)
        self.assertEqual((result["status"], result["http_status"]), ("PASS", 403))
        self.assert_cleaned()

    def test_missing_kernel_and_invalid_target_do_not_start_processes(self):
        result = kernel.verify("192.0.2.10", "example.test", self.runtime, "/no/such/xray")
        self.assertEqual(result["error"], "KERNEL_DEPENDENCY")
        for ip, sni in (("bad-ip", "example.test"), ("192.0.02.10", "example.test"),
                        ("fe80::1%eth0", "example.test"), ("192.0.2.10", "0x7f000001"),
                        ("192.0.2.10", "*.example.test"), ("192.0.2.10", "bad\x1b.test")):
            with self.subTest(ip=ip, sni=sni):
                result = kernel.verify(ip, sni, self.runtime, self.binary)
                self.assertEqual(result["error"], "KERNEL_TARGET")
        self.assertEqual(self.records(), [])

    def test_bad_keys_and_unsupported_configuration_are_unknown(self):
        for mode, error in (("bad_keys", "KERNEL_KEYS"), ("config_error", "KERNEL_CONFIG")):
            with self.subTest(mode=mode), mock.patch.dict(os.environ, {"FAKE_XRAY_MODE": mode}):
                result = kernel.verify("192.0.2.10", "example.test", self.runtime, self.binary)
                self.assertEqual((result["status"], result["error"]), ("UNKNOWN", error))
                self.assertNotIn("secret-malformed", json.dumps(result))
        self.assert_cleaned()

    def test_early_exit_and_network_failure_are_unknown(self):
        with mock.patch.dict(os.environ, {"FAKE_XRAY_MODE": "exit"}):
            result = kernel.verify("192.0.2.10", "example.test", self.runtime, self.binary)
        self.assertEqual((result["status"], result["error"]), ("UNKNOWN", "KERNEL_EXITED"))
        with mock.patch.dict(os.environ, {"FAKE_CURL_ERROR": "1"}):
            result = kernel.verify("192.0.2.10", "example.test", self.runtime, self.binary)
        self.assertEqual((result["status"], result["error"]), ("UNKNOWN", "KERNEL_HTTP"))
        self.assert_cleaned()

    def test_process_exit_during_request_cannot_pass(self):
        with mock.patch.dict(os.environ, {"FAKE_XRAY_MODE": "exit_midrequest", "FAKE_CURL_DELAY": "0.4"}):
            result = kernel.verify("192.0.2.10", "example.test", self.runtime, self.binary)
        self.assertEqual((result["status"], result["error"]), ("UNKNOWN", "KERNEL_EXITED"))
        self.assert_cleaned()

    def test_deadline_reaps_kernels_curl_and_separate_descendant_group(self):
        triggered, timestamps = self.trigger_during_request(
            lambda: setattr(self.runtime, "deadline", time.monotonic() + 0.1))
        with mock.patch.dict(os.environ, {"FAKE_XRAY_MODE": "descendant", "FAKE_CURL_DELAY": "30"}):
            result = kernel.verify("192.0.2.10", "example.test", self.runtime, self.binary)
        self.assertTrue(triggered.is_set(), "test did not reach the active request")
        self.assertTrue(any(item["event"] == "descendant" for item in self.records()))
        self.assertEqual(result["status"], "UNKNOWN", result)
        self.assertIn(result["error"], {"DEADLINE", "OPERATION_TIMEOUT"})
        self.assertLess(time.monotonic() - timestamps[0], 1.5)
        self.assert_cleaned()

    def test_running_request_is_cancellable_and_preserves_no_credentials(self):
        triggered, timestamps = self.trigger_during_request(self.runtime.cancelled.set)
        with mock.patch.dict(os.environ, {"FAKE_CURL_DELAY": "30"}):
            result = kernel.verify("192.0.2.10", "example.test", self.runtime, self.binary)
        self.assertTrue(triggered.is_set(), "test did not reach the active request")
        self.assertEqual((result["status"], result["error"]), ("UNKNOWN", "CANCELLED"))
        self.assertLess(time.monotonic() - timestamps[0], 1)
        self.assert_cleaned()

    def test_waiting_for_kernel_slot_is_cancellable(self):
        kernel._SLOTS.acquire()
        timer = threading.Timer(0.08, self.runtime.cancelled.set)
        timer.start()
        try:
            started = time.monotonic()
            result = kernel.verify("192.0.2.10", "example.test", self.runtime, self.binary)
            self.assertEqual((result["status"], result["error"]), ("UNKNOWN", "CANCELLED"))
            self.assertEqual(result["elapsed_ms"], 0)
            self.assertLess(time.monotonic() - started, 0.4)
            self.assertEqual(self.records(), [])
        finally:
            timer.cancel()
            kernel._SLOTS.release()

    def test_only_one_kernel_pair_runs_at_a_time(self):
        with mock.patch.dict(os.environ, {"FAKE_CURL_DELAY": "0.1"}):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: kernel.verify("192.0.2.10", "example.test", self.runtime, self.binary), range(2)))
        self.assertTrue(all(result["status"] == "PASS" for result in results), results)
        records = self.records()
        versions = [item["time"] for item in records if item["event"] == "version"]
        stops = [item["time"] for item in records if item["event"] == "stop"]
        self.assertEqual(len(versions), 2)
        self.assertLess(max(stops[:2]), versions[1])
        self.assert_cleaned()


if __name__ == "__main__":
    unittest.main()
