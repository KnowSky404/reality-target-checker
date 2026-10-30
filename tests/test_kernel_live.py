"""Opt-in real Xray test; only loopback traffic, no download or public target."""

import importlib.util
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


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("rtc_live_discovery", ROOT / "reality-target-discover.py")
core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core)


@unittest.skipUnless(os.environ.get("RTC_XRAY_BIN"), "set RTC_XRAY_BIN to an installed Xray for local authenticated testing")
class RealXray(unittest.TestCase):
    def test_authenticated_reality_and_https_with_ephemeral_local_keys(self):
        address = "127.0.0.222"
        listener = socket.socket()
        try:
            listener.bind((address, 0))
        except OSError as error:
            listener.close()
            self.skipTest("local fixture port unavailable: " + str(error.errno))
        listener.listen()
        listener.settimeout(0.1)
        port = listener.getsockname()[1]
        stop, lock = threading.Event(), threading.Lock()
        connections, workers, heads, stages = set(), [], [], []
        with tempfile.TemporaryDirectory(prefix="rtc-xray-live-") as folder:
            cert, key = Path(folder) / "ca.pem", Path(folder) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=rtc-kernel.test",
                            "-addext", "subjectAltName=DNS:rtc-kernel.test", "-days", "2"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(["h2", "http/1.1"])
            context.load_cert_chain(cert, key)

            def handle(connection):
                tls = None
                try:
                    tls = context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
                    tls.settimeout(2)
                    with lock:
                        connections.add(tls)
                    tls.do_handshake()
                    data = b""
                    while b"\r\n\r\n" not in data and len(data) < 65536:
                        part = tls.recv(4096)
                        if not part:
                            return
                        data += part
                    if data.startswith(b"HEAD "):
                        heads.append(True)
                        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
                finally:
                    if tls is not None:
                        with lock:
                            connections.discard(tls)
                        tls.close()
                    connection.close()

            def serve():
                while not stop.is_set():
                    try:
                        connection, _ = listener.accept()
                    except TimeoutError:
                        continue
                    except OSError:
                        return
                    worker = threading.Thread(target=handle, args=(connection,), daemon=True)
                    workers.append(worker)
                    worker.start()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            runtime = core.Runtime(timeout=5, deadline=30, rate=100)
            kernel = core.module("kernel")
            configs, run = kernel._configs, runtime.run
            reject_client = False

            def fixture_configs(*arguments):
                # The production API stays on 443. This test-only adapter makes
                # the same authenticated transport usable without a privileged port.
                server, client = configs(*arguments)
                target = address + ":" + str(port)
                server["inbounds"][0]["streamSettings"]["realitySettings"].update(target=target, dest=target)
                for config in (server, client):
                    config["routing"]["rules"][0]["port"] = str(port)
                # Recent Xray versions block VLESS forwarding to private IPs
                # inside freedom, after normal routing. Only this local fixture
                # needs an exact address/port exception; production keeps that
                # kernel protection and its fixed 443 destination unchanged.
                server["outbounds"][1]["settings"]["finalRules"] = [{
                    "action": "allow", "network": "tcp", "ip": [address + "/32"], "port": str(port),
                }]
                if reject_client:
                    client["outbounds"][1]["settings"]["vnext"][0]["users"][0]["id"] = (
                        "00000000-0000-4000-8000-000000000000")
                return server, client

            def fixture_run(command, *arguments, **options):
                label = "curl" if command[0] == "curl" else " ".join(command[1:3])
                started = time.monotonic()
                if command[0] == "curl":
                    command = list(command)
                    index = command.index("--resolve") + 1
                    command[index] = command[index].replace(":443:", ":" + str(port) + ":")
                    command[-1] = "https://rtc-kernel.test:" + str(port) + "/"
                try:
                    return run(command, *arguments, **options)
                finally:
                    stages.append((label, round(time.monotonic() - started, 2)))
            try:
                with mock.patch.dict(os.environ, {"CURL_CA_BUNDLE": str(cert)}), \
                        mock.patch.object(kernel, "_configs", side_effect=fixture_configs), \
                        mock.patch.object(runtime, "run", side_effect=fixture_run):
                    result = kernel.verify(address, "rtc-kernel.test", runtime, os.environ["RTC_XRAY_BIN"])
                    self.assertEqual(result["status"], "PASS", (result.get("error"), stages, len(heads)))
                    self.assertEqual(result["http_status"], 200)
                    self.assertTrue(heads, "authenticated tunnel did not reach the pinned HTTPS fixture")
                    completed_heads = len(heads)
                    reject_client = True
                    runtime.timeout = 1
                    rejected = kernel.verify(address, "rtc-kernel.test", runtime, os.environ["RTC_XRAY_BIN"])
                    self.assertEqual(rejected["status"], "UNKNOWN")
                    self.assertIn(rejected["error"], {"KERNEL_HTTP", "OPERATION_TIMEOUT"})
                    self.assertEqual(len(heads), completed_heads, "invalid VLESS identity reached HTTPS")
                self.assertEqual(runtime._processes, set())
            finally:
                runtime.close()
                stop.set()
                listener.close()
                thread.join(timeout=1)
                with lock:
                    active = list(connections)
                for connection in active:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                for worker in workers:
                    worker.join(timeout=3)
                self.assertFalse(any(worker.is_alive() for worker in workers))
