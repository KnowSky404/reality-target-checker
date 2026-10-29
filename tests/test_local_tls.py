"""Real OpenSSL against ephemeral local TLS servers; no Internet or root needed."""

import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROBE = r'''
source "$1"
network_timeout=1
workdir=$2
sni=example.test
declare -A statuses=() reasons=()
declare -a cert_before=() cert_after=()
for key in tls13 alpn_h2 x25519 cert_chain cert_san cert_validity cert_expiry; do
  set_check 0 "$key" UNKNOWN 'unverified'
done
ssl_help=$(openssl s_client -help 2>&1)
check_tls 0 "127.0.0.1:$3"
for key in tls13 alpn_h2 x25519 cert_chain cert_san cert_validity; do
  printf '%s %s\n' "$key" "${statuses[0:$key]}"
done
'''


class LocalTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="rtc-local-tls-")
        cls.directory = Path(cls.temp.name)
        cls.cert = cls.directory / "cert.pem"
        cls.key = cls.directory / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(cls.key),
             "-out", str(cls.cert), "-subj", "/CN=wrong-cn.test", "-addext",
             "subjectAltName=DNS:example.test", "-days", "2"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def probe(self, *, h2=True, tls12=False, curve=None, hang=False, trusted=True, mtls=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        context.set_alpn_protocols(["h2"] if h2 else ["http/1.1"])
        if mtls:
            context.load_verify_locations(self.cert)
            context.verify_mode = ssl.CERT_REQUIRED
        if tls12:
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        if curve:
            context.set_ecdh_curve(curve)
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
                    conn.settimeout(2)
                    if hang:
                        stop.wait(2)
                        continue
                    try:
                        with context.wrap_socket(conn, server_side=True) as tls:
                            tls.recv(1)
                    except (ssl.SSLError, OSError):
                        pass  # Expected for protocol/group refusal and EOF.

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        env = dict(os.environ)
        # Explicitly trust our ephemeral local certificate, not a global CA change.
        if trusted:
            env["SSL_CERT_FILE"] = str(self.cert)
        else:
            env.pop("SSL_CERT_FILE", None)
            env.pop("SSL_CERT_DIR", None)
        try:
            started = time.monotonic()
            result = subprocess.run(
                ["bash", "-c", PROBE, "_", str(ROOT / "reality-target-checker.sh"),
                 str(self.directory), str(port)],
                env=env, capture_output=True, text=True, timeout=6, check=True,
            )
            self.assertEqual(result.stderr, "")
            states = dict(line.split() for line in result.stdout.splitlines())
            return states, time.monotonic() - started, server_names
        finally:
            stop.set()
            listener.close()
            thread.join(timeout=3)

    def test_real_tls13_h2_x25519_and_certificate(self):
        states, _, names = self.probe()
        self.assertTrue(all(value == "PASS" for value in states.values()), states)
        self.assertEqual(names, ["example.test"])

    def test_http1_alpn_is_not_h2(self):
        states, _, _ = self.probe(h2=False)
        self.assertEqual(states["tls13"], "PASS")
        self.assertEqual(states["alpn_h2"], "FAIL")

    def test_tls12_only_is_rejected(self):
        states, _, _ = self.probe(tls12=True)
        self.assertEqual(states["tls13"], "FAIL")

    def test_real_x25519_refusal(self):
        states, _, _ = self.probe(curve="prime256v1")
        self.assertEqual(states["tls13"], "PASS")
        self.assertEqual(states["x25519"], "FAIL")

    def test_untrusted_chain_is_not_conflated_with_tls_support(self):
        states, _, _ = self.probe(trusted=False)
        self.assertEqual(states["tls13"], "PASS")
        self.assertEqual(states["cert_chain"], "FAIL")
        self.assertEqual(states["cert_san"], "PASS")

    def test_real_timeout_is_bounded_and_unknown(self):
        states, elapsed, _ = self.probe(hang=True)
        self.assertEqual(states["tls13"], "UNKNOWN")
        self.assertLess(elapsed, 3)

    def test_client_certificate_required_cannot_pass_as_completed_handshake(self):
        states, _, _ = self.probe(mtls=True)
        self.assertNotEqual(states["tls13"], "PASS")

    def test_ipv6_validation_matches_standard_library(self):
        import ipaddress

        valid = ["::", "::1", "2001:db8::10", "1:2:3:4:5:6:7:8",
                 "::ffff:192.0.2.1", "2001:DB8:0:0:1:0:0:1"]
        invalid = ["1:::2", "1:2:3", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:",
                   "1:2:3:4:5:6:7:8::", "1::2::3", "12345::", "::ffff:999.0.0.1"]
        command = 'source "$1"; normalize_ip "$2" || exit 2; printf "%s" "$IP_NORMALIZED"'
        for ip in valid + invalid:
            result = subprocess.run(["bash", "-c", command, "_", str(ROOT / "reality-target-checker.sh"), ip],
                                    capture_output=True, text=True)
            if ip in valid:
                self.assertEqual(result.returncode, 0, ip)
                self.assertEqual(ipaddress.ip_address(result.stdout), ipaddress.ip_address(ip))
                self.assertEqual(len(result.stdout.split(":")), 8)
            else:
                self.assertEqual(result.returncode, 2, ip)


if __name__ == "__main__":
    unittest.main()
