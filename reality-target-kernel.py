#!/usr/bin/env python3
"""Optional Xray REALITY authentication and HTTPS proxy-path verification.

Every configuration and credential belongs to this short-lived self-test. The
provided kernel executable is trusted; existing proxy configurations are never
loaded. Network egress is restricted to the selected IP:443 by both configurations.
"""

import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid


_SLOTS = threading.Semaphore(1)
_RUNTIME_ERRORS = {"CANCELLED", "DEADLINE", "OPERATION_TIMEOUT", "OUTPUT_LIMIT", "PROCESS_START"}


class KernelError(Exception):
    """A self-test has no reliable end-to-end success evidence."""


def _target(ip, sni):
    if not isinstance(ip, str) or "%" in ip:
        raise KernelError("KERNEL_TARGET")
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as error:
        raise KernelError("KERNEL_TARGET") from error
    if address.version == 4 and str(address) != ip:
        raise KernelError("KERNEL_TARGET")
    if not isinstance(sni, str) or not sni.isascii():
        raise KernelError("KERNEL_TARGET")
    name = sni.removesuffix(".").lower()
    if (not 1 <= len(name) <= 253 or re.fullmatch(r"[0-9.]+", name)
            or re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}", name)
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                   for label in name.split("."))):
        raise KernelError("KERNEL_TARGET")
    return address, name


def _key(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise KernelError("KERNEL_KEYS")
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except ValueError as error:
        raise KernelError("KERNEL_KEYS") from error
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise KernelError("KERNEL_KEYS")
    return value


def parse_keys(output):
    """Accept current PrivateKey/Password and the earlier Public key labels."""
    private, public = set(), set()
    for line in output.decode("ascii", "strict").splitlines():
        match = re.fullmatch(r"\s*([^:]+):\s*([A-Za-z0-9_-]+)\s*", line)
        if not match:
            continue
        label = re.sub(r"\s+", "", match[1]).lower()
        if label == "privatekey":
            private.add(_key(match[2]))
        elif label in {"publickey", "password", "password(publickey)"}:
            public.add(_key(match[2]))
    if len(private) != 1 or len(public) != 1:
        raise KernelError("KERNEL_KEYS")
    return private.pop(), public.pop()


def _environment():
    # Xray may merge its inherited confdir even alongside an explicit -config.
    # Only filter kernel-specific configuration; retain CA and network settings.
    return {key: value for key, value in os.environ.items()
            if key.upper() != "SSLKEYLOGFILE"
            and not key.upper().startswith(("XRAY_", "V2RAY_", "XRAY.", "V2RAY."))}


def _configs(address, sni, server_port, socks_port, private, public, identity, short_id, user, password):
    ip = str(address)
    target = ("[" + ip + "]" if address.version == 6 else ip) + ":443"
    prefix = ip + ("/128" if address.version == 6 else "/32")

    def routing(tag):
        return {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "network": "tcp", "ip": [prefix], "port": "443", "outboundTag": tag},
            {"type": "field", "network": "tcp,udp", "outboundTag": "blocked"},
        ]}

    log = {"access": "none", "error": "none", "loglevel": "none"}
    blocked = {"tag": "blocked", "protocol": "blackhole", "settings": {}}
    server = {
        "log": log,
        "inbounds": [{"listen": "127.0.0.1", "port": server_port, "protocol": "vless", "settings": {
            "clients": [{"id": identity, "flow": "xtls-rprx-vision"}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "show": False, "target": target, "dest": target, "xver": 0, "serverNames": [sni],
                "privateKey": private, "shortIds": [short_id]}}}],
        "outbounds": [blocked, {"tag": "target", "protocol": "freedom", "settings": {"domainStrategy": "AsIs"}}],
        "routing": routing("target"),
    }
    client = {
        "log": log,
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {
            "auth": "password", "accounts": [{"user": user, "pass": password}], "udp": False}}],
        "outbounds": [blocked, {"tag": "reality", "protocol": "vless", "settings": {
            "vnext": [{"address": "127.0.0.1", "port": server_port, "users": [
                {"id": identity, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "show": False, "serverName": sni, "fingerprint": "chrome", "password": public,
                "publicKey": public, "shortId": short_id, "spiderX": "/"}}}],
        "routing": routing("reality"),
    }
    return server, client


def _write_config(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(content, output)


def _reserve_ports():
    reservations = []
    try:
        for _ in range(2):
            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reservations.append(reservation)
            reservation.bind(("127.0.0.1", 0))
        return reservations, [sock.getsockname()[1] for sock in reservations]
    except BaseException:
        for reservation in reservations:
            reservation.close()
        raise


def _start(runtime, command, directory, environment):
    runtime.check()
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True,
                                   cwd=directory, env=environment)
    except OSError as error:
        raise KernelError("KERNEL_START") from error
    with runtime._lock:
        runtime._processes.add(process)
    return process


def _stop(runtime, process):
    try:
        runtime._terminate(process)
    finally:
        if process.poll() is not None:
            with runtime._lock:
                runtime._processes.discard(process)


def _check_alive(processes):
    if any(process.poll() is not None for process in processes):
        raise KernelError("KERNEL_EXITED")


def _wait_ready(runtime, process, port):
    end = min(runtime.deadline, time.monotonic() + runtime.timeout)
    while True:
        runtime.check()
        _check_alive([process])
        if time.monotonic() >= end:
            raise KernelError("KERNEL_START_TIMEOUT")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=min(0.05, runtime.remaining())):
                return
        except (ConnectionRefusedError, TimeoutError):
            runtime.cancelled.wait(min(0.02, runtime.remaining()))


def _run(runtime, command, environment, input_data=None):
    return runtime.run(command, input_data=input_data, timeout=runtime.operation_timeout(), env=environment)


def verify(ip, sni, runtime, binary="xray"):
    """Use an ephemeral local Xray server/client pair and a verified HTTPS HEAD.

    PASS is authenticated VLESS+REALITY transport plus HTTPS response evidence.
    Unavailable binaries, incompatible capabilities, or network failures remain
    UNKNOWN. Test credentials and process output are never included in results.
    """
    result = {"status": "UNKNOWN", "error": None, "elapsed_ms": 0,
              "kernel": "xray", "kernel_version": None}
    locked = False
    started = None
    processes = []
    reservations = []
    directory = None
    try:
        address, sni = _target(ip, sni)
        executable = shutil.which(os.fspath(binary))
        if executable is None:
            raise KernelError("KERNEL_DEPENDENCY")
        executable = str(Path(executable).resolve())
        while not locked:
            runtime.check()
            locked = _SLOTS.acquire(timeout=min(0.05, runtime.remaining()))
        runtime.acquire()
        started = time.monotonic()
        environment = _environment()
        code, output, _ = _run(runtime, [executable, "version"], environment)
        match = re.search(rb"(?m)^Xray\s+v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)\b", output)
        if code or match is None:
            raise KernelError("KERNEL_VERSION")
        result["kernel_version"] = match[1].decode("ascii")
        code, output, _ = _run(runtime, [executable, "x25519"], environment)
        if code:
            raise KernelError("KERNEL_KEYS")
        private, public = parse_keys(output)
        identity, short_id = str(uuid.uuid4()), secrets.token_hex(8)
        user, password = secrets.token_hex(8), secrets.token_hex(16)
        directory = tempfile.TemporaryDirectory(prefix="reality-target-kernel-")
        root = Path(directory.name)
        os.chmod(root, 0o700)
        empty = root / "empty"
        empty.mkdir(mode=0o700)
        reservations, (server_port, socks_port) = _reserve_ports()
        server, client = _configs(address, sni, server_port, socks_port, private, public,
                                  identity, short_id, user, password)
        paths = [root / "server.json", root / "client.json"]
        for path, config in zip(paths, (server, client)):
            _write_config(path, config)
            code, _, _ = _run(runtime, [executable, "run", "-test", "-config", str(path),
                                      "-confdir", str(empty)], environment)
            if code:
                raise KernelError("KERNEL_CONFIG")
        for path, reservation, port in zip(paths, reservations, (server_port, socks_port)):
            reservation.close()
            process = _start(runtime, [executable, "run", "-config", str(path), "-confdir", str(empty)],
                             root, environment)
            processes.append(process)
            _wait_ready(runtime, process, port)
        _check_alive(processes)
        remaining = runtime.operation_timeout()
        host = "[" + str(address) + "]" if address.version == 6 else str(address)
        command = ["curl", "--disable", "--config", "-", "--silent", "--show-error",
                   "--proxy", "socks5://127.0.0.1:" + str(socks_port), "--noproxy", "",
                   "--socks5-basic", "--proto", "=https", "--http1.1", "--head",
                   "--connect-timeout", str(remaining), "--max-time", str(remaining),
                   "--resolve", sni + ":443:" + host, "--output", os.devnull,
                   "--write-out", "%{http_code}", "https://" + sni + "/"]
        credentials = ('proxy-user = "' + user + ":" + password + '"\n').encode("ascii")
        code, output, _ = _run(runtime, command, environment, input_data=credentials)
        _check_alive(processes)
        if code or re.fullmatch(rb"[1-5][0-9]{2}", output.strip()) is None:
            raise KernelError("KERNEL_HTTP")
        result.update(status="PASS", http_status=int(output.strip()))
    except KernelError as error:
        result["error"] = str(error)
    except Exception as error:
        # Runtime errors are fixed IDs; never expose arbitrary kernel output.
        result["error"] = str(error) if str(error) in _RUNTIME_ERRORS else "KERNEL_RUNTIME"
    finally:
        for reservation in reservations:
            reservation.close()
        for process in reversed(processes):
            try:
                _stop(runtime, process)
            except Exception:
                result.update(status="UNKNOWN", error="KERNEL_CLEANUP")
        if directory is not None:
            try:
                directory.cleanup()
            except OSError:
                result.update(status="UNKNOWN", error="KERNEL_CLEANUP")
        if started is not None:
            result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        if locked:
            _SLOTS.release()
    return result
