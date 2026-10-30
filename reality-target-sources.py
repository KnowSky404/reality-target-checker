#!/usr/bin/env python3
"""Finite, untrusted discovery inputs and RIPE RIS range planning.

This module never opens a target socket. Imported names are only seeds and all
active target selection remains the responsibility of the caller.
"""

from bisect import bisect_right
import csv
from datetime import datetime, timezone
import io
import ipaddress
import json
import math
import os
import re
import stat
import time
from urllib.parse import urlencode


MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 10000
MAX_PREFIXES = 10000
MAX_SEEDS = 4096
RIPE_BASE = "https://stat.ripe.net/data/"
RIPE_LIMITATIONS = [
    "RIPE RIS observations are not an authoritative ownership or real-time routing guarantee.",
    "network-info is based on eight-hour RISwhois dumps; low-visibility routes may be absent.",
    "ASN prefix coverage does not prove exclusive origin for every prefix; MOAS describes the origin-IP lookup only.",
]


class SourceError(ValueError):
    """A source cannot supply bounded, unambiguous evidence."""


def canonical_ip(value):
    if not isinstance(value, str) or not value.isascii() or "%" in value:
        raise SourceError("SOURCE_IP")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise SourceError("SOURCE_IP") from error
    if address.version == 4 and str(address) != value:
        raise SourceError("SOURCE_IP")
    return str(address) if address.version == 4 else address.exploded


def parse_network(value):
    if not isinstance(value, str) or not value.isascii() or "%" in value or "/" not in value:
        raise SourceError("SOURCE_PREFIX")
    address, mask = value.rsplit("/", 1)
    if not re.fullmatch(r"0|[1-9][0-9]{0,2}", mask):
        raise SourceError("SOURCE_PREFIX")
    canonical_ip(address)
    try:
        return ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise SourceError("SOURCE_PREFIX") from error


def _asn(value):
    if isinstance(value, bool):
        raise SourceError("SOURCE_ASN")
    value = str(value)
    if value.startswith("AS"):
        value = value[2:]
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > 4294967295:
        raise SourceError("SOURCE_ASN")
    return int(value)


def _utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value):
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            result = float(value)
        elif isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            # RIPE and Shodan commonly use ISO UTC without an explicit suffix.
            result = parsed.replace(tzinfo=timezone.utc).timestamp() if parsed.tzinfo is None else parsed.timestamp()
        else:
            raise ValueError
        if not math.isfinite(result) or result < 0:
            raise ValueError
        return result
    except (ValueError, TypeError, OverflowError) as error:
        raise SourceError("SOURCE_TIME") from error


def _json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = item
        return result
    def constant(_value):
        raise ValueError("non-finite number")
    try:
        return json.loads(value, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise SourceError("SOURCE_JSON") from error


def _file_text(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            details = os.fstat(source.fileno())
            if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_SOURCE_BYTES:
                raise SourceError("SOURCE_FILE_LIMIT")
            data = source.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise SourceError("SOURCE_FILE_LIMIT")
        return data.decode("utf-8-sig")
    except (OSError, UnicodeError) as error:
        raise SourceError("SOURCE_FILE") from error


def load_known_ips(path, max_ips=MAX_SEEDS):
    if type(max_ips) is not int or not 1 <= max_ips <= MAX_SEEDS:
        raise SourceError("SOURCE_IP_LIMIT")
    addresses = set()
    for line in _file_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        addresses.add(canonical_ip(line))
        if len(addresses) > max_ips:
            raise SourceError("SOURCE_IP_LIMIT")
    return sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))))


def _fallback_name(value):
    if not isinstance(value, str) or not value.isascii():
        return None
    name = value.removesuffix(".").lower()
    if not 1 <= len(name) <= 253 or re.fullmatch(r"[0-9.]+", name):
        return None
    if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}", name):
        return None
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in name.split(".")):
        return None
    return name


def _field(record, path, default=None):
    if path in record:
        return record[path]
    value = record
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def _names(value):
    if value is None or value == "":
        return []
    if isinstance(value, str):
        value = _json(value) if value.lstrip().startswith("[") else [value]
    if not isinstance(value, list) or any(not isinstance(name, str) for name in value):
        raise SourceError("SEED_NAMES")
    return value


def _validate_record_total(container, rows):
    if "total" not in container:
        return
    total = container["total"]
    if type(total) is not int or total < 0:
        raise SourceError("SEED_COUNT")
    if total > len(rows):
        raise SourceError("SEED_PAGINATION")
    if total < len(rows):
        raise SourceError("SEED_COUNT")


def _records(text, format, path):
    if str(path).lower().endswith(".csv"):
        try:
            reader = csv.DictReader(io.StringIO(text), strict=True)
            headers = reader.fieldnames
            if not headers or len(set(headers)) != len(headers) or any(not key for key in headers):
                raise SourceError("SEED_CSV_HEADER")
            rows = []
            for row in reader:
                if None in row or any(value is None for value in row.values()):
                    raise SourceError("SEED_CSV_ROW")
                rows.append(row)
                if len(rows) > MAX_RECORDS:
                    raise SourceError("SOURCE_RECORD_LIMIT")
            return rows
        except csv.Error as error:
            raise SourceError("SEED_CSV") from error
    try:
        parsed = _json(text)
    except SourceError:
        rows = []
        for line in text.splitlines():
            if line.strip():
                rows.append(_json(line))
                if len(rows) > MAX_RECORDS:
                    raise SourceError("SOURCE_RECORD_LIMIT")
        return rows
    if isinstance(parsed, list):
        rows = parsed
    elif isinstance(parsed, dict):
        container = parsed.get("result", parsed)
        if isinstance(container, dict) and (
                any(container.get(key) for key in ("next", "next_page_token", "next_cursor", "next_page"))
                or _field(container, "links.next")):
            raise SourceError("SEED_PAGINATION")
        if isinstance(container, dict) and isinstance(container.get("hits"), list):
            rows = container["hits"]
            if format == "censys":
                _validate_record_total(container, rows)
        elif format == "shodan" and isinstance(container, dict) and isinstance(container.get("matches"), list):
            rows = container["matches"]
            _validate_record_total(container, rows)
        elif isinstance(container, dict) and isinstance(container.get("seeds"), list):
            rows = container["seeds"]
        else:
            rows = [parsed]
    else:
        raise SourceError("SEED_RECORD")
    if len(rows) > MAX_RECORDS:
        raise SourceError("SOURCE_RECORD_LIMIT")
    return rows


def _seed_rows(record, format):
    """Yield IP/name/time triples without trusting historic protocol claims."""
    if not isinstance(record, dict):
        raise SourceError("SEED_RECORD")
    if format in {"generic", "dns"}:
        if format == "dns" and "rrname" in record:
            kind = record.get("rrtype")
            if not isinstance(kind, str) or kind not in {"A", "AAAA"}:
                raise SourceError("SEED_DNS_TYPE")
            addresses = record.get("rdata")
            addresses = [addresses] if isinstance(addresses, str) else addresses
            if not isinstance(addresses, list) or not addresses:
                raise SourceError("SEED_IP")
            for address in addresses:
                if ipaddress.ip_address(canonical_ip(address)).version != (4 if kind == "A" else 6):
                    raise SourceError("SEED_DNS_TYPE")
                yield address, record["rrname"], record.get("last_seen", record.get("time_last"))
            return
        address = record.get("ip", record.get("ip_str"))
        values = [record[key] for key in ("sni", "domain", "hostname") if record.get(key)]
        if not values:
            values = [record.get("host")]
        if len(set(value for value in values if isinstance(value, str))) != 1:
            raise SourceError("SEED_NAME_CONFLICT")
        observed = record.get("observed_at", record.get("last_seen", record.get("timestamp")))
        yield address, values[0], observed
        return
    if format == "censys":
        address = _field(record, "host.ip", record.get("ip"))
        observed = record.get("observed_at")
        for field in ("host.dns.names", "host.dns.reverse_dns.names", "dns.names", "dns.reverse_dns.names", "host.services.cert.names"):
            for name in _names(_field(record, field)):
                yield address, name, observed
        services = _field(record, "host.services", record.get("services", []))
        if not isinstance(services, list):
            raise SourceError("SEED_SERVICES")
        for service in services:
            if not isinstance(service, dict):
                raise SourceError("SEED_SERVICES")
            if str(service.get("port")) != "443":
                continue
            for field in ("cert.names", "tls.certificates.leaf_data.names"):
                for name in _names(_field(service, field)):
                    yield address, name, service.get("scan_time", service.get("observed_at", observed))
        return
    if format == "shodan":
        address = record.get("ip_str", record.get("ipv6"))
        observed = record.get("timestamp", record.get("observed_at"))
        for name in _names(record.get("hostnames")):
            yield address, name, observed
        hostname = _field(record, "_shodan.options.hostname")
        if hostname:
            yield address, hostname, observed
        if str(record.get("port", 443)) == "443":
            cn = _field(record, "ssl.cert.subject.CN")
            if cn:
                yield address, cn, observed
            extensions = _field(record, "ssl.cert.extensions", [])
            if not isinstance(extensions, list):
                raise SourceError("SEED_EXTENSIONS")
            for extension in extensions:
                if not isinstance(extension, dict):
                    raise SourceError("SEED_EXTENSIONS")
                if extension.get("name") == "subjectAltName":
                    san = extension.get("data")
                    # Raw DER extensions are not guessed/decoded as text names.
                    if isinstance(san, str) and san.startswith("DNS:"):
                        for entry in san.split(","):
                            if entry.strip().startswith("DNS:"):
                                yield address, entry.strip()[4:], observed
        return
    raise SourceError("SEED_FORMAT")


def load_seeds(path, format="generic", normalize_name=None, max_seeds=MAX_SEEDS, now=None):
    if format not in {"generic", "censys", "shodan", "dns"}:
        raise SourceError("SEED_FORMAT")
    if type(max_seeds) is not int or not 1 <= max_seeds <= MAX_SEEDS:
        raise SourceError("SOURCE_SEED_LIMIT")
    validator = normalize_name or _fallback_name
    now = time.time() if now is None else now
    result = {}
    records = _records(_file_text(path), format, path)
    for record in records:
        labels = ["import:" + format]
        if format in {"generic", "dns"} and isinstance(record, dict):
            supplied = record.get("sources", [])
            supplied = [supplied] if isinstance(supplied, str) else supplied
            if not isinstance(supplied, list):
                raise SourceError("SEED_SOURCE")
            if record.get("source"):
                supplied = supplied + [record["source"]]
            for label in supplied:
                if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,63}", label):
                    raise SourceError("SEED_SOURCE")
                labels.append("import:" + label)
        rows = list(_seed_rows(record, format))
        if not rows:
            raise SourceError("SEED_NO_NAMES")
        for raw_ip, raw_name, observed in rows:
            address = canonical_ip(raw_ip)
            if isinstance(raw_name, str) and raw_name.startswith("*.") and validator(raw_name[2:]):
                continue
            name = validator(raw_name)
            if not name:
                raise SourceError("SEED_NAME")
            observed_at = None
            if observed not in (None, ""):
                stamp = _timestamp(observed)
                if stamp > now + 300:
                    raise SourceError("SEED_FUTURE_TIME")
                observed_at = _utc(stamp)
            key = (address, name)
            item = result.setdefault(key, {"ip": address, "sni": name, "sources": [], "observed_at": None})
            item["sources"] = sorted(set(item["sources"]) | set(labels))
            if observed_at is not None and (item["observed_at"] is None or _timestamp(observed_at) > _timestamp(item["observed_at"])):
                item["observed_at"] = observed_at
            if len(result) > max_seeds:
                raise SourceError("SOURCE_SEED_LIMIT")
    if records and not result:
        raise SourceError("SEED_NO_CONCRETE_NAMES")
    return sorted(result.values(), key=lambda item: (ipaddress.ip_address(item["ip"]).version,
                                                    int(ipaddress.ip_address(item["ip"])), item["sni"]))


def _cache_key(endpoint, params):
    key_params = {key: value for key, value in params.items() if key not in {"starttime", "endtime"}}
    return endpoint + ":" + urlencode(sorted(key_params.items()))


def _cache_response(endpoint, params, payload, retrieved_at, cache, cache_hit):
    if cache is not None and not cache_hit:
        cache.put("ripe", _cache_key(endpoint, params), {"retrieved_at": retrieved_at, "payload": payload})


def _api_json(endpoint, params, runtime, cache, now, max_age):
    if runtime is None:
        raise SourceError("RIPE_RUNTIME")
    key = _cache_key(endpoint, params)
    if cache is not None:
        cached = cache.get("ripe", key)
        if cached is not None:
            if not isinstance(cached, dict) or "payload" not in cached:
                raise SourceError("RIPE_CACHE")
            try:
                retrieved = _fresh(cached.get("retrieved_at"), now, max_age)
                if endpoint == "announced-prefixes":
                    data = _data(cached["payload"])
                    _fresh(data.get("latest_time"), now, max_age)
                    _fresh(data.get("query_endtime"), now, max_age)
            except SourceError as error:
                if str(error) != "RIPE_STALE_SNAPSHOT":
                    raise
            else:
                return cached["payload"], _utc(retrieved), True
    url = RIPE_BASE + endpoint + "/data.json?" + urlencode(sorted(params.items()))
    try:
        runtime.acquire()
        limit = min(runtime.timeout, runtime.remaining())
        if limit <= 0:
            raise SourceError("DEADLINE")
        code, output, _ = runtime.run([
            "curl", "--disable", "--fail", "--silent", "--show-error", "--globoff",
            "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", str(limit),
            "--max-time", str(limit), "--header", "Accept: application/json", "--url", url,
        ], timeout=limit, output_limit=MAX_SOURCE_BYTES)
    except SourceError:
        raise
    except Exception as error:
        code = str(error)
        raise SourceError(code if code in {"CANCELLED", "DEADLINE", "OUTPUT_LIMIT", "OPERATION_TIMEOUT"} else "RIPE_FETCH") from error
    if code or len(output) > MAX_SOURCE_BYTES:
        raise SourceError("RIPE_FETCH")
    payload = _json(output)
    retrieved_at = _utc(now)
    return payload, retrieved_at, False


def _data(payload):
    if not isinstance(payload, dict) or payload.get("status") != "ok" or not isinstance(payload.get("data"), dict):
        raise SourceError("RIPE_RESPONSE")
    if any(payload["data"].get(key) for key in ("next", "next_page_token", "next_cursor")):
        raise SourceError("RIPE_PAGINATION")
    return payload["data"]


def _fresh(stamp, now, max_age):
    stamp = _timestamp(stamp)
    if stamp > now + 300:
        raise SourceError("RIPE_FUTURE_TIME")
    if now - stamp > max_age:
        raise SourceError("RIPE_STALE_SNAPSHOT")
    return stamp


def _prefixes(values):
    if not isinstance(values, list) or len(values) > MAX_PREFIXES:
        raise SourceError("RIPE_PREFIX_LIMIT")
    networks = [parse_network(value) for value in values]
    result = []
    for version in (4, 6):
        result.extend(ipaddress.collapse_addresses(network for network in networks if network.version == version))
    return [str(network) for network in result]


def build_asn_plan(asn=None, origin_ip=None, runtime=None, cache=None, now=None, max_age=86400):
    now = time.time() if now is None else now
    if not isinstance(max_age, (int, float)) or isinstance(max_age, bool) or not 1 <= max_age <= 7 * 86400:
        raise SourceError("RIPE_MAX_AGE")
    number = _asn(asn) if asn is not None else None
    origin_ip = canonical_ip(origin_ip) if origin_ip is not None else None
    if number is None and origin_ip is None:
        raise SourceError("SOURCE_ASN")
    plan = {"asn": number, "origin_ip": origin_ip, "origin_asns": [], "moas": None, "moas_scope": "origin_ip",
            "status": "PASS", "snapshot_time": None, "retrieved_at": None,
            "prefixes_v4": [], "prefixes_v6": [], "source": "RIPEstat / RIPE RIS",
            "cache_hit": False, "issues": [], "limitations": list(RIPE_LIMITATIONS)}
    if origin_ip is not None:
        origin_params = {"resource": origin_ip}
        payload, retrieved, hit = _api_json("network-info", origin_params, runtime, cache, now, max_age)
        _fresh(retrieved, now, max_age)
        data = _data(payload)
        if not isinstance(data.get("asns"), list):
            raise SourceError("RIPE_ORIGIN")
        origins = sorted({_asn(value) for value in data["asns"]})
        plan.update(origin_asns=origins, moas=len(origins) > 1 if origins else None,
                    retrieved_at=retrieved, cache_hit=hit)
        prefix = data.get("prefix")
        if prefix is None or prefix == "" or not origins:
            plan.update(status="UNKNOWN", issues=["UNROUTED_ORIGIN"])
            return plan
        network = parse_network(prefix)
        if ipaddress.ip_address(origin_ip) not in network:
            raise SourceError("RIPE_ORIGIN_PREFIX")
        plan["origin_prefix"] = str(network)
        plan["origin_lookup"] = {"retrieved_at": retrieved, "cache_hit": hit,
                                 "prefix": str(network), "asns": origins, "dump_interval_hours": 8}
        if number is not None and number not in origins:
            raise SourceError("RIPE_ASN_ORIGIN_MISMATCH")
        _cache_response("network-info", origin_params, payload, retrieved, cache, hit)
        if number is None:
            if len(origins) != 1:
                plan.update(status="UNKNOWN", issues=["MOAS_REQUIRES_EXPLICIT_ASN"])
                return plan
            number = origins[0]
            plan["asn"] = number
    # RIPE accepts integer Unix seconds; fractional ISO timestamps with a Z
    # suffix are rejected by this endpoint despite its broad ISO8601 wording.
    query_end = int(now)
    params = {
        "resource": "AS" + str(number), "starttime": str(query_end - 86400),
        "endtime": str(query_end), "min_peers_seeing": 1,
    }
    payload, retrieved, hit = _api_json("announced-prefixes", params, runtime, cache, now, max_age)
    _fresh(retrieved, now, max_age)
    data = _data(payload)
    if _asn(data.get("resource")) != number:
        raise SourceError("RIPE_RESOURCE")
    latest = _fresh(data.get("latest_time"), now, max_age)
    query_end = _fresh(data.get("query_endtime"), now, max_age)
    query_start = _timestamp(data.get("query_starttime"))
    if query_start > query_end or latest < query_start:
        raise SourceError("RIPE_INTERVAL")
    snapshot = min(latest, query_end, now)
    rows = data.get("prefixes")
    if not isinstance(rows, list) or len(rows) > MAX_PREFIXES:
        raise SourceError("RIPE_PREFIX_LIMIT")
    selected = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("timelines"), list):
            raise SourceError("RIPE_PREFIX")
        network = parse_network(row.get("prefix"))
        for timeline in row["timelines"]:
            if not isinstance(timeline, dict):
                raise SourceError("RIPE_TIMELINE")
            start, end = _timestamp(timeline.get("starttime")), _timestamp(timeline.get("endtime"))
            if start > end or start > now + 300 or end > now + 300:
                raise SourceError("RIPE_TIMELINE")
            if start <= snapshot <= end:
                selected.add(str(network))
    announced = sorted(selected, key=lambda value: (ipaddress.ip_network(value).version,
                                                   int(ipaddress.ip_network(value).network_address),
                                                   ipaddress.ip_network(value).prefixlen))
    selected = _prefixes(list(selected))
    plan.update(snapshot_time=_utc(snapshot), retrieved_at=retrieved,
                cache_hit=plan["cache_hit"] or hit,
                prefixes_v4=[value for value in selected if ":" not in value],
                prefixes_v6=[value for value in selected if ":" in value],
                announced_prefixes=announced,
                query_starttime=_utc(query_start), query_endtime=_utc(query_end))
    if plan["moas"]:
        plan["issues"].append("MOAS_EXPLICIT_ASN")
    _cache_response("announced-prefixes", params, payload, retrieved, cache, hit)
    return plan


def validate_asn_plan(plan, asn=None, origin_ip=None, now=None, max_age=86400):
    """Validate checkpoint plan semantics without refreshing its observations.

    A checksum verifies persisted bytes, not their ASN/scope meaning. Checkpoint
    restoration must bind the plan back to the user's current selection context.
    """
    now = time.time() if now is None else now
    try:
        if (not isinstance(plan, dict) or plan.get("status") != "PASS"
                or not isinstance(max_age, (int, float)) or isinstance(max_age, bool)
                or not 1 <= max_age <= 7 * 86400
                or not isinstance(now, (int, float)) or isinstance(now, bool)
                or not math.isfinite(now) or now < 0):
            raise ValueError
        requested_asn = _asn(asn) if asn is not None else None
        requested_origin = canonical_ip(origin_ip) if origin_ip is not None else None
        if requested_asn is None and requested_origin is None:
            raise ValueError
        number = plan["asn"]
        if type(number) is not int or _asn(number) != number:
            raise ValueError
        if requested_asn is not None and number != requested_asn:
            raise ValueError
        if plan["origin_ip"] != requested_origin:
            raise ValueError
        origins = plan["origin_asns"]
        if (not isinstance(origins, list) or len(origins) > MAX_PREFIXES
                or any(type(value) is not int or _asn(value) != value for value in origins)
                or sorted(set(origins)) != origins
                or plan["moas_scope"] != "origin_ip"
                or type(plan["cache_hit"]) is not bool
                or plan["source"] != "RIPEstat / RIPE RIS"
                or plan["limitations"] != RIPE_LIMITATIONS):
            raise ValueError

        def observation(value, fresh=False):
            if not isinstance(value, str):
                raise ValueError
            stamp = _timestamp(value)
            if _utc(stamp) != value or stamp > now:
                raise ValueError
            if fresh and now - stamp > max_age:
                raise SourceError("RIPE_STALE_SNAPSHOT")
            return stamp

        snapshot = observation(plan["snapshot_time"], fresh=True)
        retrieved = observation(plan["retrieved_at"], fresh=True)
        query_start = observation(plan["query_starttime"])
        query_end = observation(plan["query_endtime"])
        if not query_start <= snapshot <= query_end <= retrieved:
            raise ValueError
        v4, v6 = plan["prefixes_v4"], plan["prefixes_v6"]
        if (not isinstance(v4, list) or not isinstance(v6, list)
                or len(v4) + len(v6) > MAX_PREFIXES):
            raise ValueError
        for version, values in ((4, v4), (6, v6)):
            for value in values:
                network = parse_network(value)
                if network.version != version or str(network) != value:
                    raise ValueError
        if _prefixes(v4 + v6) != v4 + v6:
            raise ValueError
        if "announced_prefixes" in plan:
            announcements = plan["announced_prefixes"]
            if (not isinstance(announcements, list) or len(announcements) > MAX_PREFIXES
                    or any(str(parse_network(value)) != value for value in announcements)
                    or _prefixes(announcements) != v4 + v6):
                raise ValueError
        if requested_origin is None:
            if (origins or plan["moas"] is not None or plan["issues"] != []
                    or plan.get("origin_prefix") is not None or plan.get("origin_lookup") is not None):
                raise ValueError
        else:
            if (not origins or number not in origins
                    or requested_asn is None and origins != [number]
                    or type(plan["moas"]) is not bool or plan["moas"] != (len(origins) > 1)
                    or plan["issues"] != (["MOAS_EXPLICIT_ASN"] if len(origins) > 1 else [])):
                raise ValueError
            prefix = parse_network(plan["origin_prefix"])
            if str(prefix) != plan["origin_prefix"] or ipaddress.ip_address(requested_origin) not in prefix:
                raise ValueError
            lookup = plan["origin_lookup"]
            if (not isinstance(lookup, dict) or lookup["prefix"] != str(prefix)
                    or lookup["asns"] != origins or type(lookup["cache_hit"]) is not bool
                    or type(lookup["dump_interval_hours"]) is not int or lookup["dump_interval_hours"] != 8):
                raise ValueError
            observation(lookup["retrieved_at"], fresh=True)
        return plan
    except SourceError as error:
        if str(error) == "RIPE_STALE_SNAPSHOT":
            raise
        raise SourceError("STATE_PLAN") from error
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as error:
        raise SourceError("STATE_PLAN") from error


def select_prefixes(plan, selected):
    if not isinstance(plan, dict) or plan.get("status") != "PASS":
        raise SourceError("ASN_PLAN_UNKNOWN")
    if not isinstance(selected, (list, tuple)) or len(selected) > MAX_PREFIXES:
        raise SourceError("SOURCE_PREFIX_LIMIT")
    v4, v6 = plan.get("prefixes_v4", []), plan.get("prefixes_v6", [])
    if not isinstance(v4, list) or not isinstance(v6, list) or len(v4) + len(v6) > MAX_PREFIXES:
        raise SourceError("SOURCE_PREFIX_LIMIT")
    allowed = [parse_network(value) for value in v4 + v6]
    intervals = {}
    for version in (4, 6):
        merged = []
        ranges = sorted((int(network.network_address), int(network.broadcast_address))
                        for network in allowed if network.version == version)
        for start, end in ranges:
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        intervals[version] = ([start for start, _end in merged], [end for _start, end in merged])
    networks = []
    for value in selected:
        network = parse_network(value)
        starts, ends = intervals[network.version]
        index = bisect_right(starts, int(network.network_address)) - 1
        if index < 0 or int(network.broadcast_address) > ends[index]:
            raise SourceError("ASN_PREFIX_OUT_OF_SCOPE")
        networks.append(str(network))
    # Preserve the user's enumeration semantics: /31 + /31 is not hosts(/30).
    return sorted(set(networks), key=lambda value: (ipaddress.ip_network(value).version,
                                                   int(ipaddress.ip_network(value).network_address),
                                                   ipaddress.ip_network(value).prefixlen))


def ip_in_prefixes(ip, prefixes):
    if not isinstance(prefixes, (list, tuple)) or len(prefixes) > MAX_PREFIXES:
        raise SourceError("SOURCE_PREFIX_LIMIT")
    address = ipaddress.ip_address(canonical_ip(ip))
    return any(address.version == network.version and address in network
               for network in (parse_network(prefix) for prefix in prefixes))
