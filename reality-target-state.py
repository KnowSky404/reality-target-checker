"""Private, bounded JSON cache and resumable checkpoints for discovery."""

import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time


APPLICATION_ID = 0x52544353
SCHEMA_VERSION = "1"
ENTRY_LIMIT = 1024 * 1024
CACHE_LIMIT = 64 * 1024 * 1024
CHECKPOINT_LIMIT = 256 * 1024 * 1024
_META_SQL = "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
_ENTRY_SQL = (
    "CREATE TABLE entries (namespace TEXT NOT NULL, key TEXT NOT NULL, "
    "payload BLOB NOT NULL, observed_at REAL NOT NULL, digest TEXT NOT NULL, "
    "last_access REAL NOT NULL, byte_length INTEGER NOT NULL, "
    "PRIMARY KEY (namespace, key))"
)


class StateError(Exception):
    """A state file could not safely supply or retain JSON evidence."""


def _finite_number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _reject_constant(_value):
    raise ValueError("non-finite JSON")


class _Store:
    def __init__(self, path, *, kind, fingerprint, resume, ttl, max_bytes,
                 max_entries, entry_limit):
        try:
            self.path = Path(path).absolute()
        except (TypeError, ValueError, OSError) as error:
            raise StateError("STATE_PATH") from error
        self.ttl = ttl
        self.kind = kind
        self.fingerprint = fingerprint
        self.max_bytes = max_bytes
        self.max_entries = max_entries
        self.entry_limit = entry_limit
        self._fd = None
        self._connection = None
        self._lock = threading.RLock()
        self._created = False
        self._created_at = None
        if (not _finite_number(ttl) or ttl < 0
                or type(max_bytes) is not int or not 32768 <= max_bytes <= CHECKPOINT_LIMIT
                or type(max_entries) is not int or not 1 <= max_entries <= 30000
                or type(entry_limit) is not int or not 1 <= entry_limit <= 16 * ENTRY_LIMIT
                or not isinstance(fingerprint, str) or len(fingerprint.encode("utf-8")) > 4096):
            raise StateError("STATE_OPTIONS")
        try:
            self._prepare_parent()
            self._open_file(resume)
            self._connection = sqlite3.connect(str(self.path), timeout=0,
                                               check_same_thread=False, isolation_level=None)
            self._connection.execute("PRAGMA trusted_schema=OFF")
            self._identity()
            if self._created:
                self._initialize()
            else:
                self._validate()
            self._configure()
        except BaseException as error:
            created = self._created
            inode = os.fstat(self._fd).st_ino if self._fd is not None else None
            self.close()
            if created:
                try:
                    current = self.path.lstat()
                    if stat.S_ISREG(current.st_mode) and current.st_ino == inode:
                        self.path.unlink()
                except OSError:
                    pass
            if isinstance(error, StateError):
                raise
            if isinstance(error, (OSError, sqlite3.Error, ValueError, OverflowError)):
                raise StateError("STATE_OPEN") from error
            raise

    def _prepare_parent(self):
        # SQLite's journal is adjacent to the DB: its directory must not permit
        # other users to replace it with a symlink between SQLite operations.
        current = self.path.parent
        existing = []
        while True:
            if current.exists() or current.is_symlink():
                info = current.lstat()
                if not stat.S_ISDIR(info.st_mode) or current.is_symlink():
                    raise StateError("STATE_PATH")
                if info.st_uid not in {os.getuid(), 0}:
                    raise StateError("STATE_PERMISSIONS")
                if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                    raise StateError("STATE_PERMISSIONS")
            else:
                existing.append(current)
            if current == current.parent:
                break
            current = current.parent
        for directory in reversed(existing):
            directory.mkdir(mode=0o700)
        parent = self.path.parent.stat()
        if parent.st_mode & 0o022:
            raise StateError("STATE_PERMISSIONS")

    def _open_file(self, resume):
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        if self.kind == "checkpoint" and resume:
            try:
                self._fd = os.open(self.path, flags)
            except FileNotFoundError as error:
                raise StateError("STATE_MISSING") from error
        else:
            try:
                self._fd = os.open(self.path, flags | os.O_CREAT | os.O_EXCL, 0o600)
                self._created = True
                os.fchmod(self._fd, 0o600)
            except FileExistsError as error:
                if self.kind == "checkpoint":
                    raise StateError("STATE_EXISTS") from error
                self._fd = os.open(self.path, flags)
        self._identity()
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise StateError("STATE_LOCKED") from error
        if not self._created:
            header = os.pread(self._fd, 100, 0)
            if (len(header) != 100 or not header.startswith(b"SQLite format 3\0")
                    or int.from_bytes(header[68:72], "big") != APPLICATION_ID):
                raise StateError("STATE_FORMAT")

    def _identity(self):
        if self._fd is None:
            raise StateError("STATE_CLOSED")
        original = os.fstat(self._fd)
        current = self.path.lstat()
        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                or (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino)):
            raise StateError("STATE_PATH")
        if current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o600:
            raise StateError("STATE_PERMISSIONS")
        if current.st_size > self.max_bytes:
            raise StateError("STATE_LIMIT")
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            try:
                info = sidecar.lstat()
            except FileNotFoundError:
                continue
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
                raise StateError("STATE_PATH")

    def _configure(self):
        self._connection.execute("PRAGMA journal_mode=DELETE")
        self._connection.execute("PRAGMA synchronous=FULL")
        page_size = self._connection.execute("PRAGMA page_size").fetchone()[0]
        self._connection.execute("PRAGMA max_page_count=%d" % (self.max_bytes // page_size))
        self._connection.execute("PRAGMA busy_timeout=0")

    def _initialize(self):
        self._configure()
        now = time.time()
        if not _finite_number(now) or now < 0:
            raise StateError("STATE_TIME")
        self._created_at = now
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute("PRAGMA application_id=%d" % APPLICATION_ID)
            self._connection.execute("PRAGMA user_version=1")
            self._connection.execute(_META_SQL)
            self._connection.execute(_ENTRY_SQL)
            self._connection.executemany("INSERT INTO metadata VALUES (?, ?)", (
                ("schema_version", SCHEMA_VERSION), ("kind", self.kind),
                ("fingerprint", self.fingerprint), ("created_at", repr(now)),
            ))
            self._connection.execute("COMMIT")
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def _validate(self):
        connection = self._connection
        if connection.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
            raise StateError("STATE_CORRUPT")
        schema = {row[0]: (row[1], row[2]) for row in connection.execute(
            "SELECT name, type, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
        if schema != {"metadata": ("table", _META_SQL), "entries": ("table", _ENTRY_SQL)}:
            raise StateError("STATE_FORMAT")
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        if (set(metadata) != {"schema_version", "kind", "fingerprint", "created_at"}
                or metadata["schema_version"] != SCHEMA_VERSION
                or metadata["kind"] != self.kind):
            raise StateError("STATE_FORMAT")
        if metadata["fingerprint"] != self.fingerprint:
            raise StateError("STATE_FINGERPRINT")
        try:
            created = float(metadata["created_at"])
        except (TypeError, ValueError) as error:
            raise StateError("STATE_CORRUPT") from error
        if not _finite_number(created) or created < 0 or created > time.time():
            raise StateError("STATE_TIME")
        self._created_at = created
        count = connection.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        if count > self.max_entries:
            raise StateError("STATE_LIMIT")

    def _key(self, namespace, key):
        if (not isinstance(namespace, str) or not 1 <= len(namespace.encode("utf-8")) <= 64
                or not isinstance(key, str) or not 1 <= len(key.encode("utf-8")) <= 1024):
            raise StateError("STATE_KEY")

    def _now(self):
        now = time.time()
        if (not _finite_number(now) or now < 0
                or self._created_at is not None and now < self._created_at):
            raise StateError("STATE_TIME")
        return now

    def get_record(self, namespace, key):
        """Return payload plus its original wall-clock observation timestamp."""
        self._key(namespace, key)
        with self._lock:
            try:
                self._identity()
                row = self._connection.execute(
                    "SELECT payload, observed_at, digest, byte_length FROM entries "
                    "WHERE namespace=? AND key=?", (namespace, key)).fetchone()
                if row is None:
                    return None
                payload, observed, digest, length = row
                now = self._now()
                if not _finite_number(observed) or observed < 0 or observed > now:
                    raise StateError("STATE_TIME")
                if (not isinstance(payload, bytes) or type(length) is not int
                        or length != len(payload) or length > self.entry_limit
                        or not isinstance(digest, str)
                        or hashlib.sha256(payload).hexdigest() != digest):
                    raise StateError("STATE_CORRUPT")
                if now - observed >= self.ttl:
                    return None
                value = json.loads(payload.decode("utf-8"), parse_constant=_reject_constant)
                if self.kind == "cache":
                    self._connection.execute("UPDATE entries SET last_access=? WHERE namespace=? AND key=?",
                                             (now, namespace, key))
                return {"payload": value, "observed_at": observed}
            except StateError:
                raise
            except (sqlite3.Error, OSError, ValueError, RecursionError) as error:
                raise StateError("STATE_READ") from error

    def get(self, namespace, key):
        record = self.get_record(namespace, key)
        return None if record is None else record["payload"]

    def put(self, namespace, key, payload):
        self._key(namespace, key)
        try:
            encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False,
                                 separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError) as error:
            raise StateError("STATE_PAYLOAD") from error
        if len(encoded) > self.entry_limit:
            raise StateError("STATE_LIMIT")
        with self._lock:
            try:
                self._identity()
                now = self._now()
                connection = self._connection
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute("DELETE FROM entries WHERE namespace=? AND key=?", (namespace, key))
                    count, size = connection.execute(
                        "SELECT COUNT(*), COALESCE(SUM(byte_length), 0) FROM entries").fetchone()
                    payload_budget = self.max_bytes // 2 if self.kind == "cache" else self.max_bytes * 3 // 4
                    if self.kind == "cache":
                        while count >= self.max_entries or size + len(encoded) > payload_budget:
                            victim = connection.execute(
                                "SELECT namespace, key, byte_length FROM entries "
                                "ORDER BY last_access, namespace, key LIMIT 1").fetchone()
                            if victim is None:
                                raise StateError("STATE_LIMIT")
                            connection.execute("DELETE FROM entries WHERE namespace=? AND key=?", victim[:2])
                            count -= 1
                            size -= victim[2]
                    elif count >= self.max_entries or size + len(encoded) > payload_budget:
                        raise StateError("STATE_LIMIT")
                    connection.execute("INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?)", (
                        namespace, key, sqlite3.Binary(encoded), now,
                        hashlib.sha256(encoded).hexdigest(), now, len(encoded)))
                    connection.execute("COMMIT")
                except BaseException:
                    connection.execute("ROLLBACK")
                    raise
            except StateError:
                raise
            except (sqlite3.Error, OSError, ValueError, OverflowError) as error:
                raise StateError("STATE_WRITE") from error

    def close(self):
        with self._lock:
            connection, self._connection = self._connection, None
            descriptor, self._fd = self._fd, None
            try:
                if connection is not None:
                    connection.close()
            finally:
                if descriptor is not None:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(descriptor)

    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        self.close()


class Cache(_Store):
    def __init__(self, path, ttl=3600, max_bytes=CACHE_LIMIT, *, max_entries=1024,
                 entry_limit=ENTRY_LIMIT):
        if (type(max_bytes) is not int or max_bytes > CACHE_LIMIT
                or type(max_entries) is not int or not 1 <= max_entries <= 1024):
            raise StateError("STATE_OPTIONS")
        super().__init__(path, kind="cache", fingerprint="", resume=False, ttl=ttl,
                         max_bytes=max_bytes, max_entries=max_entries, entry_limit=entry_limit)


class Checkpoint(_Store):
    def __init__(self, path, fingerprint, resume=False, ttl=3600,
                 max_bytes=CHECKPOINT_LIMIT, *, max_entries=30000):
        if not fingerprint:
            raise StateError("STATE_FINGERPRINT")
        super().__init__(path, kind="checkpoint", fingerprint=fingerprint, resume=resume,
                         ttl=ttl, max_bytes=max_bytes, max_entries=max_entries, entry_limit=ENTRY_LIMIT)
