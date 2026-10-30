"""Offline persistence tests, including process crashes and conflicting writers."""

import concurrent.futures
from contextlib import closing
import importlib.util
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("discovery_state", ROOT / "reality-target-state.py")
state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(state)


class PrivateStore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rtc-state-")
        self.directory = Path(self.temp.name)
        self.path = self.directory / "state.sqlite"

    def tearDown(self):
        self.temp.cleanup()

    def child(self, code, *args):
        loader = (
            "import importlib.util, os, sys; "
            "s=importlib.util.spec_from_file_location('state',sys.argv[1]); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
        )
        return subprocess.run([sys.executable, "-c", loader + code,
                               str(ROOT / "reality-target-state.py"), str(self.path), *args],
                              capture_output=True, text=True, timeout=5)

    def test_cache_round_trip_does_not_alias_caller_data(self):
        payload = {"ip": "192.0.2.10", "names": ["example.test"], "note": "中文"}
        with state.Cache(self.path) as cache:
            cache.put("hosts", "192.0.2.10", payload)
            payload["names"].append("caller-change.test")
            first = cache.get("hosts", "192.0.2.10")
            first["names"].append("reader-change.test")
            record = cache.get_record("hosts", "192.0.2.10")
            self.assertEqual(record["payload"]["names"], ["example.test"])
            self.assertEqual(record["payload"]["note"], "中文")
            self.assertIsInstance(record["observed_at"], float)
            self.assertIsNone(cache.get("hosts", "missing"))
        with state.Cache(self.path) as cache:
            self.assertEqual(cache.get("hosts", "192.0.2.10")["names"], ["example.test"])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertFalse(Path(str(self.path) + "-journal").exists())

    def test_missing_parent_directories_are_private(self):
        path = self.directory / "one" / "two" / "cache.sqlite"
        with state.Cache(path) as cache:
            cache.put("a", "b", {})
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.parent.parent.stat().st_mode), 0o700)

    def test_cache_lru_evicts_without_resetting_surviving_observation_time(self):
        with mock.patch.object(state.time, "time", return_value=1000):
            cache = state.Cache(self.path, max_entries=2)
        try:
            with mock.patch.object(state.time, "time", return_value=1001):
                cache.put("n", "a", 1)
            with mock.patch.object(state.time, "time", return_value=1002):
                cache.put("n", "b", 2)
            with mock.patch.object(state.time, "time", return_value=1003):
                self.assertEqual(cache.get("n", "a"), 1)
            with mock.patch.object(state.time, "time", return_value=1004):
                cache.put("n", "c", 3)
                self.assertIsNone(cache.get("n", "b"))
                self.assertEqual(cache.get_record("n", "a")["observed_at"], 1001)
                self.assertEqual(cache.get("n", "c"), 3)
        finally:
            cache.close()

    def test_expired_entries_are_not_reused(self):
        with mock.patch.object(state.time, "time", return_value=1000):
            checkpoint = state.Checkpoint(self.path, "scope", ttl=10)
        try:
            with mock.patch.object(state.time, "time", return_value=1001):
                checkpoint.put("sample", "0", {"status": "PASS"})
            with mock.patch.object(state.time, "time", return_value=1010):
                self.assertEqual(checkpoint.get("sample", "0"), {"status": "PASS"})
            with mock.patch.object(state.time, "time", return_value=1011):
                self.assertIsNone(checkpoint.get("sample", "0"))
        finally:
            checkpoint.close()

    def test_future_entries_and_future_creation_time_are_errors(self):
        with state.Checkpoint(self.path, "scope") as checkpoint:
            checkpoint.put("sample", "0", {})
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("UPDATE entries SET observed_at=?", (10**12,))
        with state.Checkpoint(self.path, "scope", resume=True) as checkpoint:
            with self.assertRaisesRegex(state.StateError, "STATE_TIME"):
                checkpoint.get("sample", "0")
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("UPDATE metadata SET value=? WHERE key='created_at'", ("1000000000000",))
        with self.assertRaisesRegex(state.StateError, "STATE_TIME"):
            state.Checkpoint(self.path, "scope", resume=True)

    def test_new_checkpoint_never_overwrites_existing_file(self):
        with state.Checkpoint(self.path, "scope") as checkpoint:
            checkpoint.put("sample", "0", {"value": "kept"})
        before = self.path.read_bytes()
        with self.assertRaisesRegex(state.StateError, "STATE_EXISTS"):
            state.Checkpoint(self.path, "scope")
        self.assertEqual(self.path.read_bytes(), before)

    def test_checkpoint_fingerprint_is_checked_without_modifying_file(self):
        with state.Checkpoint(self.path, "first") as checkpoint:
            checkpoint.put("meta", "plan", {"cidrs": ["192.0.2.0/24"]})
        before = self.path.read_bytes()
        with self.assertRaisesRegex(state.StateError, "STATE_FINGERPRINT"):
            state.Checkpoint(self.path, "second", resume=True)
        self.assertEqual(self.path.read_bytes(), before)
        with state.Checkpoint(self.path, "first", resume=True) as checkpoint:
            self.assertEqual(checkpoint.get("meta", "plan"), {"cidrs": ["192.0.2.0/24"]})

    def test_resume_requires_an_existing_checkpoint(self):
        with self.assertRaisesRegex(state.StateError, "STATE_MISSING"):
            state.Checkpoint(self.path, "scope", resume=True)
        self.assertFalse(self.path.exists())

    def test_foreign_database_and_corrupt_files_are_not_replaced(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("CREATE TABLE user_data (value TEXT)")
            connection.execute("INSERT INTO user_data VALUES ('keep')")
        self.path.chmod(0o600)
        original = self.path.read_bytes()
        with self.assertRaises(state.StateError):
            state.Cache(self.path)
        self.assertEqual(self.path.read_bytes(), original)
        self.path.write_bytes(b"not a SQLite database")
        with self.assertRaises(state.StateError):
            state.Cache(self.path)
        self.assertEqual(self.path.read_bytes(), b"not a SQLite database")

    def test_payload_corruption_is_not_a_cache_hit(self):
        with state.Cache(self.path) as cache:
            cache.put("source", "query", {"status": "WARN"})
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("UPDATE entries SET payload=?", (sqlite3.Binary(b'{"status":"PASS"}'),))
        with state.Cache(self.path) as cache:
            with self.assertRaisesRegex(state.StateError, "STATE_CORRUPT"):
                cache.get("source", "query")

    def test_unsafe_file_permissions_and_hardlinks_are_rejected(self):
        with state.Cache(self.path):
            pass
        self.path.chmod(0o644)
        with self.assertRaisesRegex(state.StateError, "STATE_PERMISSIONS"):
            state.Cache(self.path)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)
        self.path.chmod(0o600)
        linked = self.directory / "linked.sqlite"
        os.link(self.path, linked)
        with self.assertRaisesRegex(state.StateError, "STATE_PATH"):
            state.Cache(self.path)

    def test_symlink_file_or_parent_cannot_redirect_storage(self):
        target = self.directory / "target"
        target.write_text("unchanged")
        self.path.symlink_to(target)
        with self.assertRaises(state.StateError):
            state.Cache(self.path)
        self.assertEqual(target.read_text(), "unchanged")
        self.path.unlink()
        private = self.directory / "private"
        private.mkdir(mode=0o700)
        link = self.directory / "directory-link"
        link.symlink_to(private, target_is_directory=True)
        with self.assertRaisesRegex(state.StateError, "STATE_PATH"):
            state.Cache(link / "file.sqlite")
        self.assertEqual(list(private.iterdir()), [])

    def test_journal_symlink_cannot_redirect_a_transaction(self):
        target = self.directory / "unrelated"
        target.write_text("unchanged")
        with state.Cache(self.path) as cache:
            journal = Path(str(self.path) + "-journal")
            journal.symlink_to(target)
            try:
                with self.assertRaisesRegex(state.StateError, "STATE_PATH"):
                    cache.put("n", "k", {})
                self.assertEqual(target.read_text(), "unchanged")
            finally:
                journal.unlink()

    def test_clock_rewind_is_not_new_observation_evidence(self):
        with mock.patch.object(state.time, "time", return_value=1000):
            cache = state.Cache(self.path)
        try:
            with mock.patch.object(state.time, "time", return_value=999):
                with self.assertRaisesRegex(state.StateError, "STATE_TIME"):
                    cache.put("n", "k", {})
        finally:
            cache.close()

    def test_invalid_limits_are_state_errors(self):
        for arguments in ({"ttl": float("inf")}, {"ttl": -1}, {"max_bytes": "bad"},
                          {"max_bytes": 1}, {"max_entries": 1025}, {"entry_limit": 0},
                          {"entry_limit": 17 * state.ENTRY_LIMIT}):
            with self.subTest(arguments=arguments), self.assertRaises(state.StateError):
                state.Cache(self.path, **arguments)

    def test_shared_writable_parent_is_rejected(self):
        shared = self.directory / "shared"
        shared.mkdir(mode=0o777)
        shared.chmod(0o777)
        try:
            with self.assertRaisesRegex(state.StateError, "STATE_PERMISSIONS"):
                state.Cache(shared / "file.sqlite")
        finally:
            shared.chmod(0o700)

    def test_second_writer_is_rejected_in_process_and_across_processes(self):
        with state.Cache(self.path) as cache:
            with self.assertRaisesRegex(state.StateError, "STATE_LOCKED"):
                state.Cache(self.path)
            result = self.child(
                "\ntry:\n m.Cache(sys.argv[2])\nexcept m.StateError as e:\n print(str(e)); sys.exit(42)\n"
            )
            self.assertEqual((result.returncode, result.stdout.strip()), (42, "STATE_LOCKED"))
            cache.put("a", "b", "still owns lock")
        with state.Cache(self.path) as cache:
            self.assertEqual(cache.get("a", "b"), "still owns lock")

    def test_threads_store_complete_independent_records(self):
        with state.Checkpoint(self.path, "threaded") as checkpoint:
            def save(number):
                payload = {"sample": number, "values": list(range(20))}
                checkpoint.put("sample", str(number), payload)
                return checkpoint.get("sample", str(number))
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(save, range(64)))
            self.assertEqual([item["sample"] for item in results], list(range(64)))
        with state.Checkpoint(self.path, "threaded", resume=True) as checkpoint:
            self.assertEqual(checkpoint.get("sample", "63")["sample"], 63)

    def test_entry_and_checkpoint_capacity_errors_preserve_completed_records(self):
        with state.Checkpoint(self.path, "bounded", max_entries=1) as checkpoint:
            checkpoint.put("sample", "first", {"status": "PASS"})
            with self.assertRaisesRegex(state.StateError, "STATE_LIMIT"):
                checkpoint.put("sample", "second", {})
            with self.assertRaisesRegex(state.StateError, "STATE_LIMIT"):
                checkpoint.put("sample", "first", "x" * state.ENTRY_LIMIT)
            self.assertEqual(checkpoint.get("sample", "first"), {"status": "PASS"})
            self.assertIsNone(checkpoint.get("sample", "second"))

    def test_cache_accepts_explicit_larger_source_entry_limit(self):
        payload = {"raw": "x" * (state.ENTRY_LIMIT + 1)}
        with state.Cache(self.path) as cache:
            with self.assertRaisesRegex(state.StateError, "STATE_LIMIT"):
                cache.put("source", "large", payload)
        with state.Cache(self.path, entry_limit=8 * state.ENTRY_LIMIT) as cache:
            cache.put("source", "large", payload)
            self.assertEqual(cache.get("source", "large"), payload)

    def test_database_page_limit_is_not_exceeded(self):
        with state.Checkpoint(self.path, "size", max_bytes=65536) as checkpoint:
            checkpoint.put("s", "first", {"keep": True})
            failed = False
            for index in range(30):
                try:
                    checkpoint.put("s", str(index), {"data": "x" * 4096})
                except state.StateError:
                    failed = True
                    break
            self.assertTrue(failed)
            self.assertLessEqual(self.path.stat().st_size, 65536)
            self.assertEqual(checkpoint.get("s", "first"), {"keep": True})

    def test_only_strict_json_is_stored_and_keys_are_values(self):
        with state.Cache(self.path) as cache:
            for payload in (float("nan"), float("inf"), object(), {1, 2}):
                with self.subTest(payload=type(payload)), self.assertRaisesRegex(state.StateError, "STATE_PAYLOAD"):
                    cache.put("n", "bad", payload)
            key = "'); DROP TABLE entries; --"
            cache.put("n", key, {"safe": True})
            self.assertEqual(cache.get("n", key), {"safe": True})

    def test_close_is_idempotent_and_closed_store_cannot_be_reused(self):
        cache = state.Cache(self.path)
        cache.close()
        cache.close()
        with self.assertRaisesRegex(state.StateError, "STATE_CLOSED"):
            cache.get("a", "b")
        with self.assertRaisesRegex(state.StateError, "STATE_CLOSED"):
            cache.put("a", "b", {})

    def test_committed_partial_progress_survives_process_exit(self):
        result = self.child(
            "c=m.Checkpoint(sys.argv[2],'crash'); c.put('meta','plan',{'cidrs':['192.0.2.0/24']}); "
            "c.put('sample','first',{'status':'WARN'}); os._exit(0)"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with state.Checkpoint(self.path, "crash", resume=True) as checkpoint:
            self.assertEqual(checkpoint.get("sample", "first"), {"status": "WARN"})
            self.assertEqual(checkpoint.get("meta", "plan")["cidrs"], ["192.0.2.0/24"])

    def test_uncommitted_interruption_rolls_back_without_losing_prior_sample(self):
        with state.Checkpoint(self.path, "atomic") as checkpoint:
            checkpoint.put("sample", "first", {"status": "WARN"})
        result = self.child(
            "c=m.Checkpoint(sys.argv[2],'atomic',resume=True); "
            "c._connection.execute('BEGIN IMMEDIATE'); "
            "c._connection.execute(\"DELETE FROM entries WHERE namespace='sample'\"); "
            "os._exit(0)"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with state.Checkpoint(self.path, "atomic", resume=True) as checkpoint:
            self.assertEqual(checkpoint.get("sample", "first"), {"status": "WARN"})


if __name__ == "__main__":
    unittest.main()
