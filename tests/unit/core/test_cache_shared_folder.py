#!/usr/bin/env python3
"""Analysis cache safety on a shared/network folder used by several processes or hosts.

Covers host-unique temp file names, the advisory per-APK lock file (busy, stale,
ownership) and the re-read-and-merge of the metadata index.
"""

import json
import os
import re
import threading
import time
from unittest import mock

from dexray_insight.core import cache_manager
from dexray_insight.core.cache_manager import LOCK_FILE_NAME
from dexray_insight.core.cache_manager import AnalysisCacheManager

MD5_A = "a" * 32
MD5_B = "b" * 32


def _manager(tmp_path, **attrs):
    manager = AnalysisCacheManager(cache_dir=tmp_path / "cache")
    for name, value in attrs.items():
        setattr(manager, name, value)
    return manager


def _metadata(tmp_path):
    return json.loads(next((tmp_path / "cache").glob("env-*/cache_metadata.json")).read_text())["apks"]


class TestTempFileNames:
    def test_temp_names_carry_host_pid_and_uuid(self, tmp_path):
        manager = _manager(tmp_path)
        replaced = []
        real_replace = os.replace

        def record(src, dst):
            replaced.append(os.path.basename(src))
            real_replace(src, dst)

        with mock.patch.object(cache_manager.os, "replace", side_effect=record):
            manager.set_module_result(MD5_A, "string_analysis", "cfg", {"n": 1})
            manager.set_module_result(MD5_A, "string_analysis", "cfg", {"n": 2})

        module_tmps = [name for name in replaced if name.startswith("string_analysis__cfg.json.tmp.")]
        assert len(module_tmps) == 2
        assert module_tmps[0] != module_tmps[1]
        pattern = rf"\.tmp\.{re.escape(cache_manager._HOST)}\.{os.getpid()}\.[0-9a-f]{{32}}$"
        assert all(re.search(pattern, name) for name in module_tmps)
        assert manager.get_module_result(MD5_A, "string_analysis", "cfg") == {"n": 2}


class TestPerApkLock:
    def _lock(self, tmp_path, md5=MD5_A):
        return _manager(tmp_path).env_dir / md5 / LOCK_FILE_NAME

    def test_lock_is_released_after_write(self, tmp_path):
        manager = _manager(tmp_path)
        manager.set_module_result(MD5_A, "string_analysis", "cfg", {"n": 1})
        assert not self._lock(tmp_path).exists()
        leftovers = [p.name for p in (tmp_path / "cache").rglob("*") if ".tmp." in p.name]
        assert leftovers == []

    def test_busy_lock_skips_write_and_is_left_alone(self, tmp_path):
        manager = _manager(tmp_path, LOCK_WAIT_SECONDS=0.2, LOCK_POLL_SECONDS=0.01)
        lock = self._lock(tmp_path)
        lock.parent.mkdir(parents=True)
        lock.write_text("otherhost 1 token")

        manager.set_module_result(MD5_A, "string_analysis", "cfg", {"n": 1})

        assert manager.get_module_result(MD5_A, "string_analysis", "cfg") is None
        assert lock.read_text() == "otherhost 1 token"

    def test_stale_lock_is_broken(self, tmp_path):
        manager = _manager(tmp_path, LOCK_WAIT_SECONDS=1.0, LOCK_STALE_SECONDS=60.0, LOCK_POLL_SECONDS=0.01)
        lock = self._lock(tmp_path)
        lock.parent.mkdir(parents=True)
        lock.write_text("crashedhost 1 token")
        old = time.time() - 3600
        os.utime(lock, (old, old))

        manager.set_module_result(MD5_A, "string_analysis", "cfg", {"n": 1})

        assert manager.get_module_result(MD5_A, "string_analysis", "cfg") == {"n": 1}
        assert not lock.exists()

    def test_foreign_lock_is_not_removed_on_release(self, tmp_path):
        manager = _manager(tmp_path)
        lock = self._lock(tmp_path)
        with manager._apk_write_lock(MD5_A):
            assert lock.exists()
            # Another writer broke our lock as stale and took it over.
            lock.write_text("otherhost 2 token")
        assert lock.read_text() == "otherhost 2 token"

    def test_lock_uses_exclusive_create(self, tmp_path):
        manager = _manager(tmp_path)
        with mock.patch.object(cache_manager.os, "open", wraps=os.open) as os_open, manager._apk_write_lock(MD5_A):
            pass
        flags = os_open.call_args.args[1]
        assert flags & os.O_CREAT and flags & os.O_EXCL

    def test_concurrent_writers_serialize(self, tmp_path):
        manager = _manager(tmp_path, LOCK_POLL_SECONDS=0.001)
        modules = [f"module_{i}" for i in range(8)]
        threads = [
            threading.Thread(target=manager.set_module_result, args=(MD5_A, name, "cfg", {"name": name}))
            for name in modules
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        for name in modules:
            assert manager.get_module_result(MD5_A, name, "cfg") == {"name": name}
        assert not self._lock(tmp_path).exists()


class TestMetadataMerge:
    def test_writers_merge_instead_of_overwriting(self, tmp_path):
        first = _manager(tmp_path)
        second = _manager(tmp_path)  # loaded before `first` wrote anything

        first.set_dex_strings(MD5_A, [["a"]])
        second.set_dex_strings(MD5_B, [["b"]])

        assert set(_metadata(tmp_path)) == {MD5_A, MD5_B}
        assert second.get_cache_stats()["cached_apks"] == 2

    def test_entries_without_apk_dir_are_dropped(self, tmp_path):
        first = _manager(tmp_path)
        first.set_dex_strings(MD5_A, [["a"]])
        first.set_dex_strings(MD5_B, [["b"]])

        other = _manager(tmp_path)
        other.invalidate(MD5_A)

        assert set(_metadata(tmp_path)) == {MD5_B}
        # A stale in-memory entry from `first` is not resurrected on its next save.
        first._save_metadata()
        assert set(_metadata(tmp_path)) == {MD5_B}

    def test_clear_cache_leaves_empty_index(self, tmp_path):
        first = _manager(tmp_path)
        first.set_dex_strings(MD5_A, [["a"]])
        other = _manager(tmp_path)

        assert other.clear_cache() == 1
        assert _metadata(tmp_path) == {}


class TestPerEnvironmentSubtree:
    """Hosts/venvs with different versions sharing one cache_dir must not read each other's results."""

    @staticmethod
    def _env_manager(tmp_path, androguard_version):
        with mock.patch.object(cache_manager, "_androguard_version", return_value=androguard_version):
            return _manager(tmp_path)

    def test_environments_do_not_share_results(self, tmp_path):
        host_b = self._env_manager(tmp_path, "4.1.3")
        host_a = self._env_manager(tmp_path, "4.1.2")
        assert host_a.env_dir != host_b.env_dir

        host_b.set_module_result(MD5_A, "string_analysis", "cfg", {"from": "b"})
        host_a.set_module_result(MD5_A, "manifest_analysis", "cfg", {"from": "a"})

        assert host_a.get_module_result(MD5_A, "string_analysis", "cfg") is None
        assert host_b.get_module_result(MD5_A, "string_analysis", "cfg") == {"from": "b"}
        # A fresh process of environment B still trusts its own subtree.
        assert self._env_manager(tmp_path, "4.1.3").get_module_result(MD5_A, "string_analysis", "cfg") == {"from": "b"}

    def test_legacy_flat_layout_is_a_miss(self, tmp_path):
        manager = _manager(tmp_path)
        legacy = tmp_path / "cache" / MD5_A
        (legacy / "modules").mkdir(parents=True)
        (legacy / "manifest.json").write_text(json.dumps(manager._fingerprint()))
        (legacy / "modules" / "string_analysis__cfg.json").write_text('{"legacy": true}')

        assert manager.get_module_result(MD5_A, "string_analysis", "cfg") is None

    def test_clear_cache_counts_apks_across_layouts(self, tmp_path):
        manager = _manager(tmp_path)
        manager.set_dex_strings(MD5_A, [["a"]])
        manager.set_dex_strings(MD5_B, [["b"]])
        (tmp_path / "cache" / ("c" * 32)).mkdir()  # legacy flat-layout entry

        assert manager.clear_cache() == 3
        assert [p for p in (tmp_path / "cache").iterdir() if p.is_dir()] == [manager.env_dir]
