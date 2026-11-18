#!/usr/bin/env python3
"""Analysis cache safety on a shared/network folder used by several processes or hosts.

Covers host-unique temp file names, per-environment subtrees, concurrent writers
and the re-read-and-merge of the metadata index.
"""

import json
import os
import re
import threading
from unittest import mock

from dexray_insight.core import cache_manager
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


class TestConcurrentWrites:
    def test_no_lock_or_temp_files_are_left(self, tmp_path):
        manager = _manager(tmp_path)
        manager.set_module_result(MD5_A, "string_analysis", "cfg", {"n": 1})
        leftovers = [p.name for p in (tmp_path / "cache").rglob("*") if ".tmp." in p.name or p.name == ".lock"]
        assert leftovers == []

    def test_writes_for_one_apk_share_an_in_process_lock(self, tmp_path):
        manager = _manager(tmp_path)
        assert manager._apk_write_lock(MD5_A) is manager._apk_write_lock(MD5_A)
        assert manager._apk_write_lock(MD5_A) is not manager._apk_write_lock(MD5_B)

    def test_write_waits_for_the_in_process_lock(self, tmp_path):
        manager = _manager(tmp_path)
        lock = manager._apk_write_lock(MD5_A)
        lock.acquire()
        writer = threading.Thread(target=manager.set_module_result, args=(MD5_A, "string_analysis", "cfg", {"n": 1}))
        writer.start()
        writer.join(timeout=0.2)
        assert writer.is_alive()  # blocked, not skipped
        lock.release()
        writer.join()
        assert manager.get_module_result(MD5_A, "string_analysis", "cfg") == {"n": 1}

    def test_concurrent_writers_all_land(self, tmp_path):
        writers = [_manager(tmp_path) for _ in range(2)]  # two "processes" sharing the folder
        modules = [f"module_{i}" for i in range(8)]
        threads = [
            threading.Thread(target=writers[i % 2].set_module_result, args=(MD5_A, name, "cfg", {"name": name}))
            for i, name in enumerate(modules)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        reader = _manager(tmp_path)
        for name in modules:
            assert reader.get_module_result(MD5_A, name, "cfg") == {"name": name}


class TestMetadataMerge:
    def test_writers_merge_instead_of_overwriting(self, tmp_path):
        first = _manager(tmp_path)
        second = _manager(tmp_path)  # loaded before `first` wrote anything

        first.set_dex_strings(MD5_A, [["a"]])
        second.set_dex_strings(MD5_B, [["b"]])

        assert set(_metadata(tmp_path)) == {MD5_A, MD5_B}
        assert second.get_cache_stats()["cached_apks"] == 2

    def test_invalidated_entries_are_dropped(self, tmp_path):
        first = _manager(tmp_path)
        first.set_dex_strings(MD5_A, [["a"]])
        first.set_dex_strings(MD5_B, [["b"]])

        other = _manager(tmp_path)
        other.invalidate(MD5_A)
        assert set(_metadata(tmp_path)) == {MD5_B}

        # Re-caching an invalidated APK lists it again.
        other.set_dex_strings(MD5_A, [["a"]])
        assert set(_metadata(tmp_path)) == {MD5_A, MD5_B}

    def test_save_does_not_stat_apk_dirs(self, tmp_path):
        manager = _manager(tmp_path)
        manager.set_dex_strings(MD5_A, [["a"]])
        with mock.patch.object(cache_manager.Path, "is_dir", side_effect=AssertionError("is_dir scan")):
            manager._save_metadata()
        assert set(_metadata(tmp_path)) == {MD5_A}

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
