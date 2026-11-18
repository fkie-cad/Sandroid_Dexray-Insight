#!/usr/bin/env python3
"""Regression lock for the shallow analysis-cache logic-version keying.

Security results are cached inside the full-result cache, keyed on a config-derived
hash. Because that hash is config-based (not code-based) and the fingerprint's
``tool_version`` does not move during in-place development, a detection-logic change
would otherwise be masked by a stale cache hit. ``ANALYSIS_SCHEMA_VERSION`` is folded
into both the full-result and per-module cache keys so bumping it invalidates prior
entries — the shallow-cache analog of ``DEEP_SCHEMA_VERSION``.
"""

import json
from unittest import mock

import pytest

from dexray_insight.core import cache_manager
from dexray_insight.core.analysis_engine import AnalysisEngine
from dexray_insight.core.configuration import Configuration
from dexray_insight.modules.tracker_analysis.databases import tracker_database


@pytest.fixture
def engine():
    return AnalysisEngine(Configuration())


def _fresh(engine):
    # The hashes are memoized on the engine; clear so a patched schema is picked up.
    engine._config_hash_cache = {}


class TestAnalysisSchemaVersionInCacheKey:
    def test_full_result_key_changes_when_schema_version_bumps(self, engine):
        modules = ["apk_overview", "manifest_analysis"]
        _fresh(engine)
        h1 = engine._full_hit_config_hash(modules)
        with mock.patch.object(cache_manager, "ANALYSIS_SCHEMA_VERSION", "different-version"):
            _fresh(engine)
            h2 = engine._full_hit_config_hash(modules)
        assert h1 != h2, "full-result cache key must change when ANALYSIS_SCHEMA_VERSION bumps"

    def test_module_key_changes_when_schema_version_bumps(self, engine):
        _fresh(engine)
        h1 = engine._module_cache_key_hash()
        with mock.patch.object(cache_manager, "ANALYSIS_SCHEMA_VERSION", "different-version"):
            _fresh(engine)
            h2 = engine._module_cache_key_hash()
        assert h1 != h2, "per-module cache key must change when ANALYSIS_SCHEMA_VERSION bumps"

    def test_same_schema_and_config_is_stable(self, engine):
        # Sanity: without a bump, the key is deterministic (a genuine cache hit still works).
        modules = ["apk_overview"]
        _fresh(engine)
        first = engine._full_hit_config_hash(modules)
        _fresh(engine)
        second = engine._full_hit_config_hash(modules)
        assert first == second


class TestSignatureDbInCacheKey:
    """Editing the tracker signature database must invalidate tracker and full results."""

    MD5 = "0123456789abcdef0123456789abcdef"

    @staticmethod
    def _override(tmp_path, label):
        path = tmp_path / "sigdb.json"
        path.write_text(json.dumps({"entries": {"acme": {"kind": "recipient", "label": label}}}))
        return str(path)

    def _manager(self, tmp_path, db_path):
        return cache_manager.AnalysisCacheManager(cache_dir=tmp_path / "cache", tracker_db_path=db_path)

    def test_digest_tracks_override_and_builtin_content(self, tmp_path):
        db_path = self._override(tmp_path, "A")
        first = cache_manager.signature_db_digest(db_path)
        assert first == cache_manager.signature_db_digest(db_path)
        assert first != cache_manager.signature_db_digest(None)

        self._override(tmp_path, "B")
        assert cache_manager.signature_db_digest(db_path) != first

        builtin = tmp_path / "builtin.json"
        builtin.write_text('{"entries": {}}')
        with mock.patch.object(tracker_database, "SIGNATURE_DB_PATH", builtin):
            patched = cache_manager.signature_db_digest(None)
        assert patched != cache_manager.signature_db_digest(None)

    def test_db_change_invalidates_tracker_and_full_results_only(self, tmp_path):
        db_path = self._override(tmp_path, "A")
        writer = self._manager(tmp_path, db_path)
        writer.set_module_result(self.MD5, "tracker_analysis", "cfg", {"total_trackers": 1})
        writer.set_module_result(self.MD5, "string_analysis", "cfg", {"urls": []})
        writer.set_full_result(self.MD5, "cfg", {"main": {}, "security": None})

        same = self._manager(tmp_path, db_path)
        assert same.get_module_result(self.MD5, "tracker_analysis", "cfg") == {"total_trackers": 1}
        assert same.get_full_result(self.MD5, "cfg") == {"main": {}, "security": None}

        self._override(tmp_path, "B")
        changed = self._manager(tmp_path, db_path)
        assert changed.get_module_result(self.MD5, "tracker_analysis", "cfg") is None
        assert changed.get_full_result(self.MD5, "cfg") is None
        assert changed.get_module_result(self.MD5, "string_analysis", "cfg") == {"urls": []}

    def test_engine_passes_tracker_db_path(self, tmp_path):
        db_path = self._override(tmp_path, "A")
        config = Configuration(
            config_dict={
                "caching": {"cache_dir": str(tmp_path / "cache")},
                "modules": {"tracker_analysis": {"tracker_db_path": db_path}},
            }
        )
        assert AnalysisEngine(config).cache_manager.tracker_db_path == db_path
