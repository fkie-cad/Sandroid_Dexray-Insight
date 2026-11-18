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
    """Editing the tracker signature database must invalidate tracker-dependent results."""

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

    def _engine(self, tmp_path, db_path):
        config = Configuration(
            config_dict={
                "caching": {"cache_dir": str(tmp_path / "cache")},
                "modules": {"tracker_analysis": {"tracker_db_path": db_path}},
            }
        )
        return AnalysisEngine(config)

    def test_full_result_key_follows_db_when_tracker_analysis_runs(self, tmp_path):
        db_path = self._override(tmp_path, "A")
        with_tracker = ["string_analysis", "tracker_analysis"]
        without_tracker = ["string_analysis"]
        before = self._engine(tmp_path, db_path)
        before_keys = (before._full_hit_config_hash(with_tracker), before._full_hit_config_hash(without_tracker))

        self._override(tmp_path, "B")
        after = self._engine(tmp_path, db_path)

        assert after._full_hit_config_hash(with_tracker) != before_keys[0]
        assert after._full_hit_config_hash(without_tracker) == before_keys[1]

    def test_pii_flow_deep_cache_key_includes_db(self):
        from dexray_insight.security import pii_flow_assessment

        keys = []

        def fake_cached(context, name, config, build_fn):
            keys.append(cache_manager.hash_config(config))
            return []

        def assess(db_key):
            manager = mock.Mock()
            manager.signature_db_key.return_value = db_key
            context = mock.Mock(config={"deep_mode": True}, cache_manager=manager)
            pii_flow_assessment.PIIFlowAssessment({}).assess({}, context)

        with mock.patch.object(pii_flow_assessment, "cached_deep_findings", side_effect=fake_cached):
            assess("db-a")
            assess("db-a")
            assess("db-b")
        assert keys[0] == keys[1] != keys[2]

    def test_module_results_are_not_keyed_by_db(self, tmp_path):
        db_path = self._override(tmp_path, "A")
        writer = self._manager(tmp_path, db_path)
        writer.set_module_result(self.MD5, "string_analysis", "cfg", {"urls": []})
        writer_key = writer.signature_db_key()
        self._override(tmp_path, "B")
        reader = self._manager(tmp_path, db_path)
        assert reader.signature_db_key() != writer_key
        assert reader.get_module_result(self.MD5, "string_analysis", "cfg") == {"urls": []}

    def test_engine_passes_tracker_db_path(self, tmp_path):
        db_path = self._override(tmp_path, "A")
        assert self._engine(tmp_path, db_path).cache_manager.tracker_db_path == db_path
