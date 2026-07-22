#!/usr/bin/env python3
"""Regression lock for the shallow analysis-cache logic-version keying.

Security results are cached inside the full-result cache, keyed on a config-derived
hash. Because that hash is config-based (not code-based) and the fingerprint's
``tool_version`` does not move during in-place development, a detection-logic change
would otherwise be masked by a stale cache hit. ``ANALYSIS_SCHEMA_VERSION`` is folded
into both the full-result and per-module cache keys so bumping it invalidates prior
entries — the shallow-cache analog of ``DEEP_SCHEMA_VERSION``.
"""

from unittest import mock

import pytest

from dexray_insight.core import cache_manager
from dexray_insight.core.analysis_engine import AnalysisEngine
from dexray_insight.core.configuration import Configuration


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
