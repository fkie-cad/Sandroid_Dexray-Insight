#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for per-category sample capping/bucketing (PR-2 / WS2).

Ensures no category emits an unbounded flat list while the true total count is
preserved (false-negative guard) and the full list stays available internally.
"""

import pytest

from dexray_insight.modules.string_analysis.string_analysis_module import StringAnalysisModule

pytestmark = pytest.mark.unit


def _email_only_module(cap):
    """Build a module that only runs the (cheap) email filter, with a sample cap."""
    config = {
        "min_string_length": 2,
        "email_addresses": True,
        "ip_addresses": False,
        "urls": False,
        "domains": False,
        "android_properties": False,
        "max_samples_per_category": cap,
    }
    return StringAnalysisModule(config)


class TestSampleCapping:
    def test_large_input_is_capped_but_count_preserved(self):
        cap = 1000
        module = _email_only_module(cap)

        total = 200_000
        synthetic = {f"user{i}@example{i}.com" for i in range(total)}
        assert len(synthetic) == total

        results = module._apply_all_filters(synthetic)

        # Emitted samples are bounded by the cap ...
        assert len(results["emails"]) <= cap
        assert len(results["emails"]) == cap
        # ... but the true total count is preserved (false-negative guard).
        assert results["category_counts"]["emails"] == total
        # ... and the full, uncapped list remains available internally.
        assert len(results["full_categories"]["emails"]) == total

    def test_small_input_not_truncated(self):
        module = _email_only_module(1000)
        synthetic = {f"user{i}@example{i}.com" for i in range(10)}
        results = module._apply_all_filters(synthetic)
        assert len(results["emails"]) == 10
        assert results["category_counts"]["emails"] == 10

    def test_custom_cap_applied(self):
        cap = 50
        module = _email_only_module(cap)
        synthetic = {f"user{i}@example{i}.com" for i in range(500)}
        results = module._apply_all_filters(synthetic)
        assert len(results["emails"]) == cap
        assert results["category_counts"]["emails"] == 500
