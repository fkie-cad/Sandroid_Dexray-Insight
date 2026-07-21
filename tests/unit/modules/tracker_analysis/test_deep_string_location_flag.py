#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the ``deep_string_location_analysis`` config gate.

These tests verify that the expensive per-instruction bytecode walk in
``TrackerAnalysisModule._extract_raw_dex_strings`` is only executed when the
opt-in ``deep_string_location_analysis`` flag is enabled, and that string
collection (and therefore tracker detection input) still works when it is off.
"""

from unittest.mock import MagicMock

from src.dexray_insight.core.base_classes import AnalysisContext
from src.dexray_insight.modules.tracker_analysis.tracker_analysis_module import (
    TrackerAnalysisModule,
)


def _make_module(config=None):
    """Create a TrackerAnalysisModule with Exodus fetching disabled."""
    base = {"fetch_exodus_trackers": False}
    if config:
        base.update(config)
    return TrackerAnalysisModule(base)


def _make_context(dex):
    """Build a real AnalysisContext whose androguard_obj yields the given dex.

    A real context is used (not a stub) because the always-on DEX string pool is
    now sourced from the shared ``AnalysisContext.get_dex_strings()`` accessor;
    the mock dex's ``get_strings`` is still invoked once through that accessor.
    Caching is disabled so extraction always goes through the mock.
    """
    androguard_obj = MagicMock()
    androguard_obj.get_androguard_dex.return_value = [dex]
    return AnalysisContext(apk_path="test.apk", config={}, androguard_obj=androguard_obj)


def _make_dex(pool_strings):
    """Build a mock DEX object exposing get_classes / get_strings."""
    dex = MagicMock()
    dex.get_strings.return_value = list(pool_strings)
    dex.get_classes.return_value = []  # tracked via assert_not_called / call_count
    return dex


class TestDeepStringLocationFlagDefault:
    """The expensive deep option must default to False."""

    def test_flag_defaults_false(self):
        module = _make_module()
        assert module.deep_string_location_analysis is False

    def test_flag_can_be_enabled(self):
        module = _make_module({"deep_string_location_analysis": True})
        assert module.deep_string_location_analysis is True


class TestExtractRawDexStringsGating:
    """The bytecode operand walk runs only when the flag is enabled."""

    def test_walk_skipped_when_flag_off(self):
        module = _make_module()
        dex = _make_dex(["com.google.android.gms.ads.AdView", "short"])
        context = _make_context(dex)

        all_strings = set()
        locations = module._extract_raw_dex_strings(context, all_strings)

        # The per-class/method bytecode walk must NOT be performed.
        dex.get_classes.assert_not_called()
        # But the cheap DEX string pool extraction still runs.
        dex.get_strings.assert_called_once()

        # Strings are still collected (detection input unchanged).
        assert "com.google.android.gms.ads.AdView" in all_strings
        # Locations degrade to the generic DEX string pool marker.
        assert locations["com.google.android.gms.ads.AdView"] == ["DEX strings pool"]

    def test_walk_runs_when_flag_on(self):
        module = _make_module({"deep_string_location_analysis": True})
        dex = _make_dex(["com.google.android.gms.ads.AdView"])
        context = _make_context(dex)

        all_strings = set()
        module._extract_raw_dex_strings(context, all_strings)

        # The per-class/method bytecode walk IS performed when enabled.
        dex.get_classes.assert_called_once()
        dex.get_strings.assert_called_once()

    def test_detection_input_identical_regardless_of_flag(self):
        """The collected string set must be identical whether the walk runs.

        The DEX string pool (get_strings) is a superset of the string constants
        referenced by bytecode, so skipping the walk must not drop any string
        used for tracker detection.
        """
        pool = ["com.google.firebase.analytics.FirebaseAnalytics", "https://app-measurement.com"]

        module_off = _make_module()
        strings_off = set()
        module_off._extract_raw_dex_strings(_make_context(_make_dex(pool)), strings_off)

        module_on = _make_module({"deep_string_location_analysis": True})
        strings_on = set()
        module_on._extract_raw_dex_strings(_make_context(_make_dex(pool)), strings_on)

        assert strings_off == strings_on
