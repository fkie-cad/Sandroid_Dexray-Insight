#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression: the --deep CLI flag must actually enable the Phase C deep gates.

The deep data-flow (``deep_dataflow``) and PII-flow (``pii_flow``) assessments
gate all of their detection behind a "deep mode" check on ``context.config``.
The canonical config path written by ``--deep`` is
``modules.behaviour_analysis.deep_mode`` (see analysis_engine._is_deep_mode),
but the two assessment gates previously only checked the flat top-level and a
non-nested ``behaviour_analysis`` key, so under a real ``--deep`` run they
returned False and both assessments produced nothing.

This is the missing integration test: it builds a REAL ``Configuration``,
applies the ``--deep`` update exactly as the CLI does, converts to the dict
that ``context.config`` carries, and asserts BOTH gates return True.

It additionally pins BUG-2: ``--deep`` must also enable
``modules.tracker_analysis.deep_string_location_analysis`` so the per-method
string attribution the PII-flow detectors depend on is produced.
"""

import argparse

import pytest

from src.dexray_insight.asam import _build_configuration_updates
from src.dexray_insight.core.configuration import Configuration
from src.dexray_insight.security.deep_dataflow_assessment import DeepDataflowAssessment
from src.dexray_insight.security.pii_flow_assessment import PIIFlowAssessment


class _Ctx:
    """Minimal context carrying only the config dict the gates read."""

    def __init__(self, config):
        self.config = config


def _deep_config_dict():
    """Return the effective config dict produced by a real ``--deep`` run."""
    config = Configuration()
    args = argparse.Namespace(deep=True)
    config._merge_config(_build_configuration_updates(args))
    return config.to_dict()


@pytest.mark.unit
@pytest.mark.security
class TestDeepGateIntegration:
    """A real --deep Configuration must switch both deep gates on."""

    def test_deep_flag_sets_nested_deep_mode(self):
        cfg = _deep_config_dict()
        assert cfg["modules"]["behaviour_analysis"]["deep_mode"] is True

    def test_deep_flag_enables_string_location_analysis(self):
        # BUG 2: precise PII-source attribution needs this opt-in tracker pass.
        cfg = _deep_config_dict()
        assert cfg["modules"]["tracker_analysis"]["deep_string_location_analysis"] is True

    def test_deep_dataflow_gate_true_under_real_deep(self):
        cfg = _deep_config_dict()
        assert DeepDataflowAssessment._is_deep_mode(_Ctx(cfg)) is True

    def test_pii_flow_gate_true_under_real_deep(self):
        cfg = _deep_config_dict()
        assert PIIFlowAssessment._is_deep(_Ctx(cfg)) is True

    def test_gates_false_without_deep_flag(self):
        # Fast (default) mode must leave both gates off.
        cfg = Configuration().to_dict()
        assert DeepDataflowAssessment._is_deep_mode(_Ctx(cfg)) is False
        assert PIIFlowAssessment._is_deep(_Ctx(cfg)) is False

    def test_flat_topfallback_still_works(self):
        # Backwards-compat: existing callers passing a flat config keep working.
        assert DeepDataflowAssessment._is_deep_mode(_Ctx({"deep_mode": True})) is True
        assert PIIFlowAssessment._is_deep(_Ctx({"deep_mode": True})) is True
        assert DeepDataflowAssessment._is_deep_mode(
            _Ctx({"behaviour_analysis": {"deep_mode": True}})
        ) is True
        assert PIIFlowAssessment._is_deep(
            _Ctx({"behaviour_analysis": {"deep_mode": True}})
        ) is True
