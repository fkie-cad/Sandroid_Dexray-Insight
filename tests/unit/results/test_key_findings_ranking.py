#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PR-0b regression tests: 'Key Findings' are ranked by severity, not insertion order.

On Kik base.apk the terminal previously showed the first three inserted findings
("Weak Authentication / Insecure Session Management / Potentially Exported Service"),
none of which were the real risks. Ranking by severity weight (× confidence when set)
ensures a CRITICAL inserted late is surfaced above an earlier LOW.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.results.FullAnalysisResults import FullAnalysisResults  # noqa: E402


def _rank(finding):
    return FullAnalysisResults._finding_rank_key(finding)


@pytest.mark.unit
class TestKeyFindingRanking:
    def test_severity_ordering(self):
        findings = [
            {"title": "a low", "severity": "low"},
            {"title": "a critical", "severity": "critical"},
            {"title": "a medium", "severity": "medium"},
            {"title": "a high", "severity": "high"},
        ]
        ranked = sorted(findings, key=_rank, reverse=True)
        assert [f["severity"] for f in ranked] == ["critical", "high", "medium", "low"]

    def test_late_critical_beats_early_low(self):
        # Mirrors the Kik bug: real CRITICAL inserted after noisy LOWs must rank first.
        findings = [
            {"title": "noise 1", "severity": "low"},
            {"title": "noise 2", "severity": "low"},
            {"title": "real secret", "severity": "critical"},
        ]
        ranked = sorted(findings, key=_rank, reverse=True)
        assert ranked[0]["title"] == "real secret"

    def test_confidence_breaks_ties_within_severity(self):
        low_conf = {"title": "unproven high", "severity": "high", "confidence": 0.3}
        high_conf = {"title": "confirmed high", "severity": "high", "confidence": 0.95}
        ranked = sorted([low_conf, high_conf], key=_rank, reverse=True)
        assert ranked[0]["title"] == "confirmed high"

    def test_missing_confidence_defaults_to_pure_severity(self):
        # Without confidence, ordering is a pure severity sort (backward compatible).
        crit = {"title": "c", "severity": "critical"}
        high = {"title": "h", "severity": "high"}
        assert _rank(crit) > _rank(high)

    def test_severity_enum_value_dict_is_handled(self):
        finding = {"title": "x", "severity": {"value": "critical"}}
        assert FullAnalysisResults._finding_severity_str(finding) == "critical"
