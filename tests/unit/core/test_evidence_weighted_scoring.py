#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PR-6 tests: confidence field, severity-default backfill, and evidence-weighted scorer v2.

Covers:
- SecurityFinding.confidence serialization (additive, backward compatible).
- Severity-derived confidence backfill for unscored findings.
- v1 legacy scorer reproduces the historical Kik score (43.0) for its severity vector.
- v2 evidence-weighted scorer: Σ severity_weight × confidence, denominator ~100.
- risk_score_confirmed subset (confidence >= threshold).
- Single high-confidence CRITICAL floor.
- Monotonicity: adding a real finding never lowers the score.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from src.dexray_insight.core.base_classes import AnalysisSeverity  # noqa: E402
from src.dexray_insight.core.base_classes import SecurityFinding  # noqa: E402
from src.dexray_insight.core.configuration import Configuration  # noqa: E402
from src.dexray_insight.core.security_engine import SecurityAssessmentEngine  # noqa: E402


def _finding(severity, confidence=None, title="f"):
    return SecurityFinding(
        category="TestCat",
        severity=severity,
        title=title,
        description="d",
        evidence=[],
        recommendations=[],
        confidence=confidence,
    )


def _engine(version=2, denominator=100.0, critical_floor=75.0):
    config = Configuration()
    config.config["security"] = {
        "risk_scoring": {"version": version, "denominator": denominator, "critical_floor": critical_floor}
    }
    return SecurityAssessmentEngine(config)


@pytest.mark.unit
@pytest.mark.security
class TestConfidenceField:
    def test_confidence_serialized(self):
        f = _finding(AnalysisSeverity.HIGH, confidence=0.7)
        assert f.to_dict()["confidence"] == 0.7

    def test_confidence_defaults_none_and_serializes_null(self):
        f = _finding(AnalysisSeverity.HIGH)
        assert f.confidence is None
        assert f.to_dict()["confidence"] is None

    def test_existing_positional_constructor_still_works(self):
        f = SecurityFinding("cat", AnalysisSeverity.LOW, "t", "d", [], [])
        assert f.confidence is None  # additive field defaults cleanly


@pytest.mark.unit
@pytest.mark.security
class TestBackfill:
    def test_backfill_sets_severity_defaults(self):
        engine = _engine()
        findings = [_finding(AnalysisSeverity.CRITICAL), _finding(AnalysisSeverity.LOW)]
        engine._backfill_confidence(findings)
        assert findings[0].confidence == 0.8
        assert findings[1].confidence == 0.3

    def test_backfill_leaves_explicit_confidence(self):
        engine = _engine()
        findings = [_finding(AnalysisSeverity.HIGH, confidence=0.95)]
        engine._backfill_confidence(findings)
        assert findings[0].confidence == 0.95


@pytest.mark.unit
@pytest.mark.security
class TestLegacyScorerV1:
    def test_kik_severity_vector_reproduces_43(self):
        engine = _engine(version=1)
        findings = (
            [_finding(AnalysisSeverity.CRITICAL)] * 1
            + [_finding(AnalysisSeverity.HIGH)] * 16
            + [_finding(AnalysisSeverity.MEDIUM)] * 18
            + [_finding(AnalysisSeverity.LOW)] * 21
        )
        # 1*10 + 16*7 + 18*4 + 21*1 = 215; 215/500*100 = 43.0
        assert engine._calculate_risk_score_v1(findings) == 43.0

    def test_empty_is_zero(self):
        assert _engine()._calculate_risk_score_v1([]) == 0.0


@pytest.mark.unit
@pytest.mark.security
class TestEvidenceWeightedScorerV2:
    def test_raw_sum(self):
        engine = _engine(denominator=100.0)
        findings = [_finding(AnalysisSeverity.HIGH, 0.5), _finding(AnalysisSeverity.MEDIUM, 0.5)]
        normalized, raw = engine._calculate_risk_score_v2(findings)
        # 7*0.5 + 4*0.5 = 5.5 ; /100*100 = 5.5
        assert raw == 5.5
        assert normalized == 5.5

    def test_low_confidence_heuristics_do_not_dominate(self):
        engine = _engine()
        # 16 evidence-free HIGH heuristics at conf 0.3 contribute far less than under v1.
        findings = [_finding(AnalysisSeverity.HIGH, 0.3) for _ in range(16)]
        _, raw = engine._calculate_risk_score_v2(findings)
        assert raw == pytest.approx(16 * 7 * 0.3)  # 33.6, vs 112 under v1

    def test_confirmed_subset_excludes_low_confidence(self):
        engine = _engine()
        findings = [
            _finding(AnalysisSeverity.HIGH, 0.9, "confirmed"),
            _finding(AnalysisSeverity.HIGH, 0.3, "unproven"),
        ]
        confirmed = [f for f in findings if (f.confidence or 0.0) >= engine.confirmed_confidence_threshold]
        _, raw_confirmed = engine._calculate_risk_score_v2(confirmed)
        assert raw_confirmed == pytest.approx(7 * 0.9)

    def test_single_high_confidence_critical_floors_score(self):
        engine = _engine(critical_floor=75.0)
        findings = [_finding(AnalysisSeverity.CRITICAL, 0.9)]
        normalized, _ = engine._calculate_risk_score_v2(findings)
        assert normalized >= 75.0

    def test_low_confidence_critical_does_not_floor(self):
        engine = _engine(critical_floor=75.0)
        findings = [_finding(AnalysisSeverity.CRITICAL, 0.4)]
        normalized, _ = engine._calculate_risk_score_v2(findings)
        assert normalized < 75.0

    def test_monotonic_adding_finding_never_lowers(self):
        engine = _engine()
        base = [_finding(AnalysisSeverity.MEDIUM, 0.5)]
        more = base + [_finding(AnalysisSeverity.HIGH, 0.6)]
        assert engine._calculate_risk_score_v2(more)[1] >= engine._calculate_risk_score_v2(base)[1]

    def test_capped_at_100(self):
        engine = _engine(denominator=100.0)
        findings = [_finding(AnalysisSeverity.CRITICAL, 1.0) for _ in range(50)]
        normalized, _ = engine._calculate_risk_score_v2(findings)
        assert normalized == 100.0
