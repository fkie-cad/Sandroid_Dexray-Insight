#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A7 measurement/regression harness: headline-score anchors.

Pins the confirmed-subset headline risk score against two committed real-world
security JSONs (a real threat, Kik base.apk, and a benign-ish example app) plus
two synthetic profiles (clean / malware). This is the regression tripwire that
catches score drift and false-positive explosions WITHOUT depending on the
164MB APK — it is a pure JSON-load + scorer recompute and is fast.

The headline is the ``confirmed`` subset score: findings whose
``verification_status`` is CONFIRMED (unset normalizes to CONFIRMED for the
pre-verification-status committed JSONs) AND whose confidence is at/above the
confirmed threshold (0.7), fed through ``_calculate_risk_score_v2``. See
``SecurityAssessmentEngine._confirmed_subset`` / ``_calculate_risk_score_v2``.

Measured anchors (discovered from the committed fixtures, 2026-07-22):
    * Kik base.apk  confirmed headline = 41.3  (11-finding confirmed subset)
    * example app   confirmed headline =  0.0  (0-finding confirmed subset)
"""

import json
import os

import pytest

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.core.base_classes import SecurityFinding
from src.dexray_insight.core.base_classes import VerificationStatus
from src.dexray_insight.core.configuration import Configuration
from src.dexray_insight.core.security_engine import SecurityAssessmentEngine

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "security_scores")

_SEVERITY_MAP = {
    "low": AnalysisSeverity.LOW,
    "medium": AnalysisSeverity.MEDIUM,
    "high": AnalysisSeverity.HIGH,
    "critical": AnalysisSeverity.CRITICAL,
}


def _finding_from_dict(raw: dict) -> SecurityFinding:
    """Reconstruct a SecurityFinding from a committed security-JSON finding dict.

    verification_status defaults to CONFIRMED when absent (the committed JSONs
    predate the field), matching the engine's backward-compatible normalization.
    """
    status_value = raw.get("verification_status")
    status = VerificationStatus(status_value) if status_value else VerificationStatus.CONFIRMED
    return SecurityFinding(
        category=raw.get("category", "unknown"),
        severity=_SEVERITY_MAP[raw["severity"]],
        title=raw.get("title", ""),
        description=raw.get("description", ""),
        evidence=raw.get("evidence", []) or [],
        recommendations=raw.get("recommendations", []) or [],
        confidence=raw.get("confidence"),
        verification_status=status,
    )


def _load_fixture(name: str) -> list[SecurityFinding]:
    with open(os.path.join(FIXTURE_DIR, name), encoding="utf-8") as fh:
        data = json.load(fh)
    return [_finding_from_dict(f) for f in data["findings"]]


def _headline(engine: SecurityAssessmentEngine, findings: list[SecurityFinding]) -> float:
    """Recompute the confirmed-subset headline, exactly as the engine does."""
    normalized, _ = engine._calculate_risk_score_v2(engine._confirmed_subset(findings))
    return normalized


def _synthetic(severity, confidence, status=VerificationStatus.CONFIRMED, title="synthetic") -> SecurityFinding:
    return SecurityFinding(
        category="Synthetic",
        severity=severity,
        title=title,
        description="d",
        evidence=["e"],
        recommendations=[],
        confidence=confidence,
        verification_status=status,
    )


@pytest.fixture(scope="module")
def engine():
    # Default config -> v2 scorer, confirmed headline mode, threshold 0.7, floor 75.
    return SecurityAssessmentEngine(Configuration())


# --------------------------------------------------------------------------- #
# Committed-fixture anchors
# --------------------------------------------------------------------------- #
@pytest.mark.regression
@pytest.mark.security
class TestFixtureAnchors:
    def test_kik_headline_in_defensible_band(self, engine):
        kik = _load_fixture("kik_base_security.json")
        headline = _headline(engine, kik)
        # Broad defensibility band required by the harness spec.
        assert 20 <= headline <= 55, f"Kik headline {headline} left the defensible band"
        # Tight band around the measured value (41.3 as of 2026-07-22). This is the
        # actual drift tripwire; loosen only with a documented reason.
        assert 40.0 <= headline <= 43.0, f"Kik headline drifted from measured 41.3: {headline}"

    def test_exampleapp_headline_is_low(self, engine):
        example = _load_fixture("exampleapp_security.json")
        headline = _headline(engine, example)
        # Measured: 0.0 (no confirmed high-confidence findings).
        assert headline <= 25, f"benign example headline should be low, got {headline}"

    def test_kik_strictly_outranks_exampleapp(self, engine):
        kik = _headline(engine, _load_fixture("kik_base_security.json"))
        example = _headline(engine, _load_fixture("exampleapp_security.json"))
        assert kik > example, f"Kik headline ({kik}) must strictly exceed example ({example})"


# --------------------------------------------------------------------------- #
# Synthetic profile anchors
# --------------------------------------------------------------------------- #
@pytest.mark.regression
@pytest.mark.security
class TestSyntheticProfiles:
    def test_clean_app_profile_is_low(self, engine):
        # 0-2 low-confidence findings: nothing clears the confirmed threshold.
        clean = [
            _synthetic(AnalysisSeverity.LOW, 0.3),
            _synthetic(AnalysisSeverity.MEDIUM, 0.4),
        ]
        assert _headline(engine, clean) <= 15

    def test_empty_app_profile_is_zero(self, engine):
        assert _headline(engine, []) == 0.0

    def test_malware_profile_hits_critical_band(self, engine):
        # >=2 CONFIRMED CRITICAL findings at high confidence -> critical_floor path.
        malware = [
            _synthetic(AnalysisSeverity.CRITICAL, 0.9, title="c1"),
            _synthetic(AnalysisSeverity.CRITICAL, 0.85, title="c2"),
        ]
        assert _headline(engine, malware) >= 70
