#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PR-9 tests: analyst-summary TOP RISKS + triage tiers in FullAnalysisResults.

The old severity-only "Key Findings" block is replaced by a ranked TOP RISKS
section plus Confirmed / Needs-review / Informational tiers. The informational
tier is collapsed to a one-line notice unless verbose=True.
"""

import io
from contextlib import redirect_stdout

import pytest

from src.dexray_insight.results.FullAnalysisResults import FullAnalysisResults


def _security_assessment():
    def f(sev, conf, title, category="A02:2021-Cryptographic Failures"):
        return {
            "severity": sev,
            "confidence": conf,
            "title": title,
            "category": category,
            "evidence": [f"evidence for {title}"],
            "recommendations": ["Fix it"],
        }

    return {
        "overall_risk_score": 75.0,
        "risk_score_confirmed": 75.0,
        "total_findings": 4,
        "findings_by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 1},
        "owasp_categories_affected": ["A02:2021-Cryptographic Failures"],
        "findings": [
            f("critical", 0.9, "Hard-coded AWS Secret"),
            f("high", 0.7, "SQL Injection Risk", "A03:2021-Injection"),
            f("medium", 0.5, "WebView JavaScript Bridge Exposure", "A05"),
            f("low", 0.2, "Authentication Hardening Posture", "A07"),
        ],
    }


def _capture(results, **kwargs):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        results.print_analyst_summary(**kwargs)
    return buffer.getvalue()


@pytest.fixture
def results():
    r = FullAnalysisResults()
    r.security_assessment = _security_assessment()
    return r


@pytest.mark.unit
class TestAnalystSummaryTiers:
    def test_no_args_still_works(self, results):
        # Backward compatibility: the historical no-arg call must not raise.
        out = _capture(results)
        assert "TOP RISKS" in out

    def test_top_risks_section_present_and_ranked(self, results):
        out = _capture(results)
        assert "TOP RISKS" in out
        assert out.index("Hard-coded AWS Secret") < out.index("Authentication Hardening Posture")

    def test_score_pair_labelled_triage_aid(self, results):
        out = _capture(results)
        assert "triage aid" in out.lower()
        assert "confirmed-only" in out

    def test_confirmed_and_review_tiers_shown(self, results):
        out = _capture(results)
        assert "CONFIRMED" in out
        assert "NEEDS MANUAL REVIEW" in out

    def test_informational_hidden_by_default_with_notice(self, results):
        out = _capture(results, verbose=False)
        assert "hidden — rerun with -v" in out
        # The low-confidence posture note is not printed in full when hidden.
        assert "INFORMATIONAL / LOW-CONFIDENCE" not in out

    def test_informational_shown_when_verbose(self, results):
        out = _capture(results, verbose=True)
        assert "INFORMATIONAL / LOW-CONFIDENCE" in out
        assert "Authentication Hardening Posture" in out

    def test_top_n_respected_from_config_dict(self, results):
        config = {"output": {"security_report": {"top_n": 1}}}
        out = _capture(results, config=config)
        top_block = out.split("TOP RISKS", 1)[1].split("CONFIRMED", 1)[0]
        assert "1. [" in top_block
        assert "2. [" not in top_block

    def test_evidence_and_hint_in_top_risks(self, results):
        out = _capture(results)
        top_block = out.split("TOP RISKS", 1)[1]
        assert "evidence:" in top_block
        assert "→" in top_block
