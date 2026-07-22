#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PR-9 unit tests: MarkdownSecurityReporter.

Verifies the Markdown report renders the expected sections from both a plain dict
and a light object, is resilient to missing sections, and delegates ranking/tiering
to risk_ranking (Top Risks ordered by severity × confidence, tier tables present).
"""

import pytest

from src.dexray_insight.results.reporting.markdown_report import MarkdownSecurityReporter


def _finding(severity, confidence, title, category="A02:2021-Cryptographic Failures", evidence=None):
    return {
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "category": category,
        "evidence": evidence or [f"evidence for {title}"],
        "recommendations": ["Do the thing"],
    }


def _results_dict():
    return {
        "apk_overview": {
            "general_info": {
                "package_name": "com.example.app",
                "app_name": "Example",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "a" * 64,
                "target_sdk": 34,
                "min_sdk": 24,
            }
        },
        "security_assessment": {
            "overall_risk_score": 75.0,
            "risk_score_confirmed": 75.0,
            "risk_score_version": 2,
            "total_findings": 4,
            "findings_by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 1},
            "owasp_categories_affected": ["A02:2021-Cryptographic Failures", "A03:2021-Injection"],
            "summary": {"total_assessments_run": 11, "total_assessments_failed": 0},
            "findings": [
                _finding("critical", 0.9, "Hard-coded AWS Secret"),
                _finding("high", 0.7, "SQL Injection Risk", category="A03:2021-Injection"),
                _finding("medium", 0.5, "WebView JavaScript Bridge Exposure", category="A05"),
                _finding("low", 0.2, "Authentication Hardening Posture", category="A07"),
            ],
        },
    }


@pytest.mark.unit
class TestMarkdownReport:
    def test_renders_all_core_sections(self):
        md = MarkdownSecurityReporter().generate(_results_dict())
        assert "# Security Report: Example" in md
        assert "## Executive Summary" in md
        assert "## Top Risks" in md
        assert "## Confirmed" in md
        assert "## Needs Manual Review" in md
        assert "## All Findings" in md
        assert "## Scan Metadata" in md

    def test_header_includes_hashes_and_sdk(self):
        md = MarkdownSecurityReporter().generate(_results_dict())
        assert "d41d8cd98f00b204e9800998ecf8427e" in md
        assert "34" in md  # target sdk
        assert "com.example.app" in md

    def test_executive_summary_has_score_pair_and_triage_label(self):
        md = MarkdownSecurityReporter().generate(_results_dict())
        assert "75.0/100" in md
        assert "confirmed-only" in md
        assert "triage aid" in md.lower()

    def test_top_risks_ordered_by_value(self):
        md = MarkdownSecurityReporter().generate(_results_dict())
        # The CRITICAL secret (10 × 0.9) must appear before the LOW posture note.
        assert md.index("Hard-coded AWS Secret") < md.index("Authentication Hardening Posture")

    def test_top_risks_include_evidence_and_hint(self):
        md = MarkdownSecurityReporter().generate(_results_dict())
        assert "Evidence:" in md
        assert "Why it matters:" in md

    def test_confirmed_tier_contains_high_confidence_high_severity(self):
        md = MarkdownSecurityReporter().generate(_results_dict())
        confirmed_block = md.split("## Confirmed", 1)[1].split("## Needs Manual Review", 1)[0]
        assert "Hard-coded AWS Secret" in confirmed_block  # crit conf 0.9
        assert "Authentication Hardening Posture" not in confirmed_block  # low

    def test_informational_appendix_present_for_low_findings(self):
        md = MarkdownSecurityReporter().generate(_results_dict())
        assert "Suppressed / Informational" in md
        info_block = md.split("Suppressed / Informational", 1)[1]
        assert "Authentication Hardening Posture" in info_block

    def test_top_n_config_limits_top_risks(self):
        md = MarkdownSecurityReporter(top_n=1).generate(_results_dict())
        top_block = md.split("## Top Risks", 1)[1].split("## Confirmed", 1)[0]
        # Only one numbered entry.
        assert top_block.count("### 1.") == 1
        assert "### 2." not in top_block

    def test_no_security_assessment_is_graceful(self):
        md = MarkdownSecurityReporter().generate({"apk_overview": {"general_info": {"app_name": "X"}}})
        assert "# Security Report: X" in md
        assert "No security assessment was performed" in md

    def test_accepts_object_with_attributes(self):
        class _Results:
            apk_overview = {"general_info": {"app_name": "ObjApp"}}
            security_assessment = _results_dict()["security_assessment"]

        md = MarkdownSecurityReporter().generate(_Results())
        assert "ObjApp" in md
        assert "Hard-coded AWS Secret" in md

    def test_pipe_in_title_is_escaped_in_tables(self):
        results = _results_dict()
        results["security_assessment"]["findings"].append(
            _finding("medium", 0.5, "Weird | Title | With Pipes", category="A05")
        )
        md = MarkdownSecurityReporter().generate(results)
        assert "Weird \\| Title \\| With Pipes" in md
