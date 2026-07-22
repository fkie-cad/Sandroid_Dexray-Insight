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


@pytest.mark.unit
class TestMarkdownReportHonestyModel:
    """R9: the executive summary must mirror the console's confirmed-headline /
    review-queue honesty model (see FullAnalysisResults._print_security_assessment_summary)."""

    def test_executive_summary_shows_confirmed_headline(self):
        results = _results_dict()
        results["security_assessment"]["overall_risk_score"] = 42.0
        results["security_assessment"]["risk_score_confirmed"] = 42.0
        md = MarkdownSecurityReporter().generate(results)
        summary = md.split("## Executive Summary", 1)[1].split("## Top Risks", 1)[0]
        # Headline is the confirmed subset and labeled as such (not "all findings").
        assert "42.0/100" in summary
        assert "confirmed headline" in summary.lower()
        assert "confirmed-only" in summary

    def test_review_mass_is_surfaced_and_labeled_as_review_queue(self):
        results = _results_dict()
        results["security_assessment"]["risk_score_review_mass"] = 18.5
        md = MarkdownSecurityReporter().generate(results)
        summary = md.split("## Executive Summary", 1)[1].split("## Top Risks", 1)[0]
        assert "18.5" in summary
        assert "Review-queue weight (not in headline)" in summary
        assert "manual-review queue" in summary.lower()

    def test_needs_dynamic_finding_is_not_presented_as_confirmed(self):
        """A high-severity, high-confidence finding whose verification_status is
        NEEDS_DYNAMIC must land in the review queue, never the Confirmed tier."""
        results = _results_dict()
        dynamic_finding = _finding(
            "critical", 0.95, "Dynamic-Only Exploitable Path", category="A03:2021-Injection"
        )
        dynamic_finding["verification_status"] = "NEEDS_DYNAMIC"
        results["security_assessment"]["findings"].append(dynamic_finding)
        md = MarkdownSecurityReporter().generate(results)

        confirmed_block = md.split("## Confirmed", 1)[1].split("## Needs Manual Review", 1)[0]
        review_block = md.split("## Needs Manual Review", 1)[1].split("## All Findings", 1)[0]
        assert "Dynamic-Only Exploitable Path" not in confirmed_block
        assert "Dynamic-Only Exploitable Path" in review_block

    def test_needs_review_status_visible_in_all_findings_table(self):
        results = _results_dict()
        review_finding = _finding("high", 0.8, "Needs-Review Item", category="A03:2021-Injection")
        review_finding["verification_status"] = "NEEDS_REVIEW"
        results["security_assessment"]["findings"].append(review_finding)
        md = MarkdownSecurityReporter().generate(results)
        all_block = md.split("## All Findings", 1)[1]
        # The verification status column exists and the review item shows its status.
        assert "| Status |" in md or "Status |" in all_block
        review_row = [line for line in all_block.splitlines() if "Needs-Review Item" in line][0]
        assert "NEEDS_REVIEW" in review_row
