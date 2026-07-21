#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for BrokenAccessControlAssessment (OWASP A01:2021).

Covers the recently implemented fixes:
- Manifest component lists that are plain STRINGS (not dicts) are handled
  without crashing.
- Every SecurityFinding is constructed with a non-empty ``recommendations`` list.
- intent_filters entries in the real shape
  {"component_type","component_name","filters":{"action":[...],"category":[...]}}
  drive intent-filter-based export detection.
"""

import pytest

from src.dexray_insight.security.broken_access_control_assessment import BrokenAccessControlAssessment


@pytest.fixture
def assessment():
    return BrokenAccessControlAssessment({})


@pytest.fixture
def string_based_manifest_analysis():
    """Manifest data with plain-string component lists (the real upstream shape)."""
    return {
        "manifest_analysis": {
            "activities": ["com.example.MainActivity", "com.example.SettingsActivity"],
            "services": ["com.example.BackgroundService"],
            "receivers": ["com.example.BootReceiver"],
            "content_providers": ["com.example.DataProvider"],
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.WRITE_SECURE_SETTINGS",
                "android.permission.CAMERA",
            ],
            "intent_filters": [
                {
                    "component_type": "receiver",
                    "component_name": "com.example.BootReceiver",
                    "filters": {
                        "action": ["android.intent.action.VIEW"],
                        "category": ["android.intent.category.DEFAULT"],
                    },
                }
            ],
        }
    }


class TestBrokenAccessControlWithStringComponents:
    """Assessment must handle plain-string component lists gracefully."""

    @pytest.mark.security
    @pytest.mark.unit
    def test_assess_returns_list_and_does_not_raise(self, assessment, string_based_manifest_analysis):
        findings = assessment.assess(string_based_manifest_analysis)
        assert isinstance(findings, list)

    @pytest.mark.security
    @pytest.mark.unit
    def test_no_assessment_error_finding_produced(self, assessment, string_based_manifest_analysis):
        """The generic 'Assessment Error' finding indicates an unhandled crash."""
        findings = assessment.assess(string_based_manifest_analysis)
        titles = [f.title for f in findings]
        assert "Assessment Error" not in titles

    @pytest.mark.security
    @pytest.mark.unit
    def test_all_findings_have_required_fields(self, assessment, string_based_manifest_analysis):
        findings = assessment.assess(string_based_manifest_analysis)
        assert findings, "Expected at least one finding for this manifest"
        for finding in findings:
            assert finding.recommendations, f"Finding '{finding.title}' has empty recommendations"
            assert isinstance(finding.recommendations, list)
            assert finding.title
            assert finding.category
            assert finding.description

    @pytest.mark.security
    @pytest.mark.unit
    def test_dangerous_permission_finding_present(self, assessment, string_based_manifest_analysis):
        """WRITE_SECURE_SETTINGS should surface a dangerous-permissions finding."""
        findings = assessment.assess(string_based_manifest_analysis)
        dangerous = [f for f in findings if f.title == "Excessive Dangerous Permissions"]
        assert dangerous, "Expected a dangerous-permissions finding for WRITE_SECURE_SETTINGS"
        evidence_text = " ".join(dangerous[0].evidence)
        assert "WRITE_SECURE_SETTINGS" in evidence_text

    @pytest.mark.security
    @pytest.mark.unit
    def test_intent_filter_produces_potentially_exported_finding(self, assessment, string_based_manifest_analysis):
        """A receiver reachable via an intent filter should be flagged as potentially exported."""
        findings = assessment.assess(string_based_manifest_analysis)
        potentially_exported = [f for f in findings if f.title.startswith("Potentially Exported")]
        assert potentially_exported, "Expected a 'Potentially Exported' finding from the intent-filter path"
