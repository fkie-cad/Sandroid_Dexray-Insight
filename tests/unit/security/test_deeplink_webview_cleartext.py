#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for PR-8: IPC / WebView attack-surface detection.

Covers the three new detectors:

- ``BrokenAccessControlAssessment._assess_exported_deeplink_activities`` - exported
  browsable / deep-link activities that lack permission protection, with
  first-party vs framework triage, catch-all and custom-scheme escalation, and
  spoof-resistance for framework-named deep-link entry points.
- ``SecurityMisconfigurationAssessment._assess_webview_js_bridges`` - one MEDIUM
  finding summarising real addJavascriptInterface / setJavaScriptEnabled counts.
- ``SecurityMisconfigurationAssessment._assess_cleartext_traffic`` - manifest
  usesCleartextTraffic=True feeding first-party http:// endpoints (unknown/False
  sentinels suppress the finding).
"""

import pytest

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.security.broken_access_control_assessment import BrokenAccessControlAssessment
from src.dexray_insight.security.security_misconfiguration_assessment import SecurityMisconfigurationAssessment


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _deeplink_findings(analysis_data):
    assessment = BrokenAccessControlAssessment({})
    return assessment._assess_exported_deeplink_activities(analysis_data)


def _find_deeplink(findings, activity_name):
    for f in findings:
        if activity_name in (f.description or "") or any(activity_name in e for e in (f.evidence or [])):
            return f
    return None


# --------------------------------------------------------------------------- #
# Deep-link detection
# --------------------------------------------------------------------------- #
class TestExportedDeeplinkActivities:
    @pytest.mark.security
    @pytest.mark.unit
    def test_first_party_custom_scheme_flagged_medium(self):
        analysis_data = {
            "apk_overview": {
                "general_info": {"package_name": "kik.android"},
                "components": {
                    "exported_activities": ["kik.android.chat.KikApiLandingActivity"],
                },
                "browsable_activities": {
                    "kik.android.chat.KikApiLandingActivity": {
                        "schemes": ["kik://", "kik://age-verification", "kik://screen"],
                        "hosts": [],
                        "paths": [],
                    }
                },
            }
        }
        findings = _deeplink_findings(analysis_data)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == AnalysisSeverity.MEDIUM
        assert f.confidence == 0.7
        # Custom scheme mentioned in description
        assert "kik://" in f.description

    @pytest.mark.security
    @pytest.mark.unit
    def test_catch_all_no_scheme_flagged_with_note(self):
        analysis_data = {
            "apk_overview": {
                "general_info": {"package_name": "kik.android"},
                "components": {
                    "exported_activities": ["kik.android.deeplinks.InternalDeeplinkActivity"],
                },
                "browsable_activities": {
                    # Catch-all VIEW+BROWSABLE with no <data> scheme.
                    "kik.android.deeplinks.InternalDeeplinkActivity": {
                        "schemes": [],
                        "categories": ["android.intent.category.BROWSABLE"],
                    }
                },
            }
        }
        findings = _deeplink_findings(analysis_data)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == AnalysisSeverity.MEDIUM
        assert f.confidence == 0.7
        assert "catch-all" in f.description.lower()

    @pytest.mark.security
    @pytest.mark.unit
    def test_non_exported_browsable_not_flagged(self):
        analysis_data = {
            "apk_overview": {
                "general_info": {"package_name": "kik.android"},
                "components": {"exported_activities": []},  # not exported
                "browsable_activities": {
                    "kik.android.chat.InternalOnly": {"schemes": ["kik://"]}
                },
            }
        }
        findings = _deeplink_findings(analysis_data)
        assert findings == []

    @pytest.mark.security
    @pytest.mark.unit
    def test_permission_guarded_downranked_not_medium(self):
        analysis_data = {
            "apk_overview": {
                "general_info": {"package_name": "kik.android"},
                "components": {
                    "exported_activities": ["kik.android.chat.GuardedActivity"],
                },
                "browsable_activities": {
                    "kik.android.chat.GuardedActivity": {
                        "schemes": ["kik://"],
                        "permission": "kik.android.permission.PRIVATE",
                    }
                },
            }
        }
        findings = _deeplink_findings(analysis_data)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity != AnalysisSeverity.MEDIUM
        assert f.severity == AnalysisSeverity.LOW

    @pytest.mark.security
    @pytest.mark.unit
    def test_framework_named_deeplink_still_surfaced(self):
        # Spoof resistance: a com.google.* named browsable exported activity is
        # still surfaced (never suppressed by the SDK allowlist), just at LOW.
        analysis_data = {
            "apk_overview": {
                "general_info": {"package_name": "kik.android"},
                "components": {
                    "exported_activities": ["com.google.fake.SpoofedDeeplinkActivity"],
                },
                "browsable_activities": {
                    "com.google.fake.SpoofedDeeplinkActivity": {"schemes": ["evilscheme://"]}
                },
            }
        }
        findings = _deeplink_findings(analysis_data)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == AnalysisSeverity.LOW
        assert f.confidence == 0.3

    @pytest.mark.security
    @pytest.mark.unit
    def test_no_apk_overview_is_noop(self):
        assert _deeplink_findings({}) == []

    @pytest.mark.security
    @pytest.mark.unit
    def test_deeplink_wired_into_main_assess(self):
        analysis_data = {
            "apk_overview": {
                "general_info": {"package_name": "kik.android"},
                "components": {"exported_activities": ["kik.android.chat.KikApiLandingActivity"]},
                "browsable_activities": {
                    "kik.android.chat.KikApiLandingActivity": {"schemes": ["kik://"]}
                },
            }
        }
        assessment = BrokenAccessControlAssessment({})
        findings = assessment.assess(analysis_data)
        titles = [f.title for f in findings]
        assert "Exported Deep-Link Activity Without Permission Protection" in titles


# --------------------------------------------------------------------------- #
# WebView JS-bridge detection
# --------------------------------------------------------------------------- #
class TestWebViewJsBridges:
    @pytest.fixture
    def assessment(self):
        return SecurityMisconfigurationAssessment({})

    @pytest.mark.security
    @pytest.mark.unit
    def test_counts_smali_and_dotted_forms_single_finding(self, assessment):
        api_calls = []
        # 3 addJavascriptInterface (mix of smali + dotted)
        for _ in range(2):
            api_calls.append(
                {"called_class": "Landroid/webkit/WebView;", "called_method": "addJavascriptInterface"}
            )
        api_calls.append(
            {"called_class": "android.webkit.WebView", "called_method": "addJavascriptInterface"}
        )
        # 4 setJavaScriptEnabled
        for _ in range(4):
            api_calls.append(
                {"called_class": "Landroid/webkit/WebSettings;", "called_method": "setJavaScriptEnabled"}
            )
        analysis_data = {"api_invocation": {"api_calls": api_calls}}

        findings = assessment._assess_webview_js_bridges(analysis_data)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == AnalysisSeverity.MEDIUM
        assert f.confidence == 0.6
        joined = " ".join(f.evidence)
        assert "addJavascriptInterface ×3" in joined
        assert "setJavaScriptEnabled ×4" in joined

    @pytest.mark.security
    @pytest.mark.unit
    def test_no_webview_calls_no_finding(self, assessment):
        analysis_data = {
            "api_invocation": {
                "api_calls": [
                    {"called_class": "Landroid/util/Log;", "called_method": "d"},
                ]
            }
        }
        assert assessment._assess_webview_js_bridges(analysis_data) == []

    @pytest.mark.security
    @pytest.mark.unit
    def test_missing_api_invocation_no_finding(self, assessment):
        assert assessment._assess_webview_js_bridges({}) == []


# --------------------------------------------------------------------------- #
# Cleartext-into-WebView detection
# --------------------------------------------------------------------------- #
class TestCleartextTraffic:
    @pytest.fixture
    def assessment(self):
        return SecurityMisconfigurationAssessment({})

    def _base(self, cleartext_value):
        return {
            "apk_overview": {
                "general_info": {"package_name": "kik.android"},
                "manifest_security": {
                    "uses_cleartext_traffic": cleartext_value,
                    "network_security_config": None,
                    "allow_backup": False,
                    "debuggable": False,
                },
            },
            "string_analysis": {"urls": ["http://kik.example/api/login", "https://safe.example/x"]},
        }

    @pytest.mark.security
    @pytest.mark.unit
    def test_true_with_first_party_http_flagged_medium(self, assessment):
        findings = assessment._assess_cleartext_traffic(self._base(True))
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == AnalysisSeverity.MEDIUM
        assert f.confidence == 0.7
        assert any("kik.example" in e for e in f.evidence)

    @pytest.mark.security
    @pytest.mark.unit
    def test_escalates_when_webview_js_present(self, assessment):
        analysis_data = self._base(True)
        analysis_data["api_invocation"] = {
            "api_calls": [
                {"called_class": "Landroid/webkit/WebSettings;", "called_method": "setJavaScriptEnabled"}
            ]
        }
        findings = assessment._assess_cleartext_traffic(analysis_data)
        assert len(findings) == 1
        assert findings[0].title == "Cleartext Content Into WebView"

    @pytest.mark.security
    @pytest.mark.unit
    def test_unknown_sentinel_none_no_finding(self, assessment):
        assert assessment._assess_cleartext_traffic(self._base(None)) == []

    @pytest.mark.security
    @pytest.mark.unit
    def test_false_no_finding(self, assessment):
        assert assessment._assess_cleartext_traffic(self._base(False)) == []

    @pytest.mark.security
    @pytest.mark.unit
    def test_no_first_party_http_no_finding(self, assessment):
        analysis_data = self._base(True)
        analysis_data["string_analysis"] = {"urls": ["https://kik.example/api"]}  # https only
        assert assessment._assess_cleartext_traffic(analysis_data) == []
