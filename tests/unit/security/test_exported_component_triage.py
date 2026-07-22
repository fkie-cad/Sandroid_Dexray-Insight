#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for PR-4: exported-component triage + absence-heuristic demotion.

Covers:
- Package-allowlist classification (framework / first_party / unknown) and the
  BROWSABLE / custom-scheme spoof-resistance override.
- BrokenAccessControlAssessment down-ranking of framework-owned exported
  components while surfacing first-party and deep-link entry points.
- AuthenticationFailuresAssessment no longer emitting HIGH from a missing
  biometric permission.
- InsecureDesignAssessment collapsing the absence checklists into a single LOW
  posture finding.
"""

import pytest

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.security.authentication_failures_assessment import AuthenticationFailuresAssessment
from src.dexray_insight.security.broken_access_control_assessment import BrokenAccessControlAssessment
from src.dexray_insight.security.evidence import carries_browsable_or_custom_scheme
from src.dexray_insight.security.evidence import classify_component
from src.dexray_insight.security.evidence import should_downrank
from src.dexray_insight.security.insecure_design_assessment import InsecureDesignAssessment


# --------------------------------------------------------------------------- #
# package_allowlist unit tests
# --------------------------------------------------------------------------- #
class TestClassifyComponent:
    @pytest.mark.security
    @pytest.mark.unit
    def test_first_party_by_package_name(self):
        assert classify_component("kik.android.chat.MainActivity", package_name="kik.android") == "first_party"

    @pytest.mark.security
    @pytest.mark.unit
    def test_first_party_by_configured_prefix(self):
        assert classify_component("com.mycorp.Foo", first_party_prefixes=["com.mycorp."]) == "first_party"

    @pytest.mark.security
    @pytest.mark.unit
    def test_framework_prefixes(self):
        assert classify_component("androidx.work.impl.SystemForegroundService") == "framework"
        assert classify_component("com.google.firebase.messaging.FirebaseMessagingService") == "framework"
        assert classify_component("com.google.android.gms.measurement.AppMeasurementReceiver") == "framework"

    @pytest.mark.security
    @pytest.mark.unit
    def test_unknown_component(self):
        assert classify_component("net.example.thirdparty.Widget") == "unknown"

    @pytest.mark.security
    @pytest.mark.unit
    def test_first_party_wins_over_framework_prefix(self):
        # App legitimately namespaced under com.google.* is still its own code.
        assert (
            classify_component("com.google.internal.App", package_name="com.google.internal") == "first_party"
        )

    @pytest.mark.security
    @pytest.mark.unit
    def test_library_fingerprint_corroboration(self):
        libs = [{"package": "com.some.sdk"}]
        assert classify_component("com.some.sdk.EntryReceiver", library_results=libs) == "framework"

    @pytest.mark.security
    @pytest.mark.unit
    def test_should_downrank_only_framework(self):
        assert should_downrank("framework") is True
        assert should_downrank("first_party") is False
        assert should_downrank("unknown") is False


class TestBrowsableOverride:
    @pytest.mark.security
    @pytest.mark.unit
    def test_browsable_category_detected(self):
        ifs = [{"filters": {"action": ["android.intent.action.VIEW"], "category": ["android.intent.category.BROWSABLE"]}}]
        assert carries_browsable_or_custom_scheme(ifs) is True

    @pytest.mark.security
    @pytest.mark.unit
    def test_custom_scheme_detected(self):
        ifs = [{"filters": {"action": ["android.intent.action.VIEW"], "data": {"scheme": "kik"}}}]
        assert carries_browsable_or_custom_scheme(ifs) is True

    @pytest.mark.security
    @pytest.mark.unit
    def test_standard_scheme_not_flagged(self):
        ifs = [{"filters": {"data": {"scheme": "https"}}}]
        assert carries_browsable_or_custom_scheme(ifs) is False

    @pytest.mark.security
    @pytest.mark.unit
    def test_plain_default_filter_not_flagged(self):
        ifs = [{"filters": {"action": ["android.intent.action.VIEW"], "category": ["android.intent.category.DEFAULT"]}}]
        assert carries_browsable_or_custom_scheme(ifs) is False


# --------------------------------------------------------------------------- #
# BrokenAccessControlAssessment exported-component triage
# --------------------------------------------------------------------------- #
def _potentially_exported_findings(findings):
    return [f for f in findings if f.title.startswith("Potentially Exported")]


def _finding_for(findings, name_substring):
    for f in findings:
        if any(name_substring in ev for ev in f.evidence):
            return f
    return None


@pytest.fixture
def assessment():
    return BrokenAccessControlAssessment({})


class TestExportedComponentTriage:
    @pytest.mark.security
    @pytest.mark.unit
    def test_exported_false_service_produces_no_finding(self, assessment):
        """(a) exported=false service -> NO finding."""
        data = {
            "manifest_analysis": {
                "activities": [],
                "services": [
                    {
                        "name": "kik.android.SomeService",
                        "exported": False,
                        "permission": None,
                        "intent_filters": [{"filters": {"action": ["x"]}}],
                    }
                ],
                "receivers": [],
                "content_providers": [],
                "permissions": [],
                "intent_filters": [],
            }
        }
        findings = assessment.assess(data)
        service_findings = [
            f for f in findings if "kik.android.SomeService" in " ".join(f.evidence)
        ]
        assert service_findings == [], "exported=false service must not be flagged"

    @pytest.mark.security
    @pytest.mark.unit
    def test_permission_guarded_receiver_is_downranked(self, assessment):
        """(b) permission-guarded receiver -> low/low-confidence at most."""
        data = {
            "manifest_analysis": {
                "activities": [],
                "services": [],
                "receivers": [
                    {
                        "name": "net.example.GuardedReceiver",
                        "exported": None,
                        "permission": "android.permission.BIND_JOB_SERVICE",
                        "intent_filters": [{"filters": {"action": ["x"]}}],
                    }
                ],
                "content_providers": [],
                "permissions": [],
                "intent_filters": [],
            }
        }
        findings = assessment.assess(data)
        f = _finding_for(findings, "net.example.GuardedReceiver")
        if f is not None:
            assert f.severity == AnalysisSeverity.LOW
            assert f.confidence is not None and f.confidence <= 0.3

    @pytest.mark.security
    @pytest.mark.unit
    def test_first_party_deeplink_activity_is_surfaced(self, assessment):
        """(c) first-party activity with a kik:// scheme -> surfaced (not down-ranked)."""
        data = {
            "apk_overview": {"general_info": {"package_name": "kik.android"}},
            "manifest_analysis": {
                "activities": [
                    {
                        "name": "kik.android.deeplink.DeepLinkActivity",
                        "exported": None,
                        "permission": None,
                        "intent_filters": [
                            {
                                "filters": {
                                    "action": ["android.intent.action.VIEW"],
                                    "category": ["android.intent.category.BROWSABLE"],
                                    "data": {"scheme": "kik"},
                                }
                            }
                        ],
                    }
                ],
                "services": [],
                "receivers": [],
                "content_providers": [],
                "permissions": [],
                "intent_filters": [],
            },
        }
        findings = assessment.assess(data)
        f = _finding_for(findings, "kik.android.deeplink.DeepLinkActivity")
        assert f is not None, "first-party deep-link activity must be surfaced"
        assert f.severity == AnalysisSeverity.MEDIUM
        assert f.confidence == pytest.approx(0.6)

    @pytest.mark.security
    @pytest.mark.unit
    def test_framework_receiver_is_downranked(self, assessment):
        """(d) androidx/firebase exported receiver -> down-ranked LOW/low-confidence."""
        data = {
            "manifest_analysis": {
                "activities": [],
                "services": [],
                "receivers": [
                    {
                        "name": "androidx.work.impl.background.systemalarm.RescheduleReceiver",
                        "exported": None,
                        "permission": None,
                        "intent_filters": [
                            {"filters": {"action": ["android.intent.action.BOOT_COMPLETED"]}}
                        ],
                    },
                    {
                        "name": "com.google.firebase.iid.FirebaseInstanceIdReceiver",
                        "exported": True,
                        "permission": None,
                        "intent_filters": [{"filters": {"action": ["com.google.x"]}}],
                    },
                ],
                "content_providers": [],
                "permissions": [],
                "intent_filters": [],
            }
        }
        findings = assessment.assess(data)
        androidx_f = _finding_for(findings, "androidx.work.impl.background")
        assert androidx_f is not None
        assert androidx_f.severity == AnalysisSeverity.LOW
        assert androidx_f.confidence == pytest.approx(0.25)

        firebase_f = _finding_for(findings, "com.google.firebase.iid")
        assert firebase_f is not None
        assert firebase_f.severity == AnalysisSeverity.LOW
        assert firebase_f.confidence == pytest.approx(0.25)

    @pytest.mark.security
    @pytest.mark.unit
    def test_spoofed_google_component_with_browsable_is_surfaced(self, assessment):
        """(e) com.google.*-named component carrying BROWSABLE -> still surfaced."""
        data = {
            "manifest_analysis": {
                "activities": [
                    {
                        "name": "com.google.android.SpoofedActivity",
                        "exported": None,
                        "permission": None,
                        "intent_filters": [
                            {
                                "filters": {
                                    "action": ["android.intent.action.VIEW"],
                                    "category": ["android.intent.category.BROWSABLE"],
                                    "data": {"scheme": "evilscheme"},
                                }
                            }
                        ],
                    }
                ],
                "services": [],
                "receivers": [],
                "content_providers": [],
                "permissions": [],
                "intent_filters": [],
            }
        }
        findings = assessment.assess(data)
        f = _finding_for(findings, "com.google.android.SpoofedActivity")
        assert f is not None, "BROWSABLE component must be surfaced despite com.google.* name"
        assert f.severity == AnalysisSeverity.MEDIUM
        assert f.confidence == pytest.approx(0.6)


# --------------------------------------------------------------------------- #
# AuthenticationFailuresAssessment demotion
# --------------------------------------------------------------------------- #
class TestAuthenticationFailuresDemotion:
    @pytest.mark.security
    @pytest.mark.unit
    def test_missing_biometric_does_not_produce_high(self):
        assessment = AuthenticationFailuresAssessment({})
        data = {
            "string_analysis": {"all_strings": ["nothing interesting here"]},
            "manifest_analysis": {"permissions": ["android.permission.INTERNET"]},
        }
        findings = assessment.assess(data)
        assert all(f.severity != AnalysisSeverity.HIGH for f in findings), "missing biometric must not be HIGH"
        # A demoted LOW posture note is acceptable.
        posture = [f for f in findings if f.title == "Authentication Hardening Posture"]
        assert posture, "expected a demoted LOW posture note"
        assert posture[0].severity == AnalysisSeverity.LOW
        assert posture[0].confidence == pytest.approx(0.2)

    @pytest.mark.security
    @pytest.mark.unit
    def test_weak_credential_string_is_medium(self):
        assessment = AuthenticationFailuresAssessment({})
        data = {
            "string_analysis": {"all_strings": ['password = "123456"']},
            "manifest_analysis": {"permissions": ["android.permission.USE_BIOMETRIC"]},
        }
        findings = assessment.assess(data)
        weak = [f for f in findings if f.title == "Weak Authentication Mechanisms"]
        assert weak, "expected a weak-authentication finding for a concrete credential hit"
        assert weak[0].severity == AnalysisSeverity.MEDIUM
        assert weak[0].confidence == pytest.approx(0.5)

    @pytest.mark.security
    @pytest.mark.unit
    def test_session_finding_requires_concrete_signal(self):
        assessment = AuthenticationFailuresAssessment({})
        # A benign SessionManager mention with no concrete insecure signal.
        data = {
            "string_analysis": {"all_strings": ["com.example.SessionManager", "CookieManager"]},
            "manifest_analysis": {"permissions": ["android.permission.USE_BIOMETRIC"]},
        }
        findings = assessment.assess(data)
        session = [f for f in findings if f.title == "Insecure Session Management"]
        assert session == [], "no session finding without a concrete insecure signal"

    @pytest.mark.security
    @pytest.mark.unit
    def test_session_finding_on_setsecure_false(self):
        assessment = AuthenticationFailuresAssessment({})
        data = {
            "string_analysis": {"all_strings": ["cookie.setSecure(false)"]},
            "manifest_analysis": {"permissions": ["android.permission.USE_BIOMETRIC"]},
        }
        findings = assessment.assess(data)
        session = [f for f in findings if f.title == "Insecure Session Management"]
        assert session, "expected a session finding for setSecure(false)"
        assert session[0].severity == AnalysisSeverity.MEDIUM
        assert session[0].confidence == pytest.approx(0.5)


# --------------------------------------------------------------------------- #
# InsecureDesignAssessment posture collapse
# --------------------------------------------------------------------------- #
class TestInsecureDesignPostureCollapse:
    @pytest.mark.security
    @pytest.mark.unit
    def test_absence_only_input_produces_single_low_posture(self):
        assessment = InsecureDesignAssessment({})
        # No hardening controls, no insecure patterns -> only the posture finding.
        data = {
            "string_analysis": {"all_strings": ["com.example.MainActivity"]},
            "manifest_analysis": {"permissions": ["android.permission.INTERNET"]},
            "behaviour_analysis": {},
        }
        findings = assessment.assess(data)
        posture = [f for f in findings if f.title == "Security Hardening Posture"]
        assert len(posture) == 1, "expected exactly one hardening-posture finding"
        assert posture[0].severity == AnalysisSeverity.LOW
        assert posture[0].confidence == pytest.approx(0.2)

        # The old MEDIUM absence checklists must be gone.
        legacy_titles = {"Missing Security Controls", "Insufficient Threat Scenario Coverage"}
        assert not [f for f in findings if f.title in legacy_titles], "legacy MEDIUM absence findings must not be emitted"
