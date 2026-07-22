#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for WS5 manifest-facts data plumbing (PR-1).

Covers:
- ``get_manifest_facts`` merges apk_overview.general_info (SDK ints) with
  apk_overview.manifest_security, and returns unknown sentinels (never 0/True)
  when apk_overview is absent.
- ``SecurityMisconfigurationAssessment`` no longer emits the historical false
  positives ("Target SDK 0", "Backup is enabled", "No/Missing network security
  configuration") when the authoritative facts contradict them, and skips those
  findings entirely when the facts are unknown.
- The new APKOverviewResult fields survive a to_dict/from_dict round-trip.
"""

import pytest

from src.dexray_insight.core.base_classes import AnalysisStatus
from src.dexray_insight.modules.apk_overview_analysis import APKOverviewResult
from src.dexray_insight.security.manifest_facts import get_manifest_facts
from src.dexray_insight.security.security_misconfiguration_assessment import SecurityMisconfigurationAssessment


@pytest.fixture
def assessment():
    return SecurityMisconfigurationAssessment({})


def _all_evidence(findings):
    """Flatten all evidence strings across a list of SecurityFinding objects."""
    evidence = []
    for finding in findings:
        evidence.extend(finding.evidence or [])
    return evidence


class TestGetManifestFacts:
    """get_manifest_facts merges and guards against misleading defaults."""

    def test_merges_apk_overview_general_info_and_manifest_security(self):
        analysis_results = {
            "apk_overview": {
                "general_info": {"target_sdk": 36, "min_sdk": 24},
                "manifest_security": {
                    "allow_backup": False,
                    "network_security_config": "@xml/nsc",
                    "uses_cleartext_traffic": True,
                    "debuggable": False,
                },
            }
        }

        facts = get_manifest_facts(analysis_results)

        assert facts["target_sdk"] == 36
        assert facts["min_sdk"] == 24
        assert facts["network_security_config"] == "@xml/nsc"
        assert facts["network_security_config_known"] is True
        assert facts["allow_backup"] is False
        assert facts["uses_cleartext_traffic"] is True

    def test_missing_apk_overview_returns_unknown_sentinels_not_defaults(self):
        # No apk_overview and no manifest_analysis -> everything unknown.
        facts = get_manifest_facts({})

        assert facts["target_sdk"] is None
        assert facts["min_sdk"] is None
        assert facts["max_sdk"] is None
        # NEVER default to 0/True
        assert facts["allow_backup"] is None
        assert facts["target_sdk"] != 0
        assert facts["allow_backup"] is not True
        # Absence must be "unknown", not "known-absent"
        assert facts["network_security_config"] is None
        assert facts["network_security_config_known"] is False

    def test_accepts_baseresult_like_object_via_to_dict(self):
        overview = APKOverviewResult(
            module_name="apk_overview",
            status=AnalysisStatus.SUCCESS,
            general_info={"target_sdk": 30, "min_sdk": 21},
            manifest_security={
                "allow_backup": True,
                "network_security_config": None,
                "uses_cleartext_traffic": False,
                "debuggable": False,
            },
        )
        facts = get_manifest_facts({"apk_overview": overview})

        assert facts["target_sdk"] == 30
        assert facts["min_sdk"] == 21
        # NSC attribute absent but manifest was inspected -> known absence
        assert facts["network_security_config"] is None
        assert facts["network_security_config_known"] is True
        assert facts["allow_backup"] is True

    def test_thin_manifest_fallback_does_not_signal_known_nsc_absence(self):
        # apk_overview absent; thin manifest with SDK ints but no NSC -> NSC unknown.
        analysis_results = {
            "manifest_analysis": {
                "target_sdk_version": 33,
                "min_sdk_version": 24,
            }
        }
        facts = get_manifest_facts(analysis_results)

        assert facts["target_sdk"] == 33
        assert facts["min_sdk"] == 24
        assert facts["network_security_config_known"] is False


class TestSecurityMisconfigurationNoFalsePositives:
    """The assessment must not emit stale FPs when facts contradict them."""

    def test_no_sdk_backup_or_nsc_false_positives_but_flags_cleartext(self, assessment):
        analysis_results = {
            "apk_overview": {
                "general_info": {"target_sdk": 36, "min_sdk": 24},
                "manifest_security": {
                    "allow_backup": False,
                    "network_security_config": "@xml/nsc",
                    "uses_cleartext_traffic": True,
                    "debuggable": False,
                },
            },
            # An http:// endpoint drives the insecure-network (cleartext) finding.
            "string_analysis": {
                "all_strings": ["http://api.acmeapp.io/login"],
                "urls": ["http://api.acmeapp.io/login"],
                "domains": [],
            },
        }

        findings = assessment.assess(analysis_results)
        evidence = _all_evidence(findings)
        joined = " | ".join(evidence)

        # No stale false positives
        assert "Target SDK 0" not in joined
        assert "Target SDK version 0" not in joined
        assert "Minimum SDK version 0" not in joined
        assert not any("Backup is enabled" in e for e in evidence)
        assert not any("network security configuration detected" in e for e in evidence)
        assert not any("Missing network security configuration" in e for e in evidence)

        # Cleartext / insecure network IS flagged
        assert any("Insecure network configuration" in e for e in evidence)

    def test_unknown_facts_skip_findings_no_false_positive(self, assessment):
        # No apk_overview -> facts unknown -> SDK/backup/NSC findings skipped.
        analysis_results = {
            "string_analysis": {
                "all_strings": ["http://api.acmeapp.io/login"],
                "urls": ["http://api.acmeapp.io/login"],
                "domains": [],
            }
        }

        findings = assessment.assess(analysis_results)
        evidence = _all_evidence(findings)

        assert not any("Target SDK version" in e for e in evidence)
        assert not any("Minimum SDK version" in e for e in evidence)
        assert not any("Backup is enabled" in e for e in evidence)
        assert not any("network security configuration detected" in e for e in evidence)
        assert not any("Missing network security configuration" in e for e in evidence)

    def test_known_low_sdk_and_backup_still_flagged(self, assessment):
        analysis_results = {
            "apk_overview": {
                "general_info": {"target_sdk": 21, "min_sdk": 19},
                "manifest_security": {
                    "allow_backup": True,
                    "network_security_config": None,
                    "uses_cleartext_traffic": False,
                    "debuggable": False,
                },
            }
        }

        findings = assessment.assess(analysis_results)
        evidence = _all_evidence(findings)

        assert any("Target SDK version 21" in e for e in evidence)
        assert any("Minimum SDK version 19" in e for e in evidence)
        assert any("Backup is enabled" in e for e in evidence)
        assert any("Missing network security configuration" in e for e in evidence)


class TestAPKOverviewResultRoundTrip:
    """New additive fields survive to_dict/from_dict, tolerating missing keys."""

    def test_round_trip_preserves_new_fields(self):
        original = APKOverviewResult(
            module_name="apk_overview",
            status=AnalysisStatus.SUCCESS,
            general_info={"target_sdk": 36},
            browsable_activities={"com.example.Main": {"browsable": True}},
            network_security=[{"rule": "example"}],
            manifest_security={
                "allow_backup": False,
                "network_security_config": "@xml/nsc",
                "uses_cleartext_traffic": True,
                "debuggable": False,
            },
        )

        restored = APKOverviewResult.from_dict(original.to_dict())

        assert restored.browsable_activities == original.browsable_activities
        assert restored.network_security == original.network_security
        assert restored.manifest_security == original.manifest_security

    def test_from_dict_tolerates_missing_and_unknown_keys(self):
        data = {
            "module_name": "apk_overview",
            "status": "success",
            "general_info": {"target_sdk": 30},
            "some_unknown_key": "ignored",
        }

        restored = APKOverviewResult.from_dict(data)

        # Missing new keys fall back to dataclass defaults
        assert restored.browsable_activities == {}
        assert restored.manifest_security == {}
        assert restored.network_security == []
        assert restored.general_info == {"target_sdk": 30}
