#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) {{ year }} Dexray Insight Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Phase B6: cross-finding cleartext correlation in the post-processing pass.

Assessments run in isolation and never see one another's findings, so the manifest
cleartext-traffic fact is correlated with sibling PII / WebView-bridge findings here,
after the full finding list is known. Covers:
* PII arm -> one HIGH "Cleartext PII Transmission" CONFIRMED finding,
* bridge arm -> one HIGH "Cleartext Content Into WebView" NEEDS_DYNAMIC finding,
* uses_cleartext_traffic not True -> no correlated finding,
* missing / malformed inputs -> no crash,
* idempotency (running twice appends nothing new),
* the P4 ground-truth target.
"""

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.core.base_classes import SecurityFinding
from src.dexray_insight.core.base_classes import VerificationStatus
from src.dexray_insight.security.finding_postprocessor import FindingPostProcessor

MISCONFIG_CATEGORY = "A05:2021-Security Misconfiguration"
PII_CATEGORY = "PRIVACY:2024-Personal Data Exposure"
UPLOAD_URL = "http://profilepicsup.piranhakik.com/profilepics"


def _analysis_results(cleartext=True, urls=None):
    """Build synthetic analysis_results with a manifest cleartext fact + URLs."""
    return {
        "apk_overview": {"manifest_security": {"uses_cleartext_traffic": cleartext}},
        "string_analysis": {"urls": urls if urls is not None else [UPLOAD_URL]},
    }


def _pii_finding():
    return SecurityFinding(
        category=PII_CATEGORY,
        severity=AnalysisSeverity.MEDIUM,
        title="Personal Data Exposure: email",
        description="d",
        evidence=["user@example.com"],
        recommendations=["r"],
    )


def _bridge_finding():
    return SecurityFinding(
        category="OWASP Mobile Top 10",
        severity=AnalysisSeverity.HIGH,
        title="WebView Reflection/Prompt JavaScript Bridge",
        description="d",
        evidence=["Bridge dispatch markers: CardsBridge"],
        recommendations=["r"],
    )


def _m1_webview_finding():
    """M1 Improper Platform Usage finding that lists WebView APIs in evidence."""
    return SecurityFinding(
        category="OWASP Mobile Top 10",
        severity=AnalysisSeverity.MEDIUM,
        title="Improper Platform Usage",
        description="d",
        evidence=["WebView.addJavascriptInterface", "setJavaScriptEnabled"],
        recommendations=["r"],
    )


def _correlated(findings):
    """Return correlated A05 findings from a result list."""
    return [f for f in findings if f.category == MISCONFIG_CATEGORY]


class TestPiiArm:
    def test_pii_arm_emits_high_confirmed(self):
        findings = [_pii_finding()]
        result = FindingPostProcessor()._apply_cleartext_correlation(findings, _analysis_results())

        correlated = _correlated(result)
        assert len(correlated) == 1
        f = correlated[0]
        assert f.title == "Cleartext PII Transmission"
        assert f.severity == AnalysisSeverity.HIGH
        assert f.confidence == 0.7
        assert f.verification_status == VerificationStatus.CONFIRMED
        assert UPLOAD_URL in f.evidence
        assert "usesCleartextTraffic=true" in f.evidence
        assert any("PII finding" in e for e in f.evidence)

    def test_p4_ground_truth_target(self):
        """usesCleartextTraffic=true + profilepics upload + PII -> one HIGH CONFIRMED."""
        results = _analysis_results(urls=[UPLOAD_URL])
        findings = [_pii_finding()]
        out = FindingPostProcessor()._apply_cleartext_correlation(findings, results)

        correlated = _correlated(out)
        assert len(correlated) == 1
        assert correlated[0].title == "Cleartext PII Transmission"
        assert correlated[0].verification_status == VerificationStatus.CONFIRMED


class TestBridgeArm:
    def test_bridge_arm_emits_high_needs_dynamic(self):
        # No upload URL, so the PII arm cannot fire; the bridge arm takes over.
        findings = [_bridge_finding()]
        result = FindingPostProcessor()._apply_cleartext_correlation(
            findings, _analysis_results(urls=["http://cdn.example.com/static.js"])
        )

        correlated = _correlated(result)
        assert len(correlated) == 1
        f = correlated[0]
        assert f.title == "Cleartext Content Into WebView"
        assert f.severity == AnalysisSeverity.HIGH
        assert f.confidence == 0.6
        assert f.verification_status == VerificationStatus.NEEDS_DYNAMIC

    def test_m1_webview_evidence_matches_bridge_arm(self):
        findings = [_m1_webview_finding()]
        result = FindingPostProcessor()._apply_cleartext_correlation(
            findings, _analysis_results(urls=[])
        )
        assert len(_correlated(result)) == 1

    def test_pii_arm_wins_over_bridge_when_both_present(self):
        findings = [_pii_finding(), _bridge_finding()]
        result = FindingPostProcessor()._apply_cleartext_correlation(findings, _analysis_results())

        correlated = _correlated(result)
        assert len(correlated) == 1
        assert correlated[0].title == "Cleartext PII Transmission"


class TestUploadOnlyArm:
    def test_upload_only_emits_medium_confirmed(self):
        # Cleartext upload URL but no PII/bridge finding -> optional MEDIUM finding.
        result = FindingPostProcessor()._apply_cleartext_correlation([], _analysis_results())
        correlated = _correlated(result)
        assert len(correlated) == 1
        f = correlated[0]
        assert f.title == "Cleartext Upload Endpoint"
        assert f.severity == AnalysisSeverity.MEDIUM
        assert f.verification_status == VerificationStatus.CONFIRMED


class TestNoFire:
    def test_cleartext_false_no_finding(self):
        result = FindingPostProcessor()._apply_cleartext_correlation(
            [_pii_finding()], _analysis_results(cleartext=False)
        )
        assert _correlated(result) == []

    def test_cleartext_unknown_no_finding(self):
        # No manifest_security dict -> uses_cleartext_traffic stays None (unknown).
        results = {"string_analysis": {"urls": [UPLOAD_URL]}}
        result = FindingPostProcessor()._apply_cleartext_correlation([_pii_finding()], results)
        assert _correlated(result) == []

    def test_non_upload_url_with_pii_no_pii_arm(self):
        # Cleartext http but path is not an upload -> PII arm cannot fire.
        results = _analysis_results(urls=["http://ads.example.com/track"])
        result = FindingPostProcessor()._apply_cleartext_correlation([_pii_finding()], results)
        assert _correlated(result) == []

    def test_local_upload_url_ignored(self):
        results = _analysis_results(urls=["http://127.0.0.1/upload"])
        result = FindingPostProcessor()._apply_cleartext_correlation([_pii_finding()], results)
        assert _correlated(result) == []


class TestRobustness:
    def test_missing_string_analysis_no_crash(self):
        results = {"apk_overview": {"manifest_security": {"uses_cleartext_traffic": True}}}
        result = FindingPostProcessor()._apply_cleartext_correlation([_pii_finding()], results)
        # Cleartext known True but no upload URL and no bridge -> nothing emitted.
        assert _correlated(result) == []

    def test_empty_inputs_no_crash(self):
        assert FindingPostProcessor()._apply_cleartext_correlation([], {}) == []

    def test_malformed_urls_no_crash(self):
        results = _analysis_results(urls="not-a-list")
        result = FindingPostProcessor()._apply_cleartext_correlation([_pii_finding()], results)
        assert _correlated(result) == []


class TestIdempotency:
    def test_running_twice_appends_nothing(self):
        processor = FindingPostProcessor()
        results = _analysis_results()
        findings = [_pii_finding()]

        first = processor._apply_cleartext_correlation(findings, results)
        assert len(_correlated(first)) == 1

        second = processor._apply_cleartext_correlation(first, results)
        assert len(_correlated(second)) == 1


class TestThroughProcess:
    def test_correlation_runs_within_process(self):
        config = {
            "enabled": True,
            "dedup": {"enabled": True, "merge_across_categories": True},
        }
        processor = FindingPostProcessor()
        result = processor.process([_pii_finding()], _analysis_results(), config)

        correlated = _correlated(result)
        assert len(correlated) == 1
        assert correlated[0].title == "Cleartext PII Transmission"
