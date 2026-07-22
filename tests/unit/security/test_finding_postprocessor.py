#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) {{ year }} Dexray Insight Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""PR-7: finding post-processing (false-positive confidence pass + dedup).

Covers:
* disabled gate returns findings unchanged,
* FP false-negative guards (dev/staging/localhost/structural secrets not suppressed;
  genuine placeholders downgraded),
* confidence combination (severity untouched),
* cross-assessment dedup (merge across categories; count-buckets not cross-merged),
* perf bound on the surrounding-context scan.
"""

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.core.base_classes import FileLocation
from src.dexray_insight.core.base_classes import SecurityFinding
from src.dexray_insight.security.context_analysis.code_context_analyzer import CodeContextAnalyzer
from src.dexray_insight.security.context_analysis.false_positive_filter import FalsePositiveFilter
from src.dexray_insight.security.finding_postprocessor import FindingPostProcessor

SECRET_CATEGORY = "A02:2021-Cryptographic Failures"


def _secret_finding(value, severity=AnalysisSeverity.HIGH, confidence=None, ftype="Generic Secret", **ad):
    """Build a secret SecurityFinding carrying a value in additional_data."""
    additional = {"value": value, "type": ftype}
    additional.update(ad)
    return SecurityFinding(
        category=SECRET_CATEGORY,
        severity=severity,
        title=f"Secret: {ftype}",
        description="test",
        evidence=[value],
        recommendations=["rotate"],
        confidence=confidence,
        additional_data=additional,
    )


def _config(enabled=True, **overrides):
    cfg = {
        "enabled": enabled,
        "allow_severity_downgrade": True,
        "max_context_strings": 5000,
        "false_positive": {"downgrade_high_threshold": 0.8, "downgrade_medium_threshold": 0.5},
        "dedup": {"enabled": True, "merge_across_categories": True},
    }
    cfg.update(overrides)
    return cfg


class TestDisabledGate:
    def test_disabled_returns_findings_unchanged(self):
        findings = [_secret_finding("your_api_key_here")]
        processor = FindingPostProcessor()
        result = processor.process(findings, {}, _config(enabled=False))
        assert result is findings
        # No mutation of confidence or additional_data occurred.
        assert result[0].confidence is None
        assert "fp_probability" not in result[0].additional_data

    def test_empty_config_returns_findings_unchanged(self):
        findings = [_secret_finding("your_api_key_here")]
        processor = FindingPostProcessor()
        assert processor.process(findings, {}, {}) is findings
        assert processor.process(findings, {}, None) is findings


class TestFalseNegativeGuards:
    def test_localhost_not_downgraded_to_near_zero(self):
        finding = _secret_finding("127.0.0.1", severity=AnalysisSeverity.HIGH, confidence=0.6)
        processor = FindingPostProcessor()
        processor.process([finding], {}, _config())
        fp = finding.additional_data["fp_probability"]
        assert fp < 0.5, f"127.0.0.1 wrongly treated as placeholder (fp={fp})"
        assert finding.confidence > 0.3

    def test_staging_url_not_downgraded_to_near_zero(self):
        finding = _secret_finding(
            "https://staging.api.example.com", severity=AnalysisSeverity.HIGH, confidence=0.6
        )
        processor = FindingPostProcessor()
        processor.process([finding], {}, _config())
        fp = finding.additional_data["fp_probability"]
        assert fp < 0.5, f"staging URL wrongly suppressed (fp={fp})"

    def test_structural_aws_key_never_downgraded(self):
        finding = _secret_finding(
            "AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
            severity=AnalysisSeverity.CRITICAL,
            confidence=0.9,
            ftype="AWS Access Key",
        )
        processor = FindingPostProcessor()
        processor.process([finding], {}, _config())
        assert finding.additional_data["fp_probability"] == 0.0
        assert finding.confidence == 0.9  # unchanged: 0.9 * (1 - 0.0)
        assert "adjusted_severity" not in finding.additional_data
        assert finding.severity == AnalysisSeverity.CRITICAL

    def test_genuine_placeholder_is_downgraded(self):
        finding = _secret_finding("your_api_key_here", severity=AnalysisSeverity.HIGH, confidence=0.6)
        processor = FindingPostProcessor()
        processor.process([finding], {}, _config())
        fp = finding.additional_data["fp_probability"]
        assert fp > 0.5, f"genuine placeholder not flagged (fp={fp})"
        assert finding.confidence < 0.6  # confidence reduced by the FP signal


class TestConfidenceCombination:
    def test_confidence_combination_and_severity_untouched(self):
        # A clean value with no false-positive indicators yields the base FP
        # probability of 0.1, so 0.9 * (1 - 0.1) == 0.81. ``type`` deliberately omits
        # secret keywords so the entropy indicator is not triggered.
        f = _secret_finding(
            "genericvalueABCD1234", severity=AnalysisSeverity.HIGH, confidence=0.9, ftype="Generic Value"
        )
        processor = FindingPostProcessor()
        processor.process([f], {}, _config())

        assert f.additional_data["fp_probability"] == 0.1
        assert f.confidence == 0.81
        assert f.severity == AnalysisSeverity.HIGH  # severity never mutated


class TestDedup:
    def test_cross_category_merge(self):
        # Structural value -> FP pass leaves confidence intact, isolating the merge.
        secret = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
        loc = FileLocation(uri="file:///app/Secret.java", start_line=10)
        a = SecurityFinding(
            category="A02:2021-Cryptographic Failures",
            severity=AnalysisSeverity.MEDIUM,
            title="Hardcoded secret",
            description="d",
            evidence=[secret],
            recommendations=["rotate"],
            confidence=0.5,
            additional_data={"value": secret},
            file_location=loc,
        )
        b = SecurityFinding(
            category="A05:2021-Security Misconfiguration",
            severity=AnalysisSeverity.HIGH,
            title="Hardcoded secret",
            description="d",
            evidence=[secret, "extra evidence"],
            recommendations=["remove"],
            confidence=0.8,
            additional_data={"value": secret},
            file_location=FileLocation(uri="file:///app/Secret.java", start_line=10),
        )
        processor = FindingPostProcessor()
        result = processor.process([a, b], {}, _config())

        assert len(result) == 1
        merged = result[0]
        assert merged.severity == AnalysisSeverity.HIGH  # max severity
        assert merged.confidence == 0.8  # max confidence
        assert "extra evidence" in merged.evidence
        assert "rotate" in merged.recommendations and "remove" in merged.recommendations
        merged_titles = {m["category"] for m in merged.additional_data["merged_from"]}
        assert merged_titles == {"A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"}

    def test_count_buckets_not_cross_merged(self):
        crit = SecurityFinding(
            category="A02:2021-Cryptographic Failures",
            severity=AnalysisSeverity.CRITICAL,
            title="🔴 CRITICAL: 5 Hard-coded Secrets Found",
            description="d",
            evidence=["s1"],
            recommendations=["r"],
        )
        high = SecurityFinding(
            category="A02:2021-Cryptographic Failures",
            severity=AnalysisSeverity.HIGH,
            title="🟠 HIGH: 5 Hard-coded Secrets Found",
            description="d",
            evidence=["s2"],
            recommendations=["r"],
        )
        processor = FindingPostProcessor()
        result = processor.process([crit, high], {}, _config())
        # Different severity stems (count normalized to '#') but the wording differs, and
        # both are count-buckets keyed within-category -> must stay separate.
        assert len(result) == 2

    def test_merge_disabled(self):
        loc = FileLocation(uri="file:///app/Secret.java", start_line=10)
        a = _secret_finding("dup", severity=AnalysisSeverity.LOW)
        a.file_location = loc
        b = _secret_finding("dup", severity=AnalysisSeverity.HIGH)
        b.file_location = FileLocation(uri="file:///app/Secret.java", start_line=10)
        processor = FindingPostProcessor()
        result = processor.process([a, b], {}, _config(dedup={"enabled": False}))
        assert len(result) == 2


class TestPerfBound:
    def test_context_scan_is_bounded(self):
        analyzer = CodeContextAnalyzer()
        target = "AIzaSyTARGET1234567890"
        # 50k filler strings + one code-like matching string placed BEYOND the cap.
        corpus = [f"filler_string_{i}" for i in range(50000)]
        late_line = f'String apiKey = "{target}";'
        corpus.append(late_line)  # index 50000, well past a cap of 100

        string_data = {"all_strings": corpus}

        capped = analyzer._extract_surrounding_context_from_strings(target, string_data, max_context_strings=100)
        assert late_line not in capped.surrounding_lines  # never scanned -> cap works

        # With a cap large enough to reach it, the same line IS found.
        found = analyzer._extract_surrounding_context_from_strings(target, string_data, max_context_strings=60000)
        assert any(target in line for line in found.surrounding_lines)


class TestFalsePositiveFilterUnitFixes:
    def test_dev_staging_local_not_placeholders(self):
        fpf = FalsePositiveFilter()
        for value in ["127.0.0.1", "localhost", "staging", "development", "dev_secret"]:
            assert fpf.is_placeholder_value(value) is False, value

    def test_genuine_placeholder_still_flagged(self):
        fpf = FalsePositiveFilter()
        assert fpf.is_placeholder_value("your_api_key_here") is True

    def test_structural_secret_detection(self):
        fpf = FalsePositiveFilter()
        assert fpf.is_structural_secret("AKIAIOSFODNN7EXAMPLE") is True  # pragma: allowlist secret
        assert fpf.is_structural_secret("ghp_" + "a" * 36) is True
        assert fpf.is_structural_secret("ca-app-pub-1234567890123456") is True
        assert fpf.is_structural_secret("-----BEGIN RSA PRIVATE KEY-----") is True
        assert fpf.is_structural_secret("just_a_normal_string") is False

    def test_android_system_string_does_not_swallow_urls(self):
        fpf = FalsePositiveFilter()
        # Contains '.'/'/' plus keyword-ish tokens but must NOT be flagged as system.
        assert fpf.is_android_system_string("https://api.example.com/v1/users") is False
        assert fpf.is_android_system_string("database_connection_string") is False
        # Genuine descriptors/packages still detected.
        assert fpf.is_android_system_string("Landroid/view/View") is True
        assert fpf.is_android_system_string("androidx.core.content.ContextCompat") is True
