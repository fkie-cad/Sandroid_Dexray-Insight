#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the secret-detection scan optimizations (B1a / B1b / B2).

These tests lock in the behaviour-preserving optimizations applied to
``sensitive_data_assessment``:

- B1a: ``StringCollectionStrategy.collect_strings`` de-duplicates its string
  sources so identical values are not scanned multiple times.
- B1b: ``ResultClassificationStrategy.classify_by_severity`` aggregates a running
  count per severity while keeping only a bounded sample of evidence entries, and
  ``FindingGenerationStrategy`` still reports the TRUE total in the finding title.
- B2: ``PatternDetectionStrategy`` pre-compiles its regex patterns once and applies
  cheap literal prefilters without dropping real matches.
"""

import os
import re
import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.core.base_classes import AnalysisSeverity  # noqa: E402
from dexray_insight.security.sensitive_data_assessment import FindingGenerationStrategy  # noqa: E402
from dexray_insight.security.sensitive_data_assessment import PatternDetectionStrategy  # noqa: E402
from dexray_insight.security.sensitive_data_assessment import ResultClassificationStrategy  # noqa: E402
from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment  # noqa: E402
from dexray_insight.security.sensitive_data_assessment import StringCollectionStrategy  # noqa: E402

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret


def _real_detection_patterns():
    """Build the real detection pattern dict via a default-configured assessment."""
    assessment = SensitiveDataAssessment({})
    return assessment.detection_patterns


@pytest.mark.unit
@pytest.mark.security
class TestStringSourceDeduplication:
    """B1a: collect_strings must scan each distinct string value only once."""

    def test_duplicate_values_collected_once(self):
        strategy = StringCollectionStrategy(Mock())
        # "shared_value" is reachable via the interesting_strings category AND via the
        # all_strings field (which is consumed by both the all_strings and raw-strings
        # collectors), so without de-duplication it would appear multiple times.
        analysis_results = {
            "string_analysis": {
                "interesting_strings": ["shared_value", "unique_a"],
                "all_strings": ["shared_value", "unique_b", "unique_b"],
            }
        }

        result = strategy.collect_strings(analysis_results)
        values = [item["value"] for item in result]

        # No value is scanned more than once.
        assert len(values) == len(set(values))
        # Each distinct value is still present exactly once.
        assert values.count("shared_value") == 1
        assert values.count("unique_b") == 1
        assert set(values) == {"shared_value", "unique_a", "unique_b"}

    def test_first_occurrence_location_is_preserved(self):
        strategy = StringCollectionStrategy(Mock())
        analysis_results = {
            "string_analysis": {
                "emails": ["dup@example.com"],
                "all_strings": ["dup@example.com"],
            }
        }

        result = strategy.collect_strings(analysis_results)
        matches = [item for item in result if item["value"] == "dup@example.com"]

        # Exactly one entry, and it keeps the first (category) source location.
        assert len(matches) == 1
        assert "String analysis (emails)" in matches[0]["location"]

    def test_provenance_fields_preserved(self):
        strategy = StringCollectionStrategy(Mock())
        result = strategy.collect_strings({"string_analysis": {"urls": ["https://api.example.com"]}})
        assert result, "expected at least one collected string"
        for item in result:
            assert {"value", "location", "file_path", "line_number"}.issubset(item.keys())


@pytest.mark.unit
@pytest.mark.security
class TestLowSeverityAggregation:
    """B1b: true totals are counted while evidence is bounded."""

    @staticmethod
    def _make_low_detections(n):
        return [
            {
                "type": "High entropy string (potential key)",
                "severity": "LOW",
                "pattern_name": "high_entropy_string",
                "value": f"entropykey_{i:06d}_ABCDEFGHIJKLMNOP",
                "location": "Raw strings",
                "file_path": None,
                "line_number": None,
            }
            for i in range(n)
        ]

    def test_true_count_with_bounded_sample(self):
        classifier = ResultClassificationStrategy()
        total = 174  # far above the sample limit
        result = classifier.classify_by_severity(self._make_low_detections(total))

        # Running count reports the true total.
        assert result["counts"]["low"] == total
        # Sample buffers are bounded.
        limit = ResultClassificationStrategy._SAMPLE_LIMIT
        assert len(result["findings"]["low"]) == limit
        assert len(result["secrets"]["low"]) == limit
        # Structure is unchanged.
        assert set(result["findings"].keys()) == {"critical", "high", "medium", "low"}

    def test_finding_title_reports_true_total(self):
        classifier = ResultClassificationStrategy()
        total = 174
        classified = classifier.classify_by_severity(self._make_low_detections(total))

        generator = FindingGenerationStrategy("A02:2021-Cryptographic Failures")
        findings = generator.generate_security_findings(classified)

        low = next(f for f in findings if f.severity == AnalysisSeverity.LOW)
        # Title must show the TRUE total, not the bounded sample length.
        assert f"{total} Potential Information Leakage" in low.title
        # Evidence stays bounded (<= 20 as sliced by the generator).
        assert len(low.evidence) <= 20

    def test_generator_without_counts_falls_back_to_sample_length(self):
        # Backward-compatibility: callers that pass no "counts" key (e.g. legacy/tests)
        # still get a count derived from the sample list length.
        generator = FindingGenerationStrategy("A02:2021-Cryptographic Failures")
        classified = {
            "findings": {"critical": [], "high": [], "medium": [], "low": ["a", "b", "c"]},
            "secrets": {"critical": [], "high": [], "medium": [], "low": []},
        }
        findings = generator.generate_security_findings(classified)
        low = next(f for f in findings if f.severity == AnalysisSeverity.LOW)
        assert "3 Potential Information Leakage" in low.title

    def test_duplicates_do_not_inflate_count(self):
        classifier = ResultClassificationStrategy()
        detection = self._make_low_detections(1)[0]
        # Same (type, value) repeated should be de-duplicated -> count of 1.
        result = classifier.classify_by_severity([detection, dict(detection), dict(detection)])
        assert result["counts"]["low"] == 1


@pytest.mark.unit
@pytest.mark.security
class TestPrecompiledPatterns:
    """B2: patterns are compiled once and still match known secrets."""

    def test_patterns_precompiled_once(self):
        patterns = _real_detection_patterns()
        detector = PatternDetectionStrategy(patterns, Mock())

        # One compiled entry per pattern, preserving order.
        assert len(detector._compiled_patterns) == len(patterns)
        assert [e["name"] for e in detector._compiled_patterns] == list(patterns.keys())
        # AWS access-key pattern compiles to a real regex object.
        aws_entry = next(e for e in detector._compiled_patterns if e["name"] == "aws_access_key")
        assert isinstance(aws_entry["regex"], re.Pattern)

    def test_detects_fake_aws_key(self):
        detector = PatternDetectionStrategy(_real_detection_patterns(), Mock())
        strings = [{"value": FAKE_AWS_KEY, "location": "config.xml", "file_path": None, "line_number": None}]

        detections = detector.detect_secrets(strings)

        aws = [d for d in detections if d["pattern_name"] == "aws_access_key"]
        assert len(aws) == 1
        assert aws[0]["value"] == FAKE_AWS_KEY
        assert aws[0]["severity"] == "CRITICAL"

    def test_literal_prefilter_does_not_drop_matches(self):
        detector = PatternDetectionStrategy(_real_detection_patterns(), Mock())
        cases = {
            "-----BEGIN RSA PRIVATE KEY-----": "pem_private_key",  # pragma: allowlist secret
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789": "github_token",  # pragma: allowlist secret
            "mongodb://user:pass@host:27017/db": "mongodb_uri",  # pragma: allowlist secret
        }
        for value, expected_pattern in cases.items():
            detections = detector.detect_secrets(
                [{"value": value, "location": "x", "file_path": None, "line_number": None}]
            )
            names = {d["pattern_name"] for d in detections}
            assert expected_pattern in names, f"{expected_pattern} not detected for {value!r}"

    def test_prefilter_skips_regex_when_literal_absent(self):
        # A random string containing none of the distinctive literals must not produce a
        # literal-gated detection (e.g. aws_access_key requires an AKIA/AGPA/... prefix).
        detector = PatternDetectionStrategy(_real_detection_patterns(), Mock())
        detections = detector.detect_secrets(
            [{"value": "just a harmless sentence without any tokens", "location": "x",
              "file_path": None, "line_number": None}]
        )
        assert all(d["pattern_name"] != "aws_access_key" for d in detections)
