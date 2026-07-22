#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PR-0a regression tests: case-sensitive AWS key detection + fixed AIza char class.

These lock in the highest-visibility precision fix:

- The fake "🔴 CRITICAL: 10 Hard-coded Secrets" on Kik base.apk was caused by
  ``re.IGNORECASE`` letting the AWS account-id prefix ``AIDA`` match lowercase
  identifiers such as Unity Ads event constants ``aidAdRendererContainer``. The AWS
  pattern is now compiled case-sensitively with word boundaries.
- The ``google_api_key_aiza`` pattern previously used a broken character class
  (``[0-9A-Za-z\\-_]``) that excluded the hyphen real AIza keys contain.

Both directions are asserted: false positives disappear AND real keys are still
detected (no false negatives introduced).
"""

import os
import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.security.sensitive_data_assessment import PatternDetectionStrategy  # noqa: E402
from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment  # noqa: E402

# Real-format sample values (synthetic, not live credentials).
REAL_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
REAL_AIZA_KEY = "AIzaSyCavBhXuLCGdOzaOpKn2rzP8rHxWAd3MCA"  # pragma: allowlist secret (Kik client key, public)

# The exact Unity Ads event-name constants that produced the fake CRITICAL findings.
UNITY_AIDAD_CONSTANTS = [
    "aidAdRendererContainer",
    "aidAdContainerScreen",
    "aidAdVideoThirdQuartile",
    "aidActivityDataHolder",
    "aidAdSkippableStateChange",
]


def _detector():
    return PatternDetectionStrategy(SensitiveDataAssessment({}).detection_patterns, Mock())


def _findings_for(value):
    detector = _detector()
    return detector.detect_secrets([{"value": value, "location": "test", "file_path": None, "line_number": None}])


@pytest.mark.unit
@pytest.mark.security
class TestAwsKeyCaseSensitivity:
    """AWS key detection must be case-sensitive to avoid the aidAd… false positives."""

    @pytest.mark.parametrize("value", UNITY_AIDAD_CONSTANTS)
    def test_unity_aidad_constants_are_not_aws_keys(self, value):
        findings = _findings_for(value)
        aws = [f for f in findings if f["pattern_name"] == "aws_access_key"]
        assert aws == [], f"{value!r} was falsely detected as an AWS Access Key: {aws}"

    def test_no_critical_from_unity_constant(self):
        # The whole-string scan must not yield any CRITICAL secret for the FP input.
        findings = _findings_for("aidAdUserAcceptInvitation")
        criticals = [f for f in findings if f["severity"] == "CRITICAL"]
        assert criticals == [], f"Unexpected CRITICAL findings: {criticals}"

    def test_real_aws_key_still_detected(self):
        findings = _findings_for(f"my_key = {REAL_AWS_KEY}")
        aws = [f for f in findings if f["pattern_name"] == "aws_access_key"]
        assert len(aws) == 1, f"Real AWS key should be detected exactly once, got: {aws}"
        assert aws[0]["severity"] == "CRITICAL"

    def test_lowercased_real_key_is_not_matched(self):
        # A fully lower-cased dump of the key is not a valid AWS key id.
        findings = _findings_for(REAL_AWS_KEY.lower())
        aws = [f for f in findings if f["pattern_name"] == "aws_access_key"]
        assert aws == []


@pytest.mark.unit
@pytest.mark.security
class TestAizaCharClassFix:
    """The AIza pattern must match real keys, including those containing hyphens."""

    def test_real_aiza_key_detected(self):
        findings = _findings_for(REAL_AIZA_KEY)
        aiza = [f for f in findings if f["pattern_name"] == "google_api_key_aiza"]
        assert len(aiza) == 1, f"Real AIza key should be detected, got: {aiza}"

    def test_aiza_key_with_hyphen_detected(self):
        # 35 chars after AIza including a hyphen — previously dropped by the broken class.
        key_with_hyphen = "AIzaSyA-CdE1fGhIjKlMnOpQrStUvWxYz012345"  # pragma: allowlist secret
        assert len(key_with_hyphen) == 4 + 35
        findings = _findings_for(key_with_hyphen)
        aiza = [f for f in findings if f["pattern_name"] == "google_api_key_aiza"]
        assert len(aiza) == 1, "AIza key containing a hyphen must be detected after the char-class fix"
