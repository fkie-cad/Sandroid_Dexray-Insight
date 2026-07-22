#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PR-5 tests: secret-detection precision (drop FPs) AND recall (keep real keys).

Both directions are asserted:

* Precision (false-positive guards): the Kik-style FPs -- a Unity ``aidAd...``
  constant, a BouncyCastle ``keyPairGenerator.SPHINCS256`` dotted class name, and a
  base64 PNG/ICC image blob -- must produce ZERO CRITICAL/HIGH findings.
* Recall (false-NEGATIVE guards, the critical part): the 4 real Kik client keys
  (Branch ``key_live_``, AdMob ``ca-app-pub-``, a 40-hex Crashlytics key, and an
  ``AIzaSy...`` key) must each be detected -- public client keys at LOW
  "client-side key (safe by design)", and AIza at its restriction_dependent
  severity, NEVER fully suppressed.
"""

import base64
import json
import os
import sys
import zlib
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.security.secret_validation import SecretValidator  # noqa: E402
from dexray_insight.security.sensitive_data_assessment import PatternDetectionStrategy  # noqa: E402
from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment  # noqa: E402

# --- Synthetic (non-live) sample values --------------------------------------
BRANCH_KEY = "key_live_abcdefghijklmnopqrstuvwxyz012345"  # pragma: allowlist secret
ADMOB_ID = "ca-app-pub-1234567890123456~1234567890"
CRASHLYTICS_HEX = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
AIZA_KEY = "AIzaSyCavBhXuLCGdOzaOpKn2rzP8rHxWAd3MCA"  # pragma: allowlist secret
STRIPE_SECRET = "sk_live_0123456789abcdefghijklmn"  # pragma: allowlist secret
STRIPE_PUBLISHABLE = "pk_live_0123456789abcdefghijklmn"  # pragma: allowlist secret
# 64-char genuine base64 key shape (high entropy, no binary signature).
REAL_B64_KEY = "A1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrS"  # pragma: allowlist secret


def _detector(config=None):
    """Build a PatternDetectionStrategy wired with a real SecretValidator."""
    assessment = SensitiveDataAssessment(config or {})
    validator = SecretValidator(
        entropy_thresholds=assessment.entropy_thresholds,
        length_filters=assessment.length_filters,
        context_detection_enabled=assessment.context_detection_enabled,
        context_strict_mode=assessment.context_strict_mode,
        key_detection_config=assessment.key_detection_config,
        logger=Mock(),
    )
    return PatternDetectionStrategy(assessment.detection_patterns, Mock(), validator=validator)


def _scan(value, config=None):
    det = _detector(config)
    return det.detect_secrets([{"value": value, "location": "test", "file_path": None, "line_number": None}])


def _by_pattern(findings, name):
    return [f for f in findings if f["pattern_name"] == name]


def _high_or_critical(findings):
    return [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]


def _make_png_b64():
    return base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200).decode()


def _make_icc_b64():
    # 'acsp' colour-profile signature at byte offset 36.
    raw = bytearray(b"\x00" * 200)
    raw[36:40] = b"acsp"
    return base64.b64encode(bytes(raw)).decode()


def _make_zlib_b64():
    return base64.b64encode(zlib.compress(b"the quick brown fox " * 20)).decode()


def _make_jwt(header, payload=None, sig="abcDEFghiJKLmno"):
    hdr = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    pay = base64.urlsafe_b64encode(json.dumps(payload or {"sub": "1234567890"}).encode()).rstrip(b"=").decode()
    return f"{hdr}.{pay}.{sig}"


# ============================================================================
# Precision: false-positive guards
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestFalsePositiveGuards:
    def test_unity_aidad_constant_no_high_critical(self):
        findings = _scan("aidAdUserAcceptInvitation")
        assert _high_or_critical(findings) == []

    def test_bouncycastle_dotted_class_not_jwt(self):
        # Contains a bare "ey" that previously matched the JWT pattern.
        findings = _scan("keyPairGenerator.SPHINCS256")
        assert _by_pattern(findings, "jwt_token") == []
        assert _high_or_critical(findings) == []

    def test_png_blob_no_high_critical(self):
        findings = _scan(_make_png_b64())
        assert _high_or_critical(findings) == []

    def test_icc_blob_no_high_critical(self):
        findings = _scan(_make_icc_b64())
        assert _high_or_critical(findings) == []


# ============================================================================
# Recall: real-key false-negative guards (the critical part)
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestRealKeyRecall:
    def test_branch_key_detected_low_client_side(self):
        findings = _by_pattern(_scan(f"branchKey = {BRANCH_KEY}"), "branch_io_key")
        assert len(findings) == 1
        assert findings[0]["severity"] == "LOW"
        assert findings[0]["classification_label"] == "client-side key (safe by design)"

    def test_admob_id_detected_low_client_side(self):
        findings = _by_pattern(_scan(f'value="{ADMOB_ID}"'), "admob_app_id")
        assert len(findings) == 1
        assert findings[0]["severity"] == "LOW"
        assert findings[0]["classification_label"] == "client-side key (safe by design)"

    def test_crashlytics_key_detected_low_client_side(self):
        findings = _by_pattern(_scan(f"com.crashlytics.sdk build {CRASHLYTICS_HEX}"), "crashlytics_api_key")
        assert len(findings) == 1
        assert findings[0]["severity"] == "LOW"
        assert findings[0]["classification_label"] == "client-side key (safe by design)"

    def test_aiza_detected_restriction_dependent_never_suppressed(self):
        findings = _by_pattern(_scan(AIZA_KEY), "google_api_key_aiza")
        assert len(findings) == 1, "AIza key must never be fully suppressed"
        # Restriction-dependent: downgraded from the pattern's CRITICAL to the
        # MEDIUM floor (bare key), NOT CRITICAL/HIGH.
        assert findings[0]["severity"] == "MEDIUM"
        assert "verify" in (findings[0]["classification_label"] or "").lower()
        assert findings[0]["classification_basis"] == "prefix_only"

    def test_aiza_with_firebase_context_is_low(self):
        findings = _by_pattern(_scan(f"firebase config google_api_key {AIZA_KEY}"), "google_api_key_aiza")
        assert len(findings) == 1
        assert findings[0]["severity"] == "LOW"
        assert findings[0]["classification_basis"] == "co_location:firebase"

    def test_aiza_prefix_only_cannot_downrank_below_medium(self):
        # A prefix_only basis may NOT push a restriction_dependent key below MEDIUM.
        findings = _by_pattern(_scan(AIZA_KEY), "google_api_key_aiza")
        assert findings[0]["severity"] == "MEDIUM"


# ============================================================================
# Structural patterns are exempt from entropy/context/FP gating
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestStructuralExemptFromGating:
    def test_low_entropy_structural_key_still_surfaces(self):
        # A github token with almost no entropy would fail an entropy gate, but a
        # structural prefix key must never be dropped by entropy heuristics.
        findings = _by_pattern(_scan("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "github_token")
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"


# ============================================================================
# Private twins are never lumped into the safe (public) class
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestPrivateTwins:
    def test_stripe_secret_live_is_critical(self):
        findings = _by_pattern(_scan(STRIPE_SECRET), "stripe_api_key")
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["classification_basis"] == "allowlist:private_secret"

    def test_stripe_publishable_live_is_low_public(self):
        findings = _by_pattern(_scan(STRIPE_PUBLISHABLE), "stripe_api_key")
        assert len(findings) == 1
        assert findings[0]["severity"] == "LOW"
        assert findings[0]["classification_basis"] == "allowlist:public_client"


# ============================================================================
# JWT header-only validation
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestJwtHeaderGate:
    def test_valid_3seg_jwt_accepted(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"})
        findings = _by_pattern(_scan(token), "jwt_token")
        assert len(findings) == 1

    def test_dotted_class_name_rejected(self):
        assert _by_pattern(_scan("keyPairGenerator.SPHINCS256"), "jwt_token") == []

    def test_eyjunk_notjson_rejected(self):
        assert _by_pattern(_scan("eyJunk.notjson.x"), "jwt_token") == []

    def test_5seg_jwe_with_decodable_header_accepted(self):
        hdr = base64.urlsafe_b64encode(json.dumps({"alg": "RSA-OAEP", "enc": "A256GCM"}).encode()).rstrip(b"=").decode()
        jwe = ".".join([hdr, "encryptedkeyAAAA", "initvectorBBBB", "ciphertextCCCCCC", "authtagDDDDDDDD"])
        findings = _by_pattern(_scan(jwe), "jwt_token")
        assert len(findings) == 1

    def test_validator_requires_alg_field(self):
        v = SecretValidator(logger=Mock())
        no_alg = _make_jwt({"typ": "JWT"})
        verdict = v.evaluate(no_alg, no_alg, "jwt_token", {"severity": "HIGH"})
        assert verdict.rejected is True


# ============================================================================
# base64 -> binary rejection (generic) and genuine key acceptance
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestBinaryBlobRejection:
    def test_png_blob_rejected_from_generic(self):
        findings = _scan(_make_png_b64())
        assert _by_pattern(findings, "base64_key_long") == []
        assert _by_pattern(findings, "high_entropy_string") == []

    def test_icc_blob_rejected_from_generic(self):
        findings = _scan(_make_icc_b64())
        assert _by_pattern(findings, "base64_key_long") == []

    def test_zlib_blob_rejected_from_generic(self):
        findings = _scan(_make_zlib_b64())
        assert _by_pattern(findings, "base64_key_long") == []

    def test_genuine_base64_key_accepted(self):
        findings = _scan(REAL_B64_KEY)
        assert len(_by_pattern(findings, "base64_key_long")) == 1

    def test_validator_unit_binary_reject(self):
        v = SecretValidator(logger=Mock())
        png = _make_png_b64()
        verdict = v.evaluate(png, png, "base64_key_long", {"severity": "LOW", "min_entropy": 4.5})
        assert verdict.rejected is True
        assert verdict.classification_basis == "binary_blob"


# ============================================================================
# Config wiring: dexray.yaml knobs reach the active detection path
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestConfigWiring:
    def test_absurd_entropy_threshold_drops_generic(self):
        cfg = {
            "key_detection": {
                "entropy_thresholds": {
                    "min_base64_entropy": 8.0,
                    "min_generic_entropy": 8.0,
                    "min_hex_entropy": 8.0,
                }
            }
        }
        findings = _scan(REAL_B64_KEY, cfg)
        assert _by_pattern(findings, "base64_key_long") == []
        assert _by_pattern(findings, "high_entropy_string") == []

    def test_absurd_min_confidence_drops_generic(self):
        cfg = {"key_detection": {"confidence": {"enabled": True, "min_confidence": 0.99}}}
        findings = _scan(REAL_B64_KEY, cfg)
        assert _by_pattern(findings, "base64_key_long") == []

    def test_default_config_keeps_genuine_key(self):
        # Sanity: with defaults the same key is kept (proves the drops above are the
        # knob's effect, not a broken baseline).
        assert len(_by_pattern(_scan(REAL_B64_KEY), "base64_key_long")) == 1
