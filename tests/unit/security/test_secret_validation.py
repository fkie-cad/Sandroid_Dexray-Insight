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


def _make_square_in_image_b64():
    """A base64 image blob that CONTAINS an ``EAAA...`` square-token run.

    * The leading ``iVBORw0KGgo`` decodes to the PNG magic (offset 0), so the FULL
      string is a PNG blob.
    * It embeds ``EAAA`` + 60 alphanumerics so the ``square_access_token`` pattern
      (``EAAA[a-zA-Z0-9]{60}``) matches the ~64-char FRAGMENT — whose own decode
      has no binary signature. Only the full-string binary check catches it.
    """
    blob = "iVBORw0KGgo" + "EAAA" + "B" * 60
    blob += "A" * (-len(blob) % 4)
    return blob


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


# ============================================================================
# Residual-FP fix 1: Square token that is really a PNG/ICC base64 blob
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestSquareTokenImageBlob:
    def test_square_token_in_image_blob_rejected_via_full_context(self):
        blob = _make_square_in_image_b64()
        findings = _scan(blob)
        # The EAAA... fragment matched the square-token shape, but the FULL string
        # base64-decodes to a PNG -> dropped, no HIGH secret.
        assert _by_pattern(findings, "square_access_token") == []
        assert _high_or_critical(findings) == []

    def test_full_context_binary_reject_unit(self):
        v = SecretValidator(logger=Mock())
        blob = _make_square_in_image_b64()
        fragment = "EAAA" + "B" * 60
        verdict = v.evaluate(fragment, blob, "square_access_token", {"severity": "HIGH"})
        assert verdict.rejected is True
        assert verdict.classification_basis == "binary_blob"


# ============================================================================
# Residual-FP fix 2: Authorization Basic "basic settings" UI phrase
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestAuthorizationBasic:
    def test_basic_settings_ui_phrase_rejected(self):
        findings = _by_pattern(_scan("basic settings"), "authorization_basic")
        assert findings == []

    def test_genuine_basic_credentials_surface(self):
        creds = base64.b64encode(b"admin:SuperSecret123").decode()  # pragma: allowlist secret
        findings = _by_pattern(_scan(f"authorization: basic {creds}"), "authorization_basic")
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["classification_basis"] == "authorization_basic:valid"

    def test_basic_lowercase_word_rejected_unit(self):
        v = SecretValidator(logger=Mock())
        verdict = v.evaluate("basic settings", "basic settings", "authorization_basic", {"severity": "HIGH"})
        assert verdict.rejected is True
        assert verdict.classification_basis == "authorization_basic:fp"


# ============================================================================
# Residual-FP fix 3: crypto known-answer-test hex vectors (context-less hex)
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestHexKeyContextHardDrop:
    def test_bare_kat_hex_vector_dropped(self):
        # High-entropy 128-bit KAT vector with NO key/crypto context -> hard drop.
        findings = _by_pattern(_scan("4d696e676875615175985bd3adbada21"), "hex_key_128")
        assert findings == []

    def test_bare_zero_kat_hex_vector_dropped(self):
        findings = _by_pattern(_scan("80000000000000000000000000000000"), "hex_key_128")
        assert findings == []

    def test_hex_key_with_context_surfaces(self):
        findings = _by_pattern(_scan('apiKey = "0123456789abcdef0123456789abcdef"'), "hex_key_128")
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    def test_context_hard_drop_unit(self):
        v = SecretValidator(logger=Mock())
        cfg = {
            "severity": "MEDIUM",
            "context_required": ["key", "secret", "aes"],
            "context_hard": True,
        }
        vector = "4d696e676875615175985bd3adbada21"
        verdict = v.evaluate(vector, vector, "hex_key_128", cfg)
        assert verdict.rejected is True
        assert verdict.classification_basis == "generic:context"


# ============================================================================
# Residual-FP fix 4: high_entropy_string slash-path fragments
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestHighEntropyPathDrop:
    PATHS = [
        "com/library/test/success",
        "net/sdk/sdk/1121/android/mraid",
        "server/v1/config/secure",
        "com/pagead/conversion/app/deeplink",
    ]

    def test_fp_probability_flags_slash_paths(self):
        v = SecretValidator(logger=Mock())
        for path in self.PATHS:
            assert v._false_positive_probability(path) >= 0.9, path

    def test_slash_paths_dropped_from_high_entropy_string(self):
        # Low entropy floor so the path clears the entropy gate: the DROP must then
        # come from the path/FP rule, not from entropy.
        low = {"min_base64_entropy": 2.0, "min_hex_entropy": 2.0, "min_generic_entropy": 2.0}
        v = SecretValidator(entropy_thresholds=low, logger=Mock())
        cfg = {"severity": "LOW", "min_entropy": 2.0, "max_length": 512}
        for path in self.PATHS:
            verdict = v.evaluate(path, path, "high_entropy_string", cfg)
            assert verdict.rejected is True, path
            assert verdict.classification_basis == "generic:path_fp", path

    def test_genuine_high_entropy_base64_still_surfaces(self):
        low = {"min_base64_entropy": 2.0, "min_hex_entropy": 2.0, "min_generic_entropy": 2.0}
        v = SecretValidator(entropy_thresholds=low, logger=Mock())
        cfg = {"severity": "LOW", "min_entropy": 2.0, "max_length": 512}
        verdict = v.evaluate(REAL_B64_KEY, REAL_B64_KEY, "high_entropy_string", cfg)
        assert verdict.rejected is False
        assert verdict.classification_basis != "generic:path_fp"

    def test_base64_with_slashes_not_treated_as_path(self):
        # A genuine base64 blob may contain '/', but '+'/'=' punctuation or long
        # random segments keep it out of the path branch.
        v = SecretValidator(logger=Mock())
        blob = "aB3xY9kL/mN8pQ4rS6tU0vW1zC5dE7fG+hJ2kM4nP6qR8sT0uV2wX4yZ6a="  # pragma: allowlist secret
        assert v._false_positive_probability(blob) < 0.5


# ============================================================================
# Residual-FP fix R1b: the base64/entropy "leakage" family (base64_key_long /
# base64_key_medium) must ALSO hard-drop DEX class descriptors + slash paths.
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestBase64FamilyPathDrop:
    # DEX class descriptors and slash URL/package paths that on a real APK match
    # the base64_key_* shape and dominated the LOW "Information Leakage" bucket.
    NOISE = [
        "Lcom/revenuecat/purchases/Offerings",
        "Landroidx/compose/ui/text/SaversKt",
        "Lorg/bouncycastle/jcajce/provider/symmetric/Camellia",
        "com/stickersv2/packs/breakfastclub/17",
        "com/api/v1/LB2obTqtITKmjuGCeC407xENJSX6Z1Gunjp6X3i519a7ylBfwkKK",
    ]

    def _validator(self):
        # Low entropy floor so the value clears the entropy gate; the DROP must
        # then come from the path/DEX-descriptor rule, not from entropy.
        low = {"min_base64_entropy": 2.0, "min_hex_entropy": 2.0, "min_generic_entropy": 2.0}
        return SecretValidator(entropy_thresholds=low, logger=Mock())

    @pytest.mark.parametrize("pattern_name", ["base64_key_long", "base64_key_medium"])
    def test_dex_descriptors_and_paths_dropped(self, pattern_name):
        v = self._validator()
        cfg = {"severity": "LOW", "min_entropy": 2.0, "max_length": 512}
        for value in self.NOISE:
            verdict = v.evaluate(value, value, pattern_name, cfg)
            assert verdict.rejected is True, (pattern_name, value)
            assert verdict.classification_basis == "generic:path_fp", (pattern_name, value)

    @pytest.mark.parametrize("pattern_name", ["base64_key_long", "base64_key_medium"])
    def test_genuine_base64_secret_still_surfaces(self, pattern_name):
        # A random-looking high-entropy token (with '+'/'=' punctuation) is NOT
        # path-like and must NOT be dropped by the path rule.
        v = self._validator()
        cfg = {"severity": "LOW", "min_entropy": 2.0, "max_length": 512}
        genuine = "aB3xY9kL+mN8pQ4rS6tU0vW1zC5dE7fG+hJ2kM4nP6qR8sT0uV2wX4yZ6a="  # pragma: allowlist secret
        verdict = v.evaluate(genuine, genuine, pattern_name, cfg)
        assert verdict.rejected is False
        assert verdict.classification_basis != "generic:path_fp"

    def test_dex_descriptor_helper_covers_trailing_semicolon(self):
        v = SecretValidator(logger=Mock())
        assert v._looks_like_dex_descriptor("Landroidx/compose/ui/text/SaversKt;")
        assert v._looks_like_dex_descriptor("LFoo/Bar;")
        assert not v._looks_like_dex_descriptor("A1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvWx")


# ============================================================================
# Residual-FP fix R1c: long camelCase/PascalCase Java IDENTIFIERS (method/class
# names) match base64_key_medium ([A-Za-z0-9+/=]{20,}) because they have NO slash
# and now dominate the LOW "Information Leakage" bucket. They must hard-drop, while
# genuine base64 tokens (containing '+'/'=') and random high-entropy blobs survive.
# ============================================================================
@pytest.mark.unit
@pytest.mark.security
class TestBase64FamilyCodeIdentifierDrop:
    # Real source-code identifiers pulled from a live APK run.
    IDENTIFIERS = [
        "findTrustAnchorByIssuerAndSignature",
        "fuFaceProcessorSetFaceLandmarkQuality",
        "getTextMarkdownAttachmentOrBuilder",
        "nativeCreateFromTypefaceWithExactStyle",
        "BadgeCountFileDescriptorSupplier",
        "isISDemandOnlyRewardedVideoAvailable",
        "determinePostReceiptErrorHandlingBehavior",
    ]

    def _validator(self):
        # Low entropy floor so the value clears the entropy gate; the DROP must
        # then come from the code-identifier rule, not from entropy.
        low = {"min_base64_entropy": 2.0, "min_hex_entropy": 2.0, "min_generic_entropy": 2.0}
        return SecretValidator(entropy_thresholds=low, logger=Mock())

    def test_helper_flags_code_identifiers(self):
        v = SecretValidator(logger=Mock())
        for ident in self.IDENTIFIERS:
            assert v._looks_like_code_identifier(ident) is True, ident

    @pytest.mark.parametrize("pattern_name", ["base64_key_long", "base64_key_medium", "high_entropy_string"])
    def test_code_identifiers_dropped(self, pattern_name):
        v = self._validator()
        cfg = {"severity": "LOW", "min_entropy": 2.0, "max_length": 512}
        for ident in self.IDENTIFIERS:
            verdict = v.evaluate(ident, ident, pattern_name, cfg)
            assert verdict.rejected is True, (pattern_name, ident)
            assert verdict.classification_basis == "generic:path_fp", (pattern_name, ident)

    def test_base64_token_with_punctuation_not_identifier(self):
        # Real base64 token with '+'/'=' -> NEVER an identifier; must survive.
        v = SecretValidator(logger=Mock())
        token = "gfLiyhD2OvLSOj6bwf+kcmK11rwQ90aeBshxHD6xXgk="  # pragma: allowlist secret
        assert v._looks_like_code_identifier(token) is False

    @pytest.mark.parametrize("pattern_name", ["base64_key_long", "base64_key_medium"])
    def test_base64_token_with_padding_still_surfaces(self, pattern_name):
        v = self._validator()
        cfg = {"severity": "LOW", "min_entropy": 2.0, "max_length": 512}
        token = "gfLiyhD2OvLSOj6bwf+kcmK11rwQ90aeBshxHD6xXgk="  # pragma: allowlist secret
        verdict = v.evaluate(token, token, pattern_name, cfg)
        assert verdict.rejected is False, pattern_name
        assert verdict.classification_basis != "generic:path_fp", pattern_name

    def test_random_high_entropy_alnum_not_identifier(self):
        # Random alnum blob with single-letter case flips (REAL_B64_KEY shape) has
        # no camelCase word runs -> NOT an identifier; left for the entropy gates.
        v = SecretValidator(logger=Mock())
        assert v._looks_like_code_identifier(REAL_B64_KEY) is False

    @pytest.mark.parametrize("pattern_name", ["base64_key_long", "high_entropy_string"])
    def test_random_high_entropy_secret_still_surfaces(self, pattern_name):
        v = self._validator()
        cfg = {"severity": "LOW", "min_entropy": 2.0, "max_length": 512}
        verdict = v.evaluate(REAL_B64_KEY, REAL_B64_KEY, pattern_name, cfg)
        assert verdict.rejected is False, pattern_name
        assert verdict.classification_basis != "generic:path_fp", pattern_name

    def test_no_regression_slash_paths_and_dex_still_drop(self):
        # The previously-fixed slash paths / DEX descriptors must still hard-drop.
        v = self._validator()
        cfg = {"severity": "LOW", "min_entropy": 2.0, "max_length": 512}
        noise = [
            "Lcom/revenuecat/purchases/Offerings",
            "Landroidx/compose/ui/text/SaversKt",
            "com/library/test/success",
            "net/sdk/sdk/1121/android/mraid",
        ]
        for value in noise:
            verdict = v.evaluate(value, value, "base64_key_medium", cfg)
            assert verdict.rejected is True, value
            assert verdict.classification_basis == "generic:path_fp", value
