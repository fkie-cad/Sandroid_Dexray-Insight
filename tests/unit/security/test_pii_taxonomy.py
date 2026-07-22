#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Phase B1 tests: PII taxonomy + PIIValidator precision.

Asserts the validation layer kills the regex false positives (a non-Luhn digit
run, a 9-digit article id, a bare numeric run without phone context, out-of-range
coordinates) while accepting genuine PII shapes, and that library/placeholder
emails are recognised.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.security.evidence.pii_taxonomy import (  # noqa: E402
    PII_TAXONOMY,
    PIICategory,
    PIIPattern,
    PIIValidator,
    is_placeholder_or_library_email,
)


def _pattern(name):
    return next(p for p in PII_TAXONOMY if p.name == name)


def _validator():
    return PIIValidator()


# --------------------------------------------------------------------- luhn
def test_luhn_valid_credit_card_accepted():
    # 4111 1111 1111 1111 is the canonical Luhn-valid Visa test number.
    verdict = _validator().evaluate("4111111111111111", "card=4111111111111111", _pattern("credit_card"))
    assert verdict.rejected is False
    assert verdict.category == PIICategory.FINANCIAL
    assert verdict.confidence >= 0.7


def test_non_luhn_16_digit_run_rejected():
    verdict = _validator().evaluate("1234567812345678", "id=1234567812345678", _pattern("credit_card"))
    assert verdict.rejected is True
    assert "luhn" in (verdict.basis or "")


def test_nine_digit_zendesk_id_never_matches_credit_card_regex():
    # A 9-digit article id is below the 13-digit minimum, so the regex itself skips it.
    assert _pattern("credit_card").regex.search("article 360001234") is None


# --------------------------------------------------------------------- e164
def test_e164_plus_prefixed_accepted():
    verdict = _validator().evaluate("+14155552671", "phone", _pattern("phone_e164"))
    assert verdict.rejected is False
    assert verdict.category == PIICategory.CONTACT


def test_bare_ten_digit_rejected_without_context():
    verdict = _validator().evaluate("4155552671", "some random ui label", _pattern("phone_e164"))
    assert verdict.rejected is True


def test_bare_number_rescued_by_phone_context():
    verdict = _validator().evaluate("4155552671", "user phone number", _pattern("phone_e164"))
    assert verdict.rejected is False


# ---------------------------------------------------------------------- ssn
def test_structurally_valid_ssn_accepted():
    verdict = _validator().evaluate("123-45-6789", "value", _pattern("ssn_us"))
    assert verdict.rejected is False
    assert verdict.category == PIICategory.IDENTIFIER


def test_invalid_ssn_area_rejected():
    verdict = _validator().evaluate("000-45-6789", "value", _pattern("ssn_us"))
    assert verdict.rejected is True


def test_invalid_ssn_rescued_by_context():
    verdict = _validator().evaluate("000-45-6789", "user ssn field", _pattern("ssn_us"))
    assert verdict.rejected is False


# ---------------------------------------------------------------------- geo
def test_valid_coordinate_accepted():
    verdict = _validator().evaluate("51.5074,-0.1278", "loc", _pattern("latlong"))
    assert verdict.rejected is False
    assert verdict.category == PIICategory.LOCATION


def test_null_island_rejected():
    verdict = _validator().evaluate("0.0,0.0", "loc", _pattern("latlong"))
    assert verdict.rejected is True


def test_out_of_range_coordinate_rejected():
    verdict = _validator().evaluate("200.0,500.0", "loc", _pattern("latlong"))
    assert verdict.rejected is True


# -------------------------------------------------------------------- email
def test_library_and_placeholder_emails_flagged():
    assert is_placeholder_or_library_email("noreply@crashlytics.com") is True
    assert is_placeholder_or_library_email("dev@example.com") is True
    assert is_placeholder_or_library_email("your_email@test.com") is True


def test_real_user_email_not_flagged():
    assert is_placeholder_or_library_email("jane.doe@protonmail.com") is False


# ---------------------------------------------------------------- taxonomy
def test_taxonomy_shape():
    assert {p.name for p in PII_TAXONOMY} >= {"credit_card", "phone_e164", "ssn_us", "latlong", "email"}
    for pattern in PII_TAXONOMY:
        assert isinstance(pattern, PIIPattern)
        assert pattern.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
