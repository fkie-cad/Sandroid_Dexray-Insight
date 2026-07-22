#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Phase B1 tests: PIIAssessment ground-truth targets.

Each test instantiates the assessment directly and feeds synthetic
``analysis_results`` dicts (no engine/registry, no base.apk). The targets mirror
the Phase B1 spec: Art.9 storage, plaintext private key, Luhn FP suppression,
IDOR review-queue, permission+sink correlation (incl. AD_ID down-rank), and a
clean bill for library/placeholder-only input.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.core.base_classes import AnalysisSeverity  # noqa: E402
from dexray_insight.core.base_classes import VerificationStatus  # noqa: E402
from dexray_insight.security.pii_assessment import PIIAssessment  # noqa: E402


def _assess(results):
    return PIIAssessment({}).assess(results, None)


def _find(findings, predicate):
    return [f for f in findings if predicate(f)]


# --------------------------------------------------------------- Art.9 storage
def test_art9_columns_high_confirmed():
    results = {
        "string_analysis": {
            "all_strings": [
                "CREATE TABLE profiles (id INTEGER PRIMARY KEY, religion TEXT, ethnicity TEXT)"
            ]
        }
    }
    findings = _assess(results)
    art9 = _find(findings, lambda f: f.additional_data.get("gdpr_article") == "Art.9")
    assert len(art9) == 1
    assert art9[0].severity == AnalysisSeverity.HIGH
    assert art9[0].verification_status == VerificationStatus.CONFIRMED


# ------------------------------------------------------ plaintext private key
def test_private_key_pref_critical_confirmed():
    results = {"string_analysis": {"all_strings": ["kik.auth.gen.priv.key"]}}
    findings = _assess(results)
    crit = _find(findings, lambda f: f.severity == AnalysisSeverity.CRITICAL)
    assert len(crit) == 1
    assert crit[0].verification_status == VerificationStatus.CONFIRMED
    assert "private key" in crit[0].title.lower()


def test_private_key_pref_downgraded_when_encrypted():
    results = {
        "string_analysis": {
            "all_strings": [
                "kik.auth.gen.priv.key",
                "androidx.security.crypto.EncryptedSharedPreferences",
            ]
        }
    }
    findings = _assess(results)
    assert not _find(findings, lambda f: f.severity == AnalysisSeverity.CRITICAL)


# ------------------------------------------------------------- Luhn kills FP
def test_luhn_suppresses_false_positives():
    results = {
        "string_analysis": {
            "all_strings": [
                "article id 360001234",  # 9-digit Zendesk id
                "trace 1234567812345678",  # non-Luhn 16-digit run
            ]
        }
    }
    findings = _assess(results)
    financial = _find(findings, lambda f: f.additional_data.get("pii_category") == "financial")
    assert financial == []


def test_luhn_valid_card_reported_as_review_seed():
    results = {"string_analysis": {"all_strings": ["pan=4111111111111111"]}}
    findings = _assess(results)
    financial = _find(findings, lambda f: f.additional_data.get("pii_category") == "financial")
    assert len(financial) == 1
    assert financial[0].verification_status == VerificationStatus.NEEDS_REVIEW


# --------------------------------------------------------------------- IDOR
def test_idor_grpc_method_needs_dynamic():
    results = {
        "string_analysis": {
            "all_strings": ["mobile.persona.v2.PersonaInfo/GetPersonaFullByUsername"]
        }
    }
    findings = _assess(results)
    idor = _find(findings, lambda f: f.category == "A01:2021-Broken Access Control")
    assert len(idor) == 1
    assert idor[0].severity == AnalysisSeverity.MEDIUM
    assert idor[0].verification_status == VerificationStatus.NEEDS_DYNAMIC
    assert idor[0].confidence >= 0.85
    assert idor[0].additional_data.get("review_queue") is True


# --------------------------------------------------- permission + sink map
def test_read_phone_numbers_sink_medium():
    results = {
        "permission_analysis": {"all_permissions": ["android.permission.READ_PHONE_NUMBERS"]},
        "api_invocation": {"api_calls": ["Landroid/telephony/TelephonyManager;->getLine1Number()"]},
    }
    findings = _assess(results)
    corr = _find(findings, lambda f: f.additional_data.get("permission") == "READ_PHONE_NUMBERS" and "sinks" in f.additional_data)
    assert len(corr) == 1
    assert corr[0].severity == AnalysisSeverity.MEDIUM
    assert corr[0].verification_status == VerificationStatus.CONFIRMED


def test_ad_id_sink_downranked_to_low():
    results = {
        "permission_analysis": {"all_permissions": ["com.google.android.gms.permission.AD_ID"]},
        "api_invocation": {"api_calls": ["AdvertisingIdClient;->getAdvertisingIdInfo()"]},
    }
    findings = _assess(results)
    corr = _find(findings, lambda f: f.additional_data.get("permission") == "AD_ID" and "sinks" in f.additional_data)
    assert len(corr) == 1
    assert corr[0].severity == AnalysisSeverity.LOW


def test_correlation_self_suppressed_when_no_api_calls():
    results = {
        "permission_analysis": {"all_permissions": ["android.permission.READ_PHONE_NUMBERS"]},
        "api_invocation": {"api_calls": []},
    }
    findings = _assess(results)
    assert not _find(findings, lambda f: "sinks" in f.additional_data)


def test_permission_typo_low_confirmed():
    results = {"permission_analysis": {"all_permissions": ["READ_PHONE_NUMBERS"]}}
    findings = _assess(results)
    typo = _find(findings, lambda f: f.additional_data.get("expected_suffix") == "READ_PHONE_NUMBERS")
    assert len(typo) == 1
    assert typo[0].severity == AnalysisSeverity.LOW
    assert typo[0].confidence == 0.9
    assert typo[0].verification_status == VerificationStatus.CONFIRMED


# ------------------------------------------------------------- clean input
def test_no_findings_for_benign_library_emails():
    results = {
        "string_analysis": {
            "all_strings": [
                "noreply@crashlytics.com",
                "support@example.com",
                "your_email@test.com",
            ]
        }
    }
    findings = _assess(results)
    assert findings == []
