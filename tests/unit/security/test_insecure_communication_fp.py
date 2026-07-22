#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for M3 Insecure Communication false-positive reduction.

Ground truth (base_analys.md A2): cleartext HTTP to first-party endpoints is a
REAL MEDIUM risk. XML-namespace / documentation URIs (xmlpull.org, w3.org, ...)
are NOT endpoints and must be dropped. Weak-TLS protocol references without
first-party attribution are library constants and must be down-ranked, not HIGH.
"""

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.core.base_classes import VerificationStatus
from src.dexray_insight.security.mobile_specific_assessment import MobileSpecificAssessment


def _results(urls, all_strings=None):
    return {
        "string_analysis": {
            "all_strings": all_strings or [],
            "urls": urls,
        },
    }


def _m3(findings):
    return [f for f in findings if f.title == "Insecure Communication"]


class TestInsecureCommunicationFalsePositives:
    def test_doc_and_namespace_uris_are_filtered(self):
        """xmlpull.org / w3.org / schemas.android.com URIs must NOT appear as evidence."""
        assessment = MobileSpecificAssessment({"enabled": True})
        urls = [
            "http://xmlpull.org/v1/doc/features.html#process-docdecl",
            "http://www.w3.org/2000/svg",
            "http://schemas.android.com/apk/res/android",
            "http://java.sun.com/dtd/web-app_2_3.dtd",
            "http://www.kik.com/groups-update",  # REAL first-party (kept)
        ]
        findings = assessment._assess_insecure_communication(_results(urls))
        m3 = _m3(findings)
        assert len(m3) == 1
        evidence_blob = " ".join(m3[0].evidence)
        # Namespace/doc URIs dropped.
        assert "xmlpull.org" not in evidence_blob
        assert "w3.org" not in evidence_blob
        assert "schemas.android.com" not in evidence_blob
        assert "java.sun.com" not in evidence_blob

    def test_real_first_party_cleartext_still_produces_finding(self):
        """kik.com / piranhakik.com cleartext must STILL be reported (not suppressed)."""
        assessment = MobileSpecificAssessment({"enabled": True})
        urls = [
            "http://www.kik.com/groups-update",
            "http://profilepicsup.piranhakik.com/profilepics",
            "http://xmlpull.org/v1/doc/features.html#process-docdecl",  # noise
        ]
        findings = assessment._assess_insecure_communication(_results(urls))
        m3 = _m3(findings)
        assert len(m3) == 1
        evidence_blob = " ".join(m3[0].evidence)
        assert "www.kik.com/groups-update" in evidence_blob
        assert "profilepicsup.piranhakik.com/profilepics" in evidence_blob

    def test_severity_is_medium_not_high(self):
        """Per ground-truth A2, cleartext is a MEDIUM risk, not HIGH."""
        assessment = MobileSpecificAssessment({"enabled": True})
        urls = ["http://www.kik.com/groups-update"]
        findings = assessment._assess_insecure_communication(_results(urls))
        m3 = _m3(findings)
        assert len(m3) == 1
        assert m3[0].severity == AnalysisSeverity.MEDIUM

    def test_only_namespace_uris_yields_no_finding(self):
        """If the only cleartext URLs are namespace/doc URIs, there is no M3 finding."""
        assessment = MobileSpecificAssessment({"enabled": True})
        urls = [
            "http://xmlpull.org/v1/doc/features.html#process-docdecl",
            "http://www.w3.org/2000/svg",
        ]
        findings = assessment._assess_insecure_communication(_results(urls))
        assert _m3(findings) == []

    def test_weak_tls_constant_is_downranked_not_high(self):
        """A bare SSLv3/TLSv1.1 string (library constant) must not be a HIGH finding."""
        assessment = MobileSpecificAssessment({"enabled": True})
        findings = assessment._assess_insecure_communication(
            _results([], all_strings=["SSLv3", "TLSv1.1"])
        )
        m3 = _m3(findings)
        assert len(m3) == 1
        assert m3[0].severity == AnalysisSeverity.LOW
        assert m3[0].verification_status == VerificationStatus.NEEDS_REVIEW

    def test_first_party_weak_tls_is_confirmed_medium(self):
        """Weak TLS attributable to first-party code is kept as MEDIUM evidence."""
        assessment = MobileSpecificAssessment(
            {"enabled": True, "first_party_prefixes": ["com.kik."]}
        )
        findings = assessment._assess_insecure_communication(
            _results([], all_strings=["com.kik.net.TlsConfig SSLv3"])
        )
        m3 = _m3(findings)
        assert len(m3) == 1
        assert m3[0].severity == AnalysisSeverity.MEDIUM
        assert any("first-party" in e for e in m3[0].evidence)
