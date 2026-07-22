#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) {{ year }} Dexray Insight Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""B6 residual FP cleanup: "Insecure Network Configuration" cleartext URLs.

The A05 "Insecure Network Configuration" finding emitted HIGH/confirmed evidence
for documentation / placeholder / library cleartext URLs (www.google.com,
www.example.com, w3.org, ...). Those hosts are not first-party network
endpoints and must be dropped, while genuine first-party cleartext (meme.kik.com)
is kept. A cleartext-only finding is MEDIUM, not HIGH (base_analys.md A2).
"""

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.security.security_misconfiguration_assessment import (
    SecurityMisconfigurationAssessment,
)


def _strings(all_strings, urls=None):
    return {"string_analysis": {"all_strings": all_strings, "urls": urls or []}}


def _assessment():
    return SecurityMisconfigurationAssessment({"enabled": True})


def _network_finding(findings):
    matches = [f for f in findings if f.title == "Insecure Network Configuration"]
    return matches[0] if matches else None


DOC_PLACEHOLDER_URLS = [
    "http://www.google.com/something",
    "http://www.example.com/foo",
    "http://www.w3.org/TR/SVG11/feature#Foo",
    "http://schemas.android.com/apk/res/android",
    "http://xmlpull.org/v1/doc/features.html#process-docdecl",
]

FIRST_PARTY_CLEARTEXT = "http://meme.kik.com/some/path"


class TestCleartextHostFiltering:
    def test_doc_and_placeholder_urls_are_filtered_out(self):
        results = _strings(DOC_PLACEHOLDER_URLS)
        findings = _assessment()._assess_network_security_config(results)
        # No network finding at all — every cleartext URL was a doc/placeholder host.
        assert _network_finding(findings) is None

    def test_first_party_cleartext_still_flagged(self):
        results = _strings([FIRST_PARTY_CLEARTEXT])
        finding = _network_finding(_assessment()._assess_network_security_config(results))
        assert finding is not None
        assert any("meme.kik.com" in e for e in finding.evidence)

    def test_first_party_kept_and_doc_dropped_when_mixed(self):
        results = _strings(DOC_PLACEHOLDER_URLS + [FIRST_PARTY_CLEARTEXT])
        finding = _network_finding(_assessment()._assess_network_security_config(results))
        assert finding is not None
        assert any("meme.kik.com" in e for e in finding.evidence)
        for host in ("google.com", "example.com", "w3.org", "schemas.android.com", "xmlpull.org"):
            assert not any(host in e for e in finding.evidence), f"should have dropped {host}"

    def test_pure_first_party_cleartext_is_medium_not_high(self):
        results = _strings([FIRST_PARTY_CLEARTEXT])
        finding = _network_finding(_assessment()._assess_network_security_config(results))
        assert finding is not None
        assert finding.severity == AnalysisSeverity.MEDIUM

    def test_trust_bypass_signal_keeps_high(self):
        # A genuine TLS trust-bypass pattern is a strong signal -> HIGH.
        results = _strings(
            [FIRST_PARTY_CLEARTEXT, "setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)"]
        )
        finding = _network_finding(_assessment()._assess_network_security_config(results))
        assert finding is not None
        assert finding.severity == AnalysisSeverity.HIGH

    def test_host_helpers(self):
        a = _assessment()
        assert a._cleartext_url_host("prefix http://www.example.com/x suffix") == "www.example.com"
        assert a._cleartext_url_host("http://meme.kik.com:8080/x") == "meme.kik.com"
        assert a._cleartext_url_host("no url here") is None
        assert a._is_non_endpoint_host("www.google.com") is True
        assert a._is_non_endpoint_host("www.example.com") is True
        assert a._is_non_endpoint_host("meme.kik.com") is False


# Connectivity-check / test / vendor-doc / captive-portal / ad-SDK cleartext hosts
# (base_analys.md B6) that must be dropped from the network-config evidence.
CONNECTIVITY_AND_ADSDK_URLS = [
    "http://www.apple.com/library/test/success.html",  # Apple captive-portal check
    "http://mlwtkhfdxvcbrszn.neverssl.com/online",  # deliberate test host
    "http://schemas.microsoft.com/DRM/2007/03/protocols",  # namespace/schema
    "http://connectivitycheck.gstatic.com/generate_204",  # connectivity probe
    "http://clients3.google.com/generate_204",  # connectivity probe (google.com)
    "http://www.fyber.com",  # ad-SDK host
    "http://ads-test.st.ogury.com/",  # ad-SDK host
]

FIRST_PARTY_KEEP = [
    "http://meme.kik.com/x",
    "http://platform.piranhakik.com/y",
    "http://cdn.kik.com/cards/unsupported.html",
]


class TestConnectivityAndAdSdkHostFiltering:
    def test_connectivity_and_adsdk_hosts_are_dropped(self):
        results = _strings(CONNECTIVITY_AND_ADSDK_URLS)
        assert _network_finding(_assessment()._assess_network_security_config(results)) is None

    def test_first_party_kept_when_mixed_with_connectivity_noise(self):
        results = _strings(CONNECTIVITY_AND_ADSDK_URLS + FIRST_PARTY_KEEP)
        finding = _network_finding(_assessment()._assess_network_security_config(results))
        assert finding is not None
        assert finding.severity == AnalysisSeverity.MEDIUM
        for host in ("meme.kik.com", "piranhakik.com", "cdn.kik.com"):
            assert any(host in e for e in finding.evidence), f"should keep first-party {host}"
        for host in ("apple.com", "neverssl.com", "microsoft.com", "connectivitycheck", "fyber.com", "ogury.com"):
            assert not any(host in e for e in finding.evidence), f"should have dropped {host}"

    def test_non_endpoint_host_classification(self):
        a = _assessment()
        assert a._is_non_endpoint_host("www.apple.com") is True
        assert a._is_non_endpoint_host("mlwtkhfdxvcbrszn.neverssl.com") is True
        assert a._is_non_endpoint_host("schemas.microsoft.com") is True
        assert a._is_non_endpoint_host("connectivitycheck.android.com") is True
        assert a._is_non_endpoint_host("clients3.google.com") is True
        assert a._is_non_endpoint_host("www.fyber.com") is True
        assert a._is_non_endpoint_host("ads-test.st.ogury.com") is True
        # First-party hosts must never be classified as non-endpoints.
        assert a._is_non_endpoint_host("meme.kik.com") is False
        assert a._is_non_endpoint_host("platform.piranhakik.com") is False
        assert a._is_non_endpoint_host("cdn.kik.com") is False

    def test_ad_or_library_host_helper(self):
        a = _assessment()
        assert a._is_ad_or_library_host("www.fyber.com") is True
        assert a._is_ad_or_library_host("ads-test.st.ogury.com") is True
        assert a._is_ad_or_library_host("something.inmobi.com") is True
        assert a._is_ad_or_library_host("kik.com") is False
        assert a._is_ad_or_library_host("piranhakik.com") is False


class TestWeakSslStrongSignalGating:
    def test_library_des_substring_noise_stays_medium(self):
        # `DES` (in RC4|DES|3DES) matches "des" inside library identifiers such as
        # NavDestination / sortedArrayDescending / TextAppearance_Design. These are
        # NOT an SSL misconfiguration and must not escalate cleartext-only to HIGH.
        noise = [
            "isViewDescendantOf",
            "TextAppearance_Design_Hint",
            "sortedArrayDescending",
            "(Landroidx/navigation/NavDestination;)Ljava/lang/Boolean;",
        ]
        results = _strings([FIRST_PARTY_CLEARTEXT] + noise)
        finding = _network_finding(_assessment()._assess_network_security_config(results))
        assert finding is not None
        assert finding.severity == AnalysisSeverity.MEDIUM
        assert not any("Weak SSL configuration" in e for e in finding.evidence)

    def test_library_hash_substring_noise_stays_medium(self):
        # MD5/SHA1 substrings in BouncyCastle-style aliases / log messages.
        noise = ["Failed to get MD5", "MessageDigest.MD5", "sha1-scaled", "Alg.Alias.Mac.RC2"]
        results = _strings([FIRST_PARTY_CLEARTEXT] + noise)
        finding = _network_finding(_assessment()._assess_network_security_config(results))
        assert finding is not None
        assert finding.severity == AnalysisSeverity.MEDIUM

    def test_genuine_ssl_context_weak_cipher_is_high(self):
        # A weak cipher token in an actual SSL/TLS context is a genuine strong signal.
        results = _strings([FIRST_PARTY_CLEARTEXT, "SSLContext initialised with RC4 cipher suite"])
        finding = _network_finding(_assessment()._assess_network_security_config(results))
        assert finding is not None
        assert finding.severity == AnalysisSeverity.HIGH

    def test_deprecated_ssl_protocol_is_high(self):
        results = _strings([FIRST_PARTY_CLEARTEXT, "SSLv3"])
        finding = _network_finding(_assessment()._assess_network_security_config(results))
        assert finding is not None
        assert finding.severity == AnalysisSeverity.HIGH

    def test_ssl_context_helper(self):
        a = _assessment()
        assert a._has_ssl_tls_context("SSLContext with RC4") is True
        assert a._has_ssl_tls_context("negotiated cipher suite") is True
        assert a._has_ssl_tls_context("isViewDescendantOf") is False
        assert a._has_ssl_tls_context("MessageDigest.MD5") is False
