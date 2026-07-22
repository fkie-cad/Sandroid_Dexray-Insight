#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) {{ year }} Dexray Insight Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""B6 residual FP cleanup: "Weak Cryptographic Design" fires on ad-SDK JavaScript.

The A04 insecure-design assessment appended a "Non-cryptographic randomness"
evidence item for any string matching ``new Random()`` / ``Math.random()`` and
then built a HIGH "Weak Cryptographic Design" finding. On a real APK this fired
on bundled ad-SDK / library JavaScript blobs (OMID, MRAID, ...) whose minified JS
calls ``Math.random()``. Those are library web content, not first-party crypto,
so they must not seed the HIGH finding (base_analys.md B6). Genuine first-party
non-crypto randomness (a real ``Math.random()`` token in app code) is still kept.
"""

from src.dexray_insight.security.insecure_design_assessment import InsecureDesignAssessment


def _assessment():
    return InsecureDesignAssessment({"enabled": True})


def _results(all_strings):
    return {"string_analysis": {"all_strings": all_strings}}


def _crypto_finding(findings):
    matches = [f for f in findings if f.title == "Weak Cryptographic Design"]
    return matches[0] if matches else None


OMID_JS = (
    ";(function(omidGlobal) {\n 'use strict';var n;function aa(a){var b=0;"
    "return function(){return b<a.length?{done:!1,value:a[b++]}:{done:!0}}}"
    "var r=Math.random();return r}(this));"
)
MRAID_JS = (
    "javascript:'use strict';var _typeof=typeof Symbol===\"function\"?"
    "function(o){return typeof o}:function(o){return o};window.mraid=Math.random()=="
)


class TestJavaScriptBlobDetection:
    def test_omid_blob_recognised_as_javascript(self):
        assert InsecureDesignAssessment._looks_like_embedded_javascript(OMID_JS) is True

    def test_mraid_javascript_uri_recognised(self):
        assert InsecureDesignAssessment._looks_like_embedded_javascript(MRAID_JS) is True

    def test_first_party_random_token_not_javascript(self):
        assert InsecureDesignAssessment._looks_like_embedded_javascript("Math.random()") is False
        assert InsecureDesignAssessment._looks_like_embedded_javascript("new Random()") is False


class TestWeakCryptoDesignFalsePositive:
    def test_ad_sdk_js_does_not_fire_weak_crypto(self):
        findings = _assessment()._assess_cryptographic_design(_results([OMID_JS, MRAID_JS]))
        assert _crypto_finding(findings) is None

    def test_framework_origin_random_is_downranked(self):
        # A framework/ad-SDK-origin string (matched by the package allowlist) that
        # contains new Random() must not seed a first-party weak-crypto finding.
        findings = _assessment()._assess_cryptographic_design(
            _results(["com.applovin.impl.sdk uses new Random() internally"])
        )
        assert _crypto_finding(findings) is None

    def test_no_first_party_weak_crypto_means_no_finding(self):
        # Benign library strings only -> no weak crypto design finding at all.
        findings = _assessment()._assess_cryptographic_design(
            _results(["SomeBenignString", "androidx.compose.Foo"])
        )
        assert _crypto_finding(findings) is None


class TestGenuineFirstPartyRandomnessKept:
    def test_first_party_math_random_still_flagged(self):
        # A genuine first-party Math.random() token (not JS, not library origin)
        # still produces the weak-crypto design finding.
        findings = _assessment()._assess_cryptographic_design(_results(["Math.random()"]))
        finding = _crypto_finding(findings)
        assert finding is not None
        assert any("Non-cryptographic randomness" in e for e in finding.evidence)

    def test_first_party_new_random_still_flagged(self):
        findings = _assessment()._assess_cryptographic_design(_results(["value = new Random()"]))
        finding = _crypto_finding(findings)
        assert finding is not None
        assert any("Non-cryptographic randomness" in e for e in finding.evidence)
