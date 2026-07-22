#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) {{ year }} Dexray Insight Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""PR-3: evidence-required OWASP heuristics.

These tests exercise both directions of the precision overhaul:
* Kik-style false-positive inputs (descriptor co-occurrence, content://,
  bare Serializable, benign substrings) must NOT produce evidence-free findings.
* Real API sinks / whole-word algorithm arguments must still be flagged.
* False-negative guard: reflective command execution must still surface.
"""

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.security.evidence import collect_weak_crypto_evidence
from src.dexray_insight.security.evidence import has_sink
from src.dexray_insight.security.evidence import is_probably_code_identifier
from src.dexray_insight.security.evidence import list_weak_command_signals
from src.dexray_insight.security.evidence import looks_like_type_descriptor
from src.dexray_insight.security.evidence import matches_algorithm_token
from src.dexray_insight.security.evidence.sinks import extract_algorithm_argument
from src.dexray_insight.security.injection_assessment import InjectionAssessment
from src.dexray_insight.security.integrity_failures_assessment import IntegrityFailuresAssessment
from src.dexray_insight.security.mobile_specific_assessment import MobileSpecificAssessment
from src.dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
from src.dexray_insight.security.ssrf_assessment import SSRFAssessment


def _strings(all_strings, urls=None):
    return {"string_analysis": {"all_strings": all_strings, "urls": urls or []}}


def _api(api_calls=None, reflection_usage=None):
    return {"api_invocation": {"api_calls": api_calls or [], "reflection_usage": reflection_usage or []}}


# ---------------------------------------------------------------------------
# Evidence primitives
# ---------------------------------------------------------------------------
class TestEvidencePrimitives:
    def test_type_descriptor_detection(self):
        assert looks_like_type_descriptor("Landroidx/compose/foundation/text/DeleteSurroundingTextCommand;")
        assert looks_like_type_descriptor("Ljava/lang/String;")
        assert looks_like_type_descriptor("[Lcom/example/Foo;")
        assert looks_like_type_descriptor("androidx/compose/ui/Modifier")
        assert not looks_like_type_descriptor("a real query with spaces and = signs")
        assert not looks_like_type_descriptor("SomeDescriptor")

    def test_code_identifier(self):
        assert is_probably_code_identifier("DeleteSurroundingTextCommand")
        assert is_probably_code_identifier("Ljava/lang/String;")
        assert not is_probably_code_identifier("SELECT id FROM t")
        assert not is_probably_code_identifier("rm -rf /; echo hi")

    def test_whole_word_algorithm_matching(self):
        assert matches_algorithm_token("DES/ECB/PKCS5Padding", "DES")
        assert matches_algorithm_token('MessageDigest.getInstance("MD5")', "MD5")
        # Substring false positives are rejected.
        assert not matches_algorithm_token("SomeDescriptor", "DES")
        assert not matches_algorithm_token("desktop", "DES")
        assert not matches_algorithm_token("adDescriptor.bids", "DES")

    def test_extract_algorithm_argument(self):
        assert extract_algorithm_argument('Cipher.getInstance("DES/ECB/PKCS5Padding")') == "DES/ECB/PKCS5Padding"
        assert extract_algorithm_argument("no crypto factory call here") is None

    def test_sink_matching_smali_and_dotted(self):
        smali = _api([{"called_class": "Ljava/io/ObjectInputStream;", "called_method": "readObject"}])
        dotted = _api([{"called_class": "java.io.ObjectInputStream", "called_method": "readObject"}])
        assert has_sink(smali, "deserialization")
        assert has_sink(dotted, "deserialization")
        assert not has_sink(_api([]), "deserialization")


# ---------------------------------------------------------------------------
# Injection
# ---------------------------------------------------------------------------
class TestInjection:
    def test_descriptor_only_strings_no_sink_yield_no_sql_finding(self):
        results = {
            **_strings(
                [
                    "Landroidx/compose/foundation/text/DeleteSurroundingTextCommand;",
                    "SELECT",
                    "Landroid/database/Cursor;",
                ]
            ),
            **_api([]),
        }
        findings = InjectionAssessment({"enabled": True}).assess(results)
        sql = [f for f in findings if f.title.startswith("SQL Injection")]
        # No sink and no real query shape -> no finding at all (not even LOW).
        assert sql == []

    def test_real_sql_sink_raises_finding(self):
        results = {
            **_strings([]),
            **_api([{"called_class": "Landroid/database/sqlite/SQLiteDatabase;", "called_method": "rawQuery"}]),
        }
        findings = InjectionAssessment({"enabled": True}).assess(results)
        sql = [f for f in findings if f.title.startswith("SQL Injection")]
        assert len(sql) == 1
        assert sql[0].severity in (AnalysisSeverity.MEDIUM, AnalysisSeverity.HIGH)
        assert sql[0].confidence and sql[0].confidence >= 0.7

    def test_string_only_sql_demoted_to_low_when_require_sink(self):
        results = {
            **_strings(['String q = "SELECT name FROM users WHERE id = " + userId;']),
            **_api([]),
        }
        findings = InjectionAssessment({"enabled": True}).assess(results)
        sql = [f for f in findings if f.title.startswith("SQL Injection")]
        assert len(sql) == 1
        assert sql[0].severity == AnalysisSeverity.LOW
        assert "unproven" in sql[0].title.lower()

    def test_string_only_sql_medium_when_require_sink_false(self):
        results = {
            **_strings(['String q = "SELECT name FROM users WHERE id = " + userId;']),
            **_api([]),
        }
        findings = InjectionAssessment({"enabled": True, "require_sink": False}).assess(results)
        sql = [f for f in findings if f.title.startswith("SQL Injection")]
        assert len(sql) == 1
        assert sql[0].severity == AnalysisSeverity.MEDIUM

    def test_command_false_negative_guard_reflective_runtime_exec(self):
        # Obfuscated app: no direct Runtime.exec sink, but reflection reveals it.
        results = {
            **_strings([]),
            **_api(reflection_usage=['Class.forName("java.lang.Runtime")', "Method.invoke(m, args)"]),
        }
        findings = InjectionAssessment({"enabled": True}).assess(results)
        cmd = [f for f in findings if f.title.startswith("Command Injection")]
        assert len(cmd) >= 1  # still surfaced, not silently cleared

    def test_command_hard_sink(self):
        results = {**_strings([]), **_api([{"called_class": "Ljava/lang/Runtime;", "called_method": "exec"}])}
        findings = InjectionAssessment({"enabled": True}).assess(results)
        cmd = [f for f in findings if f.title.startswith("Command Injection")]
        assert len(cmd) == 1
        assert cmd[0].severity in (AnalysisSeverity.MEDIUM, AnalysisSeverity.HIGH)

    def test_ldap_demoted_and_requires_uri(self):
        # "search"/"directory" substrings alone are no longer evidence.
        no_uri = {**_strings(["performDirectorySearch(userInput)"]), **_api([])}
        findings = InjectionAssessment({"enabled": True}).assess(no_uri)
        assert [f for f in findings if "LDAP" in f.title] == []

        with_uri = {**_strings(['String f = "ldap://host/" + userInput;']), **_api([])}
        findings = InjectionAssessment({"enabled": True}).assess(with_uri)
        ldap = [f for f in findings if "LDAP" in f.title]
        assert len(ldap) == 1
        assert ldap[0].severity == AnalysisSeverity.LOW


# ---------------------------------------------------------------------------
# Weak cryptography
# ---------------------------------------------------------------------------
class TestWeakCrypto:
    def test_cipher_getinstance_des_flagged(self):
        results = {**_strings(['Cipher.getInstance("DES/ECB/PKCS5Padding")']), **_api([])}
        evidence = collect_weak_crypto_evidence(results, results["string_analysis"]["all_strings"])
        assert evidence

    def test_crypto_usage_algorithm_flagged(self):
        results = {"api_invocation": {"crypto_usage": [{"algorithm": "MD5", "location": "A.java:1"}]}}
        assert collect_weak_crypto_evidence(results, [])

    def test_descriptor_and_benign_substrings_not_flagged(self):
        benign = ["SomeDescriptor", "desktop", "adDescriptor.bids", "Landroidx/foo/DescriptorFactory;"]
        results = {**_strings(benign), **_api([])}
        assert collect_weak_crypto_evidence(results, benign) == []
        # And the full assessment produces no weak-crypto finding either.
        findings = SensitiveDataAssessment({"enabled": True}).assess(results)
        assert [f for f in findings if "Weak Cryptographic" in f.title] == []

    def test_sensitive_data_flags_real_des(self):
        results = {**_strings(['Cipher.getInstance("DES")']), **_api([])}
        findings = SensitiveDataAssessment({"enabled": True}).assess(results)
        assert [f for f in findings if "Weak Cryptographic" in f.title]

    # -- base_analys.md B6: library-internal / provider / prose false positives --
    #
    # The six strings below are real evidence text observed on a library-heavy
    # APK. None are first-party weak-crypto usage; the bare whole-word path must
    # reject every one of them.
    B6_FALSE_POSITIVE_STRINGS = [
        "File MD5 check fail.",  # prose / log sentence
        "KeyStore.PKCS12-3DES-3DES",  # JCA KeyStore provider alias
        "org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$MD4",  # dotted class
        "HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature)",  # provider descriptor
        "Alg.Alias.Mac.RC2/CFB8",  # BouncyCastle provider alias registration
        "Failed to get MD5",  # prose / log sentence
    ]

    def test_b6_library_provider_prose_strings_yield_no_evidence(self):
        results = {**_strings(self.B6_FALSE_POSITIVE_STRINGS), **_api([])}
        assert collect_weak_crypto_evidence(results, self.B6_FALSE_POSITIVE_STRINGS) == []

    def test_b6_each_false_positive_rejected_individually(self):
        for fp in self.B6_FALSE_POSITIVE_STRINGS:
            results = {**_strings([fp]), **_api([])}
            assert collect_weak_crypto_evidence(results, [fp]) == [], f"should reject: {fp!r}"

    def test_b6_library_heavy_app_produces_no_high_weak_crypto_finding(self):
        results = {**_strings(self.B6_FALSE_POSITIVE_STRINGS), **_api([])}
        findings = SensitiveDataAssessment({"enabled": True}).assess(results)
        assert [f for f in findings if "Weak Cryptographic" in f.title] == []

    def test_genuine_getinstance_md5_still_flagged(self):
        # #2a getInstance-argument path stays intact.
        strings = ['MessageDigest.getInstance("MD5")']
        results = {**_strings(strings), **_api([])}
        assert collect_weak_crypto_evidence(results, strings)

    def test_genuine_getinstance_des_transformation_still_flagged(self):
        strings = ['Cipher.getInstance("DES/CBC/PKCS5Padding")']
        results = {**_strings(strings), **_api([])}
        assert collect_weak_crypto_evidence(results, strings)

    def test_genuine_structured_crypto_usage_md5_still_flagged(self):
        # #1 structured api_invocation crypto_usage path stays intact.
        results = {"api_invocation": {"crypto_usage": [{"algorithm": "MD5", "location": "Enc.java:42"}]}}
        assert collect_weak_crypto_evidence(results, [])

    # -- B6 residual bare-token / header / label false positives (this session) --
    #
    # A mere MENTION of an algorithm name (a bare token, an HTTP header name, or a
    # ``<Algo> Parameters`` label) is not weak-crypto usage. These live-run HIGH
    # false positives must all yield NO evidence via the bare whole-word path.
    B6_BARE_TOKEN_FALSE_POSITIVES = ["RC2", "Md5", "sha1", "x-kik-content-md5", "RC2 Parameters"]

    def test_b6_bare_token_and_header_false_positives_yield_no_evidence(self):
        results = {**_strings(self.B6_BARE_TOKEN_FALSE_POSITIVES), **_api([])}
        assert collect_weak_crypto_evidence(results, self.B6_BARE_TOKEN_FALSE_POSITIVES) == []

    def test_b6_bare_token_false_positives_rejected_individually(self):
        for fp in self.B6_BARE_TOKEN_FALSE_POSITIVES:
            results = {**_strings([fp]), **_api([])}
            assert collect_weak_crypto_evidence(results, [fp]) == [], f"should reject: {fp!r}"

    def test_b6_bare_tokens_produce_no_high_weak_crypto_finding(self):
        results = {**_strings(self.B6_BARE_TOKEN_FALSE_POSITIVES), **_api([])}
        findings = SensitiveDataAssessment({"enabled": True}).assess(results)
        assert [f for f in findings if "Weak Cryptographic" in f.title] == []


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------
class TestSSRF:
    def test_content_and_file_uris_not_internal_service(self):
        strings = ["content://media/external/images/media/1", "file:///android_asset/index.html"]
        results = _strings(strings, urls=strings)
        findings = SSRFAssessment({"enabled": True}).assess(results)
        internal = [f for f in findings if "Internal Service" in f.title]
        assert internal == []

    def test_real_internal_http_host_flagged(self):
        strings = ["http://10.0.0.1/admin/config"]
        results = _strings(strings, urls=strings)
        findings = SSRFAssessment({"enabled": True}).assess(results)
        internal = [f for f in findings if "Internal Service" in f.title]
        assert len(internal) == 1
        # Unprovable without a user-controlled sink -> demoted to LOW.
        assert internal[0].severity == AnalysisSeverity.LOW


# ---------------------------------------------------------------------------
# Integrity failures
# ---------------------------------------------------------------------------
class TestIntegrity:
    def test_bare_serializable_gson_no_high_rce(self):
        strings = ["java.io.Serializable", "new Gson().fromJson(data, Foo.class)", "Externalizable"]
        results = {**_strings(strings), **_api([])}
        findings = IntegrityFailuresAssessment({"enabled": True}).assess(results)
        deser = [f for f in findings if "Deserialization" in f.title]
        assert deser == []
        # No MEDIUM per-absence finding either; only a LOW posture note.
        assert all(f.severity == AnalysisSeverity.LOW for f in findings)

    def test_real_readobject_sink_high(self):
        results = {
            **_strings([]),
            **_api([{"called_class": "Ljava/io/ObjectInputStream;", "called_method": "readObject"}]),
        }
        findings = IntegrityFailuresAssessment({"enabled": True}).assess(results)
        deser = [f for f in findings if "Deserialization" in f.title]
        assert len(deser) == 1
        assert deser[0].severity == AnalysisSeverity.HIGH


# ---------------------------------------------------------------------------
# Mobile-specific
# ---------------------------------------------------------------------------
class TestMobileSpecific:
    def test_compose_media_descriptors_no_substring_highs(self):
        strings = [
            "Landroidx/compose/foundation/text/DeleteSurroundingTextCommand;",
            "Landroid/media/MediaCodec;",
            "getExternalFilesDir(",  # benign scoped storage, previously an M2 HIGH
            "HttpURLConnection",  # benign, previously an M3 HIGH
            "rawQuery",  # bare token, previously an M2 HIGH
            'MessageDigest.getInstance("SHA-256")',  # strong algo, must NOT flag
        ]
        results = {**_strings(strings), **_api([]), "manifest_analysis": {}}
        findings = MobileSpecificAssessment({"enabled": True}).assess(results)
        highs = [f for f in findings if f.severity == AnalysisSeverity.HIGH]
        assert highs == []

    def test_m9_does_not_assert_no_obfuscation_from_missing_literal(self):
        # No "proguard"/"obfuscat" literal present.
        results = {**_strings(["Landroidx/foo/Bar;", "some.random.string"]), **_api([]), "manifest_analysis": {}}
        findings = MobileSpecificAssessment({"enabled": True}).assess(results)
        # The old absolute "Insufficient Reverse Engineering Protection" finding is gone.
        assert [f for f in findings if "Insufficient Reverse Engineering" in f.title] == []
        posture = [f for f in findings if "Hardening Posture" in f.title]
        assert len(posture) == 1
        assert posture[0].severity == AnalysisSeverity.LOW
        assert posture[0].confidence == 0.2

    def test_real_weak_crypto_still_flagged(self):
        results = {**_strings(['Cipher.getInstance("DES/CBC/NoPadding")']), **_api([]), "manifest_analysis": {}}
        findings = MobileSpecificAssessment({"enabled": True}).assess(results)
        m5 = [f for f in findings if "Insufficient Cryptography" in f.title]
        assert len(m5) == 1

    def test_weak_command_signals_helper(self):
        results = _api(reflection_usage=["invoke Runtime exec"])
        assert list_weak_command_signals(results)


# ---------------------------------------------------------------------------
# base_analys.md B6: SSRF / injection false positives on library format-string
# URL constants (ad-SDK / Play-Store %s/%d templates). These must NOT produce a
# HIGH SSRF or a confirmed injection finding, while genuine first-party
# user-controlled sinks must still fire.
# ---------------------------------------------------------------------------
from src.dexray_insight.security.ssrf_assessment import _is_library_origin_url  # noqa: E402
from src.dexray_insight.security.ssrf_assessment import _url_looks_user_controlled  # noqa: E402

# The two exact evidence strings base_analys.md B6 flagged as false positives.
B6_LIBRARY_URL_CONSTANTS = [
    "https://ads.pubmatic.com/AdServer/js/pwt/%s/%d/config.json",
    "https://play.google.com/store/apps/details?id=%s",
]


class TestB6UrlOriginHelpers:
    def test_ad_sdk_host_is_library_origin(self):
        assert _is_library_origin_url("https://ads.pubmatic.com/AdServer/js/pwt/%s/%d/config.json")

    def test_play_store_host_is_library_origin_via_reversed_package(self):
        # play.google.com -> com.google.play matches the com.google. framework prefix.
        assert _is_library_origin_url("https://play.google.com/store/apps/details?id=%s")

    def test_first_party_host_is_not_library_origin(self):
        assert not _is_library_origin_url("https://api.myfirstpartyapp.example/user/%s/profile")

    def test_bare_template_not_user_controlled(self):
        assert not _url_looks_user_controlled("https://cdn.example/assets/%s.png")

    def test_interpolated_user_token_is_user_controlled(self):
        assert _url_looks_user_controlled("https://api.myapp.example/fetch?redirect=%s&user=1")


class TestB6SSRFFalsePositives:
    def test_ad_sdk_format_string_urls_no_high_ssrf(self):
        results = _strings(B6_LIBRARY_URL_CONSTANTS, urls=B6_LIBRARY_URL_CONSTANTS)
        findings = SSRFAssessment({"enabled": True}).assess(results)
        # No HIGH SSRF finding of any kind.
        assert [f for f in findings if f.severity == AnalysisSeverity.HIGH] == []
        # The "Potential SSRF Vulnerability" (HIGH) title must not be present.
        assert [f for f in findings if f.title == "Potential SSRF Vulnerability"] == []
        # Library-origin templates are dropped entirely, not even a review item.
        assert [f for f in findings if "Dynamic URL Template" in f.title] == []

    def test_first_party_bare_template_is_low_review_not_high(self):
        url = "https://api.myfirstpartyapp.example/assets/%s.json"
        results = _strings([url], urls=[url])
        findings = SSRFAssessment({"enabled": True}).assess(results)
        assert [f for f in findings if f.severity == AnalysisSeverity.HIGH] == []
        review = [f for f in findings if "Dynamic URL Template" in f.title]
        assert len(review) == 1
        assert review[0].severity == AnalysisSeverity.LOW

    def test_genuine_user_controlled_url_sink_still_high(self):
        # Code-level user-controlled URL construction remains a HIGH SSRF finding.
        results = _strings(["Intent.setData(Uri.parse(userInput))"], urls=[])
        findings = SSRFAssessment({"enabled": True}).assess(results)
        high = [f for f in findings if f.title == "Potential SSRF Vulnerability"]
        assert len(high) == 1
        assert high[0].severity == AnalysisSeverity.HIGH

    def test_first_party_user_controlled_dynamic_url_still_high(self):
        url = "https://api.myfirstpartyapp.example/fetch?redirect=%s&user=1"
        results = _strings([url], urls=[url])
        findings = SSRFAssessment({"enabled": True}).assess(results)
        high = [f for f in findings if f.title == "Potential SSRF Vulnerability"]
        assert len(high) == 1
        assert high[0].severity == AnalysisSeverity.HIGH


class TestB6InjectionFalsePositives:
    def test_ad_sdk_format_string_urls_no_injection_finding(self):
        results = {**_strings(B6_LIBRARY_URL_CONSTANTS, urls=B6_LIBRARY_URL_CONSTANTS), **_api([])}
        findings = InjectionAssessment({"enabled": True}).assess(results)
        api = [f for f in findings if "API and Data Injection" in f.title]
        # Library-origin URLs are dropped: no injection finding at all.
        assert api == []

    def test_library_class_descriptor_not_injection_sink(self):
        # A Room/protobuf class descriptor must not be a first-party sink.
        descriptor = "Landroidx/room/RoomDatabase$parse_user_input;"
        results = {**_strings([descriptor], urls=[]), **_api([])}
        findings = InjectionAssessment({"enabled": True}).assess(results)
        assert [f for f in findings if "API and Data Injection" in f.title] == []

    def test_first_party_bare_template_url_is_low_review(self):
        url = "https://api.myfirstpartyapp.example/assets/%s.json"
        results = {**_strings([url], urls=[url]), **_api([])}
        findings = InjectionAssessment({"enabled": True}).assess(results)
        api = [f for f in findings if "API and Data Injection" in f.title]
        assert len(api) == 1
        assert api[0].severity == AnalysisSeverity.LOW
        assert "unproven" in api[0].title.lower()

    def test_first_party_user_param_url_still_medium(self):
        url = "https://api.myfirstpartyapp.example/query?user=%s"
        results = {**_strings([url], urls=[url]), **_api([])}
        findings = InjectionAssessment({"enabled": True}).assess(results)
        api = [f for f in findings if f.title == "API and Data Injection Risks"]
        assert len(api) == 1
        assert api[0].severity == AnalysisSeverity.MEDIUM

    def test_genuine_first_party_sql_sink_still_fires(self):
        # First-party SQL sink path is untouched and still fires MEDIUM/HIGH.
        results = {
            **_strings([]),
            **_api([{"called_class": "Landroid/database/sqlite/SQLiteDatabase;", "called_method": "rawQuery"}]),
        }
        findings = InjectionAssessment({"enabled": True}).assess(results)
        sql = [f for f in findings if f.title.startswith("SQL Injection")]
        assert len(sql) == 1
        assert sql[0].severity in (AnalysisSeverity.MEDIUM, AnalysisSeverity.HIGH)
