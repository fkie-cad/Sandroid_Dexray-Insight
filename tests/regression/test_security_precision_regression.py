#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PR-9 security-precision regression harness.

A FAST, deterministic, CI-safe end-to-end guard for the security-precision
overhaul. Instead of depending on ``base.apk`` (or the report JSON, which lacks
``all_strings`` / ``api_invocation``), it hand-authors a small ``combined_results``
dict carrying the exact false-positive triggers and real credentials that the
overhaul is meant to distinguish, feeds it through the real
``SecurityAssessmentEngine.assess`` pipeline, and asserts on the resulting findings.

It guards BOTH directions:

* Precision — the known false-positive triggers (Unity ``aidAd*`` constants, a
  BouncyCastle SPHINCS256 string, a base64 PNG blob, AES test-vector hex,
  descriptor/``content://``/``Serializable`` noise, valid NSC / disabled backup /
  valid SDK) must NOT produce phantom CRITICAL/HIGH findings.
* Recall — the four real client keys are still surfaced (Branch/AdMob/Crashlytics
  at LOW, AIza restriction-dependent), the deep-link / WebView / cleartext
  attack-surface findings still fire, and structural secrets (AKIA) and real
  sinks (``Runtime.exec`` / ``rawQuery``) still produce findings.

The report ranking (``risk_ranking``) is exercised too: the actionable
attack-surface findings must out-rank low-confidence heuristics.
"""

import base64

import pytest

# Importing the security package registers all OWASP assessments into the registry
# that SecurityAssessmentEngine loads from.
from src.dexray_insight import security  # noqa: F401
from src.dexray_insight.core.configuration import Configuration
from src.dexray_insight.core.security_engine import SecurityAssessmentEngine
from src.dexray_insight.results.reporting import risk_ranking

# --------------------------------------------------------------------------- #
# Fixture inputs
# --------------------------------------------------------------------------- #
# A base64 blob that decodes to a PNG header — the binary filter must reject it.
PNG_B64 = base64.b64encode(bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b"\x00" * 40).decode()

# Synthetic, real-format client keys (never live credentials).
REAL_KEYS = {
    "branch": "key_live_abcdefghijklmnopqrstuvwxyz012345",  # pragma: allowlist secret
    "admob": "ca-app-pub-1234567890123456~1234567890",
    "crashlytics": "0123456789abcdef0123456789abcdef01234567",  # pragma: allowlist secret
    "aiza": "AIzaSyCavBhXuLCGdOzaOpKn2rzP8rHxWAd3MCA",  # pragma: allowlist secret
}

# Structural false-negative recall probe: a real AWS access-key id.
AKIA_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret

# The exact false-positive triggers that previously produced phantom CRITICAL/HIGH
# findings. None of these may appear in a CRITICAL or HIGH finding.
FP_TRIGGERS = [
    "aidAdRendererContainer",
    "keyPairGenerator.SPHINCS256",
    PNG_B64,
    "2b7e151628aed2a6abf7158809cf4f3c",  # AES-128 test-vector key
    "3ad77bb40d7a3660a89ecaf32466ef97",  # AES test-vector ciphertext
]


def _build_combined_results() -> dict:
    """Hand-author the analysis dict fed to the security engine."""
    all_strings = [
        # --- false-positive triggers ---
        "aidAdRendererContainer",
        "aidAdContainerScreen",
        "keyPairGenerator.SPHINCS256",
        "org.bouncycastle.pqc.jcajce.provider.sphincs",
        PNG_B64,
        "2b7e151628aed2a6abf7158809cf4f3c",
        "3ad77bb40d7a3660a89ecaf32466ef97",
        # descriptor / IPC / deserialization noise
        "Landroidx/compose/foundation/text/DeleteSurroundingTextCommand;",
        "Landroid/database/Cursor;",
        "SELECT",
        "content://media/external/images/media/1",
        "java.io.Serializable",
        "Externalizable",
        # --- real client keys (recall) ---
        REAL_KEYS["branch"],
        REAL_KEYS["admob"],
        f"com.crashlytics.android.buildId {REAL_KEYS['crashlytics']}",
        REAL_KEYS["aiza"],
        # --- structural secret (recall) ---
        f"my_key = {AKIA_KEY}",
    ]

    return {
        "string_analysis": {
            "all_strings": all_strings,
            "urls": ["http://kik.example/api/login", "https://safe.example/x"],
            "emails": [],
        },
        "api_invocation": {
            # Real sinks -> injection recall.
            "api_calls": [
                {"called_class": "Landroid/database/sqlite/SQLiteDatabase;", "called_method": "rawQuery"},
                {"called_class": "Ljava/lang/Runtime;", "called_method": "exec"},
                {"called_class": "Landroid/webkit/WebView;", "called_method": "addJavascriptInterface"},
                {"called_class": "android.webkit.WebView", "called_method": "addJavascriptInterface"},
                {"called_class": "Landroid/webkit/WebSettings;", "called_method": "setJavaScriptEnabled"},
            ],
            "reflection_usage": [],
        },
        "apk_overview": {
            "general_info": {
                "package_name": "kik.android",
                "app_name": "Kik",
                "target_sdk": 36,
                "min_sdk": 24,
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "a" * 64,
            },
            "components": {
                "exported_activities": ["kik.android.chat.KikApiLandingActivity"],
            },
            # First-party exported browsable deep-link activity.
            "browsable_activities": {
                "kik.android.chat.KikApiLandingActivity": {
                    "schemes": ["kik://", "kik://age-verification"],
                    "hosts": [],
                    "paths": [],
                }
            },
            # Valid NSC + disabled backup: the "no NSC" / "backup enabled" findings
            # must NOT fire. uses_cleartext_traffic=True + first-party http feeds the
            # cleartext finding.
            "manifest_security": {
                "uses_cleartext_traffic": True,
                "network_security_config": "@xml/nsc",
                "allow_backup": False,
                "debuggable": False,
            },
        },
        # SDK versions where the vulnerable-components assessment reads them: valid
        # values so no "SDK 0 / minimum SDK" framework-version finding is emitted.
        "manifest_analysis": {
            "target_sdk_version": 36,
            "min_sdk_version": 24,
        },
    }


# --------------------------------------------------------------------------- #
# Shared, run-once fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def assessment():
    config = Configuration()
    config.config["security"]["enable_owasp_assessment"] = True
    engine = SecurityAssessmentEngine(config)
    return engine.assess(_build_combined_results())


@pytest.fixture(scope="module")
def findings_dicts(assessment):
    """Findings as serialized dicts — the exact shape the report path consumes."""
    return assessment.to_dict()["findings"]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _by_severity(findings, severity):
    return [f for f in findings if risk_ranking.severity_str(f) == severity]


def _evidence_blob(finding) -> str:
    return "\n".join(str(e) for e in (risk_ranking.get_attr(finding, "evidence", []) or []))


def _titles(findings):
    return [risk_ranking.title_of(f) for f in findings]


def _find_title_contains(findings, needle):
    return [f for f in findings if needle.lower() in risk_ranking.title_of(f).lower()]


# --------------------------------------------------------------------------- #
# Precision: no phantom CRITICAL / HIGH from false-positive triggers
# --------------------------------------------------------------------------- #
@pytest.mark.regression
@pytest.mark.security
class TestPrecision:
    def test_no_fp_trigger_in_any_critical_or_high(self, findings_dicts):
        high_impact = _by_severity(findings_dicts, "critical") + _by_severity(findings_dicts, "high")
        for finding in high_impact:
            blob = _evidence_blob(finding)
            for trigger in FP_TRIGGERS:
                assert trigger not in blob, (
                    f"False-positive trigger {trigger!r} leaked into a "
                    f"{risk_ranking.severity_str(finding).upper()} finding: {risk_ranking.title_of(finding)}"
                )

    def test_only_critical_secret_is_the_real_akia(self, findings_dicts):
        criticals = _by_severity(findings_dicts, "critical")
        # Exactly one critical secret finding, and it is the AKIA structural key.
        assert len(criticals) == 1, f"Unexpected CRITICAL findings: {_titles(criticals)}"
        assert AKIA_KEY in _evidence_blob(criticals[0])

    def test_no_evidence_free_high_findings(self, findings_dicts):
        for finding in _by_severity(findings_dicts, "high"):
            assert _evidence_blob(finding).strip(), (
                f"Evidence-free HIGH finding: {risk_ranking.title_of(finding)}"
            )

    def test_high_findings_are_sink_backed_not_substrings(self, findings_dicts):
        # The only HIGH findings should be the evidence/sink-backed data-storage
        # (rawQuery) and communication (cleartext) findings — never a bare
        # SQL/command/crypto/mobile substring promoted to HIGH.
        highs = _by_severity(findings_dicts, "high")
        for finding in highs:
            blob = _evidence_blob(finding).lower()
            assert any(marker in blob for marker in ("rawquery", "cleartext", "http://", "sqlite")), (
                f"Unexpected HIGH not backed by a sink/URL: {risk_ranking.title_of(finding)} :: {blob[:120]}"
            )

    def test_png_blob_rejected_by_binary_filter(self, findings_dicts):
        blob = "\n".join(_evidence_blob(f) for f in findings_dicts)
        assert PNG_B64 not in blob, "Base64 PNG blob should be rejected by the binary filter"

    def test_no_framework_version_or_sdk_zero_finding(self, findings_dicts):
        assert _find_title_contains(findings_dicts, "Framework Version") == []
        full_blob = "\n".join(f"{risk_ranking.title_of(f)} {_evidence_blob(f)}" for f in findings_dicts)
        assert "SDK 0" not in full_blob
        assert "Minimum SDK 0" not in full_blob

    def test_no_missing_nsc_or_backup_enabled_finding(self, findings_dicts):
        titles_blob = " ".join(_titles(findings_dicts)).lower()
        assert "network security config" not in titles_blob
        assert "backup" not in titles_blob


# --------------------------------------------------------------------------- #
# Recall: real credentials, attack surface, and sinks are still surfaced
# --------------------------------------------------------------------------- #
@pytest.mark.regression
@pytest.mark.security
class TestRecall:
    def test_four_real_keys_surfaced(self, findings_dicts):
        blob = "\n".join(_evidence_blob(f) for f in findings_dicts)
        for name, value in REAL_KEYS.items():
            assert value in blob, f"Real key {name} ({value}) was not surfaced"

    def test_branch_admob_crashlytics_at_low(self, findings_dicts):
        low_blob = "\n".join(_evidence_blob(f) for f in _by_severity(findings_dicts, "low"))
        assert REAL_KEYS["branch"] in low_blob, "Branch key should surface at LOW (client-side)"
        assert REAL_KEYS["admob"] in low_blob, "AdMob id should surface at LOW (client-side)"
        assert REAL_KEYS["crashlytics"] in low_blob, "Crashlytics key should surface at LOW (client-side)"

    def test_aiza_key_is_restriction_dependent_not_low(self, findings_dicts):
        # AIza danger depends on server-side restrictions -> never fully suppressed to
        # the LOW client-side tier; it surfaces at the MEDIUM (restriction-dependent) floor.
        medium_blob = "\n".join(_evidence_blob(f) for f in _by_severity(findings_dicts, "medium"))
        assert REAL_KEYS["aiza"] in medium_blob, "AIza key should surface at the MEDIUM restriction-dependent floor"

    def test_deeplink_webview_cleartext_present(self, findings_dicts):
        assert _find_title_contains(findings_dicts, "Deep-Link Activity"), "Deep-link finding missing"
        assert _find_title_contains(findings_dicts, "WebView JavaScript Bridge"), "WebView JS bridge finding missing"
        # Cleartext surfaces both as the misconfiguration finding and the M3 comms finding.
        assert _find_title_contains(findings_dicts, "Cleartext") or _find_title_contains(
            findings_dicts, "Insecure Communication"
        ), "Cleartext finding missing"

    def test_akia_secret_still_flagged(self, findings_dicts):
        blob = "\n".join(_evidence_blob(f) for f in findings_dicts)
        assert AKIA_KEY in blob, "Structural AKIA secret must still be flagged (false-negative guard)"

    def test_real_sql_and_command_sinks_flagged(self, findings_dicts):
        assert _find_title_contains(findings_dicts, "SQL Injection"), "rawQuery SQL sink not flagged"
        assert _find_title_contains(findings_dicts, "Command Injection"), "Runtime.exec command sink not flagged"


# --------------------------------------------------------------------------- #
# Report ranking: actionable attack surface out-ranks low-confidence heuristics
# --------------------------------------------------------------------------- #
@pytest.mark.regression
@pytest.mark.security
class TestRanking:
    def test_deeplink_and_webview_outrank_low_confidence_heuristics(self, findings_dicts):
        ranked = risk_ranking.rank_findings(findings_dicts)
        positions = {id(f): i for i, f in enumerate(ranked)}

        deeplink = _find_title_contains(findings_dicts, "Deep-Link Activity")[0]
        webview = _find_title_contains(findings_dicts, "WebView JavaScript Bridge")[0]

        # Every low-confidence (<= 0.3) heuristic finding must rank BELOW both the
        # deep-link and the WebView findings.
        low_conf = [f for f in findings_dicts if risk_ranking.confidence_of(f) <= 0.3]
        assert low_conf, "Expected some low-confidence heuristic findings in the fixture"
        for finding in low_conf:
            assert positions[id(deeplink)] < positions[id(finding)], (
                f"Deep-link finding did not out-rank low-confidence heuristic: {risk_ranking.title_of(finding)}"
            )
            assert positions[id(webview)] < positions[id(finding)], (
                f"WebView finding did not out-rank low-confidence heuristic: {risk_ranking.title_of(finding)}"
            )

    def test_top_risks_are_high_value(self, findings_dicts):
        top = risk_ranking.top_risks(findings_dicts, 5)
        # The single confirmed CRITICAL (AKIA) must lead the ranking.
        assert risk_ranking.severity_str(top[0]) == "critical"
        # No pure LOW-confidence posture note should crowd into the top 5 above the
        # sink-backed findings.
        assert all(risk_ranking.finding_score(f) > 0.3 for f in top)
