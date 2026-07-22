"""Tests for the full-hit cache re-emit terminal summary.

A full-hit cache re-run must still print the rich ``🛡️ SECURITY ASSESSMENT`` block
(risk scores, severity distribution, OWASP categories, TOP RISKS, CONFIRMED tiers)
rather than a two-line stub. These tests pin that contract for both the
``FullAnalysisResults.print_cached_summary`` renderer and the ``asam`` wrapper that
reconstructs it from cached dicts.
"""

from dexray_insight import asam
from dexray_insight.results.FullAnalysisResults import FullAnalysisResults


def _sample_security_dict() -> dict:
    """A representative cached security dict (a CRITICAL + a HIGH confirmed finding)."""
    return {
        "total_findings": 83,
        "overall_risk_score": 38.70,
        "risk_score_confirmed": 38.70,
        "risk_score_review_mass": 23.58,
        "findings_by_severity": {"critical": 1, "high": 7, "medium": 51, "low": 24},
        "owasp_categories_affected": [
            "OWASP Mobile Top 10 - M3",
            "A05:2021-Security Misconfiguration",
            "A10:2021-Server-Side Request Forgery (SSRF)",
        ],
        "findings": [
            {
                "category": "PRIVACY:2024-Personal Data Exposure",
                "title": "Private key stored in plaintext SharedPreferences",
                "severity": "critical",
                "confidence": 0.85,
                "verification_status": "confirmed",
                "evidence": ["kik.auth.gen.priv.key"],
            },
            {
                "category": "PRIVACY:2024-Personal Data Exposure",
                "title": "GDPR Art.9 special-category data stored at rest",
                "severity": "high",
                "confidence": 0.80,
                "verification_status": "confirmed",
                "evidence": ["Art.9 columns ['ethnicity', 'orientation', 'religion']"],
            },
        ],
    }


def _sample_main_dict() -> dict:
    return {
        "apk_overview": {
            "general_info": {
                "file_name": "base.apk",
                "app_name": "Kik",
                "package_name": "kik.android",
            }
        }
    }


# Markers that must appear for the security highlights to be considered present.
_SECURITY_MARKERS = (
    "🛡️  SECURITY ASSESSMENT",
    "Security Findings: 83",
    "Risk Score (triage aid)",
    "Severity Distribution",
    "OWASP Categories",
    "🎯 TOP RISKS",
    "✅ CONFIRMED",
)


def test_print_cached_summary_renders_full_security_block(capsys):
    results = FullAnalysisResults()
    results.security_assessment = _sample_security_dict()
    results.apk_overview.update_from_dict(_sample_main_dict()["apk_overview"])

    results.print_cached_summary(verbose=False, config=None)

    out = capsys.readouterr().out
    for marker in _SECURITY_MARKERS:
        assert marker in out, f"missing security marker: {marker!r}"
    # Confirmed tier surfaces the critical finding's title.
    assert "Private key stored in plaintext SharedPreferences" in out
    # The (from cache) marker distinguishes it from a fresh run.
    assert "(from cache)" in out


def test_asam_wrapper_reconstructs_and_prints(capsys):
    asam._print_cached_summary(
        _sample_main_dict(), _sample_security_dict(), verbose=False, config=None
    )

    out = capsys.readouterr().out
    for marker in _SECURITY_MARKERS:
        assert marker in out, f"missing security marker: {marker!r}"


def test_asam_wrapper_falls_back_without_raising(capsys):
    # A malformed security payload must not raise; it must degrade to the stub.
    asam._print_cached_summary(
        _sample_main_dict(), security_dict="not-a-dict", verbose=False, config=None
    )

    out = capsys.readouterr().out
    # The stub always prints the cache-labelled header even on degraded input.
    assert "DEXRAY INSIGHT ANALYSIS SUMMARY (from cache)" in out
