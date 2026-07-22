#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PR-9 unit tests: pure ranking / tiering primitives (risk_ranking).

These lock in the deterministic, I/O-free ranking and tiering used by both the
terminal analyst summary and the Markdown report. Every primitive is exercised
with BOTH dict findings and lightweight object findings to prove the safe getter
handles either shape.
"""

import pytest

from src.dexray_insight.results.reporting import risk_ranking


# --------------------------------------------------------------------------- #
# A minimal object-shaped finding to prove attribute access works too.
# --------------------------------------------------------------------------- #
class _ObjFinding:
    def __init__(self, severity, confidence=None, title="", category="", evidence=None,
                 recommendations=None, file_location=None):
        self.severity = severity
        self.confidence = confidence
        self.title = title
        self.category = category
        self.evidence = evidence or []
        self.recommendations = recommendations or []
        self.file_location = file_location


def _d(severity, confidence=None, title="", category="", evidence=None,
       recommendations=None, file_location=None):
    finding = {"severity": severity, "title": title, "category": category,
               "evidence": evidence or [], "recommendations": recommendations or []}
    if confidence is not None:
        finding["confidence"] = confidence
    if file_location is not None:
        finding["file_location"] = file_location
    return finding


@pytest.mark.unit
class TestSafeGetter:
    def test_dict_and_object_severity(self):
        assert risk_ranking.severity_str(_d("HIGH")) == "high"
        assert risk_ranking.severity_str(_ObjFinding("Critical")) == "critical"

    def test_enum_value_dict_severity(self):
        assert risk_ranking.severity_str({"severity": {"value": "critical"}}) == "critical"

    def test_enum_like_object_severity(self):
        class _Enum:
            value = "medium"
        assert risk_ranking.severity_str(_d("x")) == "x"
        assert risk_ranking.severity_str({"severity": _Enum()}) == "medium"

    def test_confidence_default(self):
        assert risk_ranking.confidence_of(_d("high")) == risk_ranking.DEFAULT_CONFIDENCE
        assert risk_ranking.confidence_of(_d("high", confidence=0.9)) == 0.9
        assert risk_ranking.confidence_of(_ObjFinding("high", confidence=0.1)) == 0.1

    def test_confidence_bad_value_falls_back(self):
        assert risk_ranking.confidence_of(_d("high", confidence="oops")) == risk_ranking.DEFAULT_CONFIDENCE


@pytest.mark.unit
class TestFindingScore:
    def test_score_is_weight_times_confidence(self):
        assert risk_ranking.finding_score(_d("critical", confidence=0.5)) == 10 * 0.5
        assert risk_ranking.finding_score(_d("high", confidence=1.0)) == 7.0
        assert risk_ranking.finding_score(_d("info", confidence=1.0)) == 0.0

    def test_unknown_severity_scores_zero(self):
        assert risk_ranking.finding_score(_d("nonsense", confidence=1.0)) == 0.0

    def test_default_confidence_applied(self):
        assert risk_ranking.finding_score(_d("medium")) == 4 * risk_ranking.DEFAULT_CONFIDENCE


@pytest.mark.unit
class TestRankFindings:
    def test_descending_by_score(self):
        findings = [_d("low", title="l"), _d("critical", title="c"),
                    _d("medium", title="m"), _d("high", title="h")]
        ranked = risk_ranking.rank_findings(findings)
        assert [risk_ranking.severity_str(f) for f in ranked] == ["critical", "high", "medium", "low"]

    def test_confidence_breaks_severity_ties(self):
        low = _d("high", confidence=0.3, title="unproven")
        high = _d("high", confidence=0.95, title="confirmed")
        ranked = risk_ranking.rank_findings([low, high])
        assert ranked[0]["title"] == "confirmed"

    def test_location_breaks_score_ties(self):
        # Same severity + confidence -> the one with a location ranks first.
        without = _d("high", confidence=0.7, title="a")
        withloc = _d("high", confidence=0.7, title="a", file_location={"uri": "x.smali"})
        ranked = risk_ranking.rank_findings([without, withloc])
        assert ranked[0] is withloc

    def test_title_is_final_tiebreak(self):
        a = _d("high", confidence=0.7, title="aaa")
        b = _d("high", confidence=0.7, title="zzz")
        ranked = risk_ranking.rank_findings([a, b])
        assert ranked[0]["title"] == "zzz"  # reverse sort -> 'zzz' before 'aaa'

    def test_empty_input(self):
        assert risk_ranking.rank_findings([]) == []

    def test_objects_rank_like_dicts(self):
        findings = [_ObjFinding("low", title="l"), _ObjFinding("critical", title="c")]
        ranked = risk_ranking.rank_findings(findings)
        assert ranked[0].title == "c"


@pytest.mark.unit
class TestTopRisks:
    def test_returns_top_n(self):
        findings = [_d("critical", title="1"), _d("high", title="2"),
                    _d("medium", title="3"), _d("low", title="4")]
        top = risk_ranking.top_risks(findings, 2)
        assert len(top) == 2
        assert risk_ranking.severity_str(top[0]) == "critical"
        assert risk_ranking.severity_str(top[1]) == "high"

    def test_n_larger_than_list(self):
        findings = [_d("high", title="1")]
        assert len(risk_ranking.top_risks(findings, 5)) == 1

    def test_zero_or_negative_n(self):
        findings = [_d("high", title="1")]
        assert risk_ranking.top_risks(findings, 0) == []
        assert risk_ranking.top_risks(findings, -3) == []


@pytest.mark.unit
class TestTierFindings:
    def test_confirmed_requires_high_conf_and_high_severity(self):
        findings = [
            _d("critical", confidence=0.9, title="confirmed-crit"),
            _d("high", confidence=0.75, title="confirmed-high-boundary"),
            _d("high", confidence=0.74, title="just-below"),  # -> needs_review
            _d("critical", confidence=0.5, title="low-conf-crit"),  # -> needs_review
        ]
        tiers = risk_ranking.tier_findings(findings)
        confirmed_titles = {risk_ranking.title_of(f) for f in tiers["confirmed"]}
        assert confirmed_titles == {"confirmed-crit", "confirmed-high-boundary"}

    def test_needs_review_boundaries(self):
        findings = [
            _d("high", confidence=0.40, title="review-floor"),   # review_min boundary -> needs_review
            _d("high", confidence=0.39, title="below-floor"),    # -> informational
            _d("medium", confidence=0.1, title="low-medium"),    # medium always at least review
            _d("medium", confidence=0.9, title="high-medium"),   # medium never confirmed
        ]
        tiers = risk_ranking.tier_findings(findings)
        review_titles = {risk_ranking.title_of(f) for f in tiers["needs_review"]}
        info_titles = {risk_ranking.title_of(f) for f in tiers["informational"]}
        assert "review-floor" in review_titles
        assert "low-medium" in review_titles
        assert "high-medium" in review_titles
        assert "high-medium" not in {risk_ranking.title_of(f) for f in tiers["confirmed"]}
        assert "below-floor" in info_titles

    def test_low_and_info_are_informational(self):
        findings = [_d("low", confidence=0.9, title="l"), _d("info", confidence=0.9, title="i")]
        tiers = risk_ranking.tier_findings(findings)
        info_titles = {risk_ranking.title_of(f) for f in tiers["informational"]}
        assert info_titles == {"l", "i"}

    def test_every_finding_lands_in_exactly_one_tier(self):
        findings = [
            _d("critical", confidence=0.9), _d("high", confidence=0.5),
            _d("medium", confidence=0.2), _d("low", confidence=0.9), _d("info"),
        ]
        tiers = risk_ranking.tier_findings(findings)
        total = len(tiers["confirmed"]) + len(tiers["needs_review"]) + len(tiers["informational"])
        assert total == len(findings)

    def test_custom_thresholds_from_config_dict(self):
        findings = [_d("high", confidence=0.6, title="x")]
        # With default 0.75 min -> needs_review. Lower the bar to 0.5 -> confirmed.
        config = {"output": {"security_report": {"tiers": {"high_confidence_min": 0.5, "review_min": 0.2}}}}
        tiers = risk_ranking.tier_findings(findings, config)
        assert risk_ranking.title_of(tiers["confirmed"][0]) == "x"

    def test_tiers_are_ranked(self):
        findings = [_d("high", confidence=0.8, title="lower"),
                    _d("critical", confidence=0.8, title="higher")]
        tiers = risk_ranking.tier_findings(findings)
        assert risk_ranking.title_of(tiers["confirmed"][0]) == "higher"


@pytest.mark.unit
class TestTierFindingsVerificationStatusLock:
    """R11 regression lock: a review-queue finding must never reach the confirmed tier.

    Locks the invariant in ``tier_findings`` that a HIGH-severity finding with
    ``verification_status == NEEDS_DYNAMIC`` and confidence >= 0.75 lands in
    ``needs_review`` (exploitability not statically settled), NOT ``confirmed`` —
    keeping the report's CONFIRMED tier in lockstep with the engine's confirmed subset.
    """

    def test_needs_dynamic_high_conf_high_sev_is_needs_review_not_confirmed(self):
        finding = _d("high", confidence=0.75, title="idor-endpoint")
        finding["verification_status"] = "NEEDS_DYNAMIC"
        tiers = risk_ranking.tier_findings([finding])
        review_titles = {risk_ranking.title_of(f) for f in tiers["needs_review"]}
        confirmed_titles = {risk_ranking.title_of(f) for f in tiers["confirmed"]}
        assert "idor-endpoint" in review_titles
        assert "idor-endpoint" not in confirmed_titles

    def test_needs_dynamic_lock_holds_at_very_high_confidence(self):
        finding = _d("high", confidence=0.99, title="near-certain")
        finding["verification_status"] = "NEEDS_DYNAMIC"
        tiers = risk_ranking.tier_findings([finding])
        assert "near-certain" in {risk_ranking.title_of(f) for f in tiers["needs_review"]}
        assert "near-certain" not in {risk_ranking.title_of(f) for f in tiers["confirmed"]}

    def test_genuinely_confirmed_high_conf_high_sev_is_confirmed(self):
        # Contrast: an identical finding that IS statically confirmed reaches confirmed.
        finding = _d("high", confidence=0.75, title="confirmed-high")
        finding["verification_status"] = "CONFIRMED"
        tiers = risk_ranking.tier_findings([finding])
        assert "confirmed-high" in {risk_ranking.title_of(f) for f in tiers["confirmed"]}
        assert "confirmed-high" not in {risk_ranking.title_of(f) for f in tiers["needs_review"]}


@pytest.mark.unit
class TestHintFor:
    def test_category_keyed_hint(self):
        finding = _d("high", category="A03:2021-Injection")
        assert "sink" in risk_ranking.hint_for(finding).lower()

    def test_falls_back_to_recommendation(self):
        finding = _d("high", category="Totally Unknown Category",
                     recommendations=["Do the specific thing"])
        assert risk_ranking.hint_for(finding) == "Do the specific thing"

    def test_generic_fallback(self):
        finding = _d("high", category="Totally Unknown Category")
        assert "Review" in risk_ranking.hint_for(finding)

    def test_object_finding_hint(self):
        finding = _ObjFinding("high", category="A02:2021-Cryptographic Failures")
        assert "crypto" in risk_ranking.hint_for(finding).lower()
