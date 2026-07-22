#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for A04 Insecure Data Flow Design false-positive reduction.

A bare ``Uri.parse(this)`` is ubiquitous and is NOT evidence of an insecure data
flow. It must not yield a HIGH/confirmed finding — it is down-ranked to a MEDIUM
review-queue lead. A genuine source->sink conjunction (sensitive keyword flowing
into a concrete sink) must still fire HIGH/confirmed.
"""

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.core.base_classes import VerificationStatus
from src.dexray_insight.security.insecure_design_assessment import InsecureDesignAssessment


def _results(all_strings):
    return {"string_analysis": {"all_strings": all_strings}}


def _flow(findings):
    return [f for f in findings if f.title == "Insecure Data Flow Design"]


class TestInsecureDataFlowFalsePositives:
    def test_bare_uri_parse_not_high_confirmed(self):
        """`Uri.parse(this)` alone must not be HIGH/confirmed."""
        assessment = InsecureDesignAssessment({"enabled": True})
        findings = assessment._assess_insecure_data_flows(_results(["Uri.parse(this)"]))
        flow = _flow(findings)
        # Either no finding, or a down-ranked review-queue finding — never HIGH/confirmed.
        for f in flow:
            assert f.severity != AnalysisSeverity.HIGH
            assert f.verification_status != VerificationStatus.CONFIRMED
        if flow:
            assert flow[0].severity == AnalysisSeverity.MEDIUM
            assert flow[0].verification_status == VerificationStatus.NEEDS_REVIEW

    def test_genuine_source_sink_still_fires_high(self):
        """A real source->sink conjunction (token logged) fires HIGH/confirmed."""
        assessment = InsecureDesignAssessment({"enabled": True})
        findings = assessment._assess_insecure_data_flows(
            _results(['Log.d("DEBUG", "auth token: " + userToken)'])
        )
        flow = _flow(findings)
        assert len(flow) == 1
        assert flow[0].severity == AnalysisSeverity.HIGH
        assert flow[0].verification_status == VerificationStatus.CONFIRMED

    def test_secret_in_intent_extra_fires_high(self):
        """Sensitive data placed into an Intent extra is a genuine conjunction."""
        assessment = InsecureDesignAssessment({"enabled": True})
        findings = assessment._assess_insecure_data_flows(
            _results(['Intent.putExtra("k", userPassword)'])
        )
        flow = _flow(findings)
        assert len(flow) == 1
        assert flow[0].severity == AnalysisSeverity.HIGH

    def test_strong_plus_bare_still_high(self):
        """A strong signal alongside a bare Uri.parse remains HIGH/confirmed."""
        assessment = InsecureDesignAssessment({"enabled": True})
        findings = assessment._assess_insecure_data_flows(
            _results(
                [
                    "Uri.parse(this)",
                    'System.out.println("password: " + password)',
                ]
            )
        )
        flow = _flow(findings)
        assert len(flow) == 1
        assert flow[0].severity == AnalysisSeverity.HIGH
        assert flow[0].verification_status == VerificationStatus.CONFIRMED
