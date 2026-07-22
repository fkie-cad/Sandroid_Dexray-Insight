#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the DEEP-assessment findings cache (Phase C4).

The two deep assessments (deep_dataflow, pii_flow) build androguard xrefs via
``create_xref()`` — the dominant cost of a deep run. Phase C4 caches their
findings so a re-run on the same APK deserializes the stored result and returns
WITHOUT touching androguard.

These tests use a fake in-memory cache manager and a fake androguard object that
COUNTS calls to ``get_androguard_analysis_obj`` (the create_xref trigger), so we
can prove the second (cache-hit) run performs zero androguard access.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.core.base_classes import AnalysisSeverity  # noqa: E402
from dexray_insight.core.base_classes import FileLocation  # noqa: E402
from dexray_insight.core.base_classes import SecurityFinding  # noqa: E402
from dexray_insight.core.base_classes import VerificationStatus  # noqa: E402
from dexray_insight.security.deep_cache import cached_deep_findings  # noqa: E402
from dexray_insight.security.deep_cache import finding_from_dict  # noqa: E402
from dexray_insight.security.deep_cache import findings_from_cache  # noqa: E402
from dexray_insight.security.deep_dataflow_assessment import DeepDataflowAssessment  # noqa: E402


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class _FakeCacheManager:
    """In-memory stand-in for AnalysisCacheManager (module-result tier only)."""

    def __init__(self):
        self.store: dict[tuple[str, str, str], dict] = {}
        self.get_calls = 0
        self.set_calls = 0

    def get_module_result(self, md5, module_name, config_hash):
        self.get_calls += 1
        return self.store.get((md5, module_name, config_hash))

    def set_module_result(self, md5, module_name, config_hash, result_dict):
        self.set_calls += 1
        self.store[(md5, module_name, config_hash)] = result_dict

    @staticmethod
    def hash_config(config):
        return "cfg-hash"


class _CountingAndroguard:
    """Fake androguard object counting create_xref-triggering accesses."""

    def __init__(self, dx):
        self._dx = dx
        self.calls = 0

    def get_androguard_analysis_obj(self):
        self.calls += 1
        return self._dx


class _FakeEncodedMethod:
    def __init__(self, class_name, name):
        self._class_name = class_name
        self._name = name

    def get_class_name(self):
        return self._class_name

    def get_name(self):
        return self._name

    def get_instructions(self):
        return []


class _FakeMethodAnalysis:
    def __init__(self, encoded, xref_to):
        self._encoded = encoded
        self._xref_to = xref_to

    def get_method(self):
        return self._encoded

    def get_xref_to(self):
        return self._xref_to

    def get_xref_read(self):
        return []


class _FakeDx:
    def __init__(self, methods):
        self._methods = methods

    def get_methods(self):
        return self._methods


class _FakeContext:
    """Context stub carrying deep config, cache manager and apk_md5."""

    def __init__(self, androguard_obj, cache_manager=None, apk_md5=None):
        self.androguard_obj = androguard_obj
        self.config = {"deep_mode": True}
        self.cache_manager = cache_manager
        self.apk_md5 = apk_md5


def _redirect_method():
    """A method that trips detector 7a (intent redirection)."""
    caller = _FakeEncodedMethod("Lcom/example/RedirectActivity;", "onCreate")
    callees = [
        (0, _FakeMethodAnalysis(_FakeEncodedMethod("Landroid/content/Intent;", "getStringExtra"), []), 0),
        (0, _FakeMethodAnalysis(_FakeEncodedMethod("Landroid/app/Activity;", "startActivity"), []), 0),
    ]
    return _FakeMethodAnalysis(caller, callees)


def _overview():
    return {
        "apk_overview": {
            "general_info": {"package_name": "com.example"},
            "components": {"exported_activities": ["com.example.RedirectActivity"]},
        }
    }


# --------------------------------------------------------------------------- #
# from_dict round-trip
# --------------------------------------------------------------------------- #
@pytest.mark.unit
@pytest.mark.security
class TestFindingRoundTrip:
    """to_dict -> finding_from_dict must be lossless for report/scorer fields."""

    def test_full_finding_survives_round_trip(self):
        original = SecurityFinding(
            category="A01:2021-Broken Access Control",
            severity=AnalysisSeverity.HIGH,
            title="Possible Intent Redirection (review)",
            description="A one-hop proximity hint.",
            evidence=["Method: Lcom/example/X;->onCreate", "Source API: getStringExtra"],
            recommendations=["Validate the target", "Pin with setPackage"],
            cve_references=["CVE-2021-0001"],
            additional_data={"cwe": "CWE-940", "detector": "deep_dataflow", "nested": {"k": 1}},
            confidence=0.45,
            verification_status=VerificationStatus.NEEDS_DYNAMIC,
        )

        restored = finding_from_dict(original.to_dict())

        assert restored.category == original.category
        assert restored.severity == AnalysisSeverity.HIGH
        assert restored.title == original.title
        assert restored.description == original.description
        assert restored.evidence == original.evidence
        assert restored.recommendations == original.recommendations
        assert restored.cve_references == original.cve_references
        assert restored.additional_data == original.additional_data
        assert restored.confidence == 0.45
        assert restored.verification_status == VerificationStatus.NEEDS_DYNAMIC
        # And the round-trip is stable at the dict level too.
        assert restored.to_dict() == original.to_dict()

    def test_file_location_round_trips(self):
        original = SecurityFinding(
            category="c",
            severity=AnalysisSeverity.MEDIUM,
            title="t",
            description="d",
            evidence=[],
            recommendations=[],
            file_location=FileLocation(uri="file:///x.smali", start_line=42, start_offset=7),
        )
        restored = finding_from_dict(original.to_dict())
        assert restored.file_location is not None
        assert restored.file_location.uri == "file:///x.smali"
        assert restored.file_location.start_line == 42
        assert restored.file_location.start_offset == 7

    def test_missing_verification_status_defaults_to_confirmed(self):
        # A payload without the field (legacy) maps to the SecurityFinding default.
        payload = {
            "category": "c",
            "severity": "low",
            "title": "t",
            "description": "d",
            "evidence": [],
            "recommendations": [],
        }
        restored = finding_from_dict(payload)
        assert restored.verification_status == VerificationStatus.CONFIRMED
        assert restored.severity == AnalysisSeverity.LOW

    def test_findings_from_cache_handles_empty_and_missing(self):
        assert findings_from_cache({}) == []
        assert findings_from_cache({"findings": []}) == []
        assert findings_from_cache({"findings": "garbage"}) == []


# --------------------------------------------------------------------------- #
# cached_deep_findings behavior
# --------------------------------------------------------------------------- #
@pytest.mark.unit
@pytest.mark.security
class TestCachedDeepFindings:
    """Miss computes + stores; hit returns from cache without build_fn."""

    def test_miss_then_hit(self):
        cm = _FakeCacheManager()
        calls = {"n": 0}

        def build():
            calls["n"] += 1
            return [
                SecurityFinding(
                    category="c",
                    severity=AnalysisSeverity.HIGH,
                    title="t",
                    description="d",
                    evidence=["e"],
                    recommendations=["r"],
                    verification_status=VerificationStatus.NEEDS_DYNAMIC,
                )
            ]

        ctx = _FakeContext(None, cache_manager=cm, apk_md5="abc")

        first = cached_deep_findings(ctx, "deep_dataflow", {}, build)
        assert calls["n"] == 1  # miss ran build
        assert cm.set_calls == 1  # and stored
        assert len(first) == 1

        second = cached_deep_findings(ctx, "deep_dataflow", {}, build)
        assert calls["n"] == 1  # HIT: build NOT called again
        assert len(second) == 1
        assert second[0].title == "t"
        assert second[0].severity == AnalysisSeverity.HIGH
        assert second[0].verification_status == VerificationStatus.NEEDS_DYNAMIC

    def test_no_cache_manager_runs_build(self):
        calls = {"n": 0}

        def build():
            calls["n"] += 1
            return []

        ctx = _FakeContext(None, cache_manager=None, apk_md5="abc")
        assert cached_deep_findings(ctx, "deep_dataflow", {}, build) == []
        assert calls["n"] == 1

    def test_no_md5_runs_build(self):
        cm = _FakeCacheManager()
        calls = {"n": 0}

        def build():
            calls["n"] += 1
            return []

        ctx = _FakeContext(None, cache_manager=cm, apk_md5=None)
        assert cached_deep_findings(ctx, "deep_dataflow", {}, build) == []
        assert calls["n"] == 1
        assert cm.get_calls == 0  # never consulted without an md5


# --------------------------------------------------------------------------- #
# End-to-end through DeepDataflowAssessment: prove create_xref is skipped
# --------------------------------------------------------------------------- #
@pytest.mark.unit
@pytest.mark.security
class TestDeepDataflowCacheIntegration:
    """A cache-hit rerun must not touch androguard (create_xref skipped)."""

    def test_second_run_skips_androguard_xref(self):
        cm = _FakeCacheManager()
        androguard = _CountingAndroguard(_FakeDx([_redirect_method()]))
        assessment = DeepDataflowAssessment({})

        ctx1 = _FakeContext(androguard, cache_manager=cm, apk_md5="deadbeef")
        first = assessment.assess(_overview(), ctx1)
        assert len(first) == 1
        assert first[0].additional_data["cwe"] == "CWE-940"
        assert androguard.calls == 1  # miss: create_xref triggered once

        # Fresh androguard object that RAISES if create_xref is ever triggered —
        # proves the cache-hit path never rebuilds xrefs.
        class _ExplodingAndroguard:
            calls = 0

            def get_androguard_analysis_obj(self_inner):
                self_inner.calls += 1
                raise AssertionError("create_xref must not run on a cache hit")

        exploding = _ExplodingAndroguard()
        ctx2 = _FakeContext(exploding, cache_manager=cm, apk_md5="deadbeef")
        second = assessment.assess(_overview(), ctx2)

        assert exploding.calls == 0  # androguard never accessed
        assert len(second) == 1
        assert second[0].additional_data["cwe"] == "CWE-940"
        assert second[0].severity == first[0].severity
        assert second[0].verification_status == first[0].verification_status
        assert second[0].to_dict() == first[0].to_dict()

    def test_no_cache_still_works(self):
        # Existing-style context without cache_manager/apk_md5 -> runs normally.
        androguard = _CountingAndroguard(_FakeDx([_redirect_method()]))

        class _Ctx:
            config = {"deep_mode": True}
            androguard_obj = androguard

        findings = DeepDataflowAssessment({}).assess(_overview(), _Ctx())
        assert len(findings) == 1
        assert androguard.calls == 1
