#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Phase C3 tests: PIIFlowAssessment (deep-only PII source -> tracker sink).

Every test instantiates the assessment directly and drives it with fake
Androguard xref objects and stub contexts (no engine/registry, no base.apk).
Targets mirror the Phase C3 spec:

* deep mode OFF                                   -> []
* PII source -> Crashlytics.recordException (xref) -> HIGH / off-device / NEEDS_DYNAMIC
  (proximity/co-occurrence, not proven argument-level flow -> never CONFIRMED)
* validator-backed PII literal                     -> higher confidence than a bare token
* PII source -> android.util.Log (xref)            -> MEDIUM / local / NEEDS_DYNAMIC
* sink present but no PII source reaches it        -> no finding
* tracker co-location only (coarse)                -> HIGH / off-device / NEEDS_DYNAMIC
* source and sink under the same SDK prefix        -> down-ranked (self-telemetry)
* framework/SDK-owned SOURCE class                 -> down-ranked (library-origin)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.core.base_classes import AnalysisSeverity  # noqa: E402
from dexray_insight.core.base_classes import VerificationStatus  # noqa: E402
from dexray_insight.security.pii_flow_assessment import PIIFlowAssessment  # noqa: E402

_CRASHLYTICS = "Lcom/google/firebase/crashlytics/FirebaseCrashlytics;"
_LOG = "Landroid/util/Log;"


# ------------------------------------------------------------- fake androguard
class FakeMethod:
    """Minimal stand-in for an Androguard EncodedMethod."""

    def __init__(self, class_name: str, name: str):
        self._class_name = class_name
        self._name = name

    def get_class_name(self) -> str:
        return self._class_name

    def get_name(self) -> str:
        return self._name


class FakeMethodAnalysis:
    """Stand-in for a MethodAnalysis with xref navigation."""

    def __init__(self, class_name, name, xref_to=None, xref_from=None):
        self._method = FakeMethod(class_name, name)
        self._xref_to = xref_to or []
        self._xref_from = xref_from or []

    def get_method(self) -> FakeMethod:
        return self._method

    def get_xref_to(self):
        # Androguard yields (class, MethodAnalysis, offset) tuples; index 1 is used.
        return [(None, ma, 0) for ma in self._xref_to]

    def get_xref_from(self):
        return [(None, ma, 0) for ma in self._xref_from]


class FakeDx:
    def __init__(self, methods):
        self._methods = methods

    def get_methods(self):
        return self._methods


class FakeAndroguard:
    def __init__(self, dx):
        self._dx = dx

    def get_androguard_analysis_obj(self):
        return self._dx


class FakeContext:
    def __init__(self, config, androguard_obj=None, string_locations=None):
        self.config = config
        self.androguard_obj = androguard_obj
        self.string_locations = string_locations


def _assess(analysis_results, context):
    return PIIFlowAssessment({}).assess(analysis_results, context)


# --------------------------------------------------------------- deep gate off
def test_returns_empty_when_not_deep():
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    caller = FakeMethodAnalysis("Lcom/evil/app/Leaker;", "leak", xref_to=[callee])
    ctx = FakeContext(
        {"deep_mode": False},
        FakeAndroguard(FakeDx([caller, callee])),
        {"user.email": ["Lcom/evil/app/Leaker;->leak"]},
    )
    assert _assess({}, ctx) == []


def test_deep_mode_nested_flag_enables():
    # deep_mode nested under behaviour_analysis must also enable the assessment.
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    caller = FakeMethodAnalysis("Lcom/evil/app/Leaker;", "leak", xref_to=[callee])
    ctx = FakeContext(
        {"behaviour_analysis": {"deep_mode": True}},
        FakeAndroguard(FakeDx([caller, callee])),
        {"user.email": ["Lcom/evil/app/Leaker;->leak"]},
    )
    assert len(_assess({}, ctx)) == 1


# ------------------------------ off-device xref co-occurrence -> NEEDS_DYNAMIC
def test_pii_column_token_to_crashlytics_xref_high_needs_dynamic():
    # A bare column/field-name token ("user.email") co-occurring with an
    # off-device sink is a proximity signal, NOT proof the value is the sink's
    # argument -> HIGH but NEEDS_DYNAMIC at the lower (column) confidence.
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    caller = FakeMethodAnalysis("Lcom/evil/app/Leaker;", "leak", xref_to=[callee])
    ctx = FakeContext(
        {"deep_mode": True},
        FakeAndroguard(FakeDx([caller, callee])),
        {"user.email": ["Lcom/evil/app/Leaker;->leak"]},
    )
    findings = _assess({}, ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == AnalysisSeverity.HIGH
    assert finding.verification_status == VerificationStatus.NEEDS_DYNAMIC
    assert finding.confidence == 0.5
    assert finding.additional_data["off_device"] is True
    assert finding.additional_data["tracker"] == "Crashlytics"
    assert finding.additional_data["evidence_tier"] == "xref"
    assert finding.additional_data["down_ranked"] is False


def test_validated_pii_literal_gets_higher_confidence():
    # A validator-backed taxonomy literal (a real, non-boilerplate email) is the
    # stronger source signal -> still NEEDS_DYNAMIC, but higher confidence (0.7).
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    caller = FakeMethodAnalysis("Lcom/evil/app/Leaker;", "leak", xref_to=[callee])
    ctx = FakeContext(
        {"deep_mode": True},
        FakeAndroguard(FakeDx([caller, callee])),
        {"john.doe@gmail.com": ["Lcom/evil/app/Leaker;->leak"]},
    )
    findings = _assess({}, ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.verification_status == VerificationStatus.NEEDS_DYNAMIC
    assert finding.confidence == 0.7
    assert finding.additional_data["source"] == "email"


def test_pii_reaches_sink_via_one_hop_caller():
    # The PII source is handled by an upstream caller of the sink-calling method.
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    sink_caller = FakeMethodAnalysis("Lcom/evil/app/Reporter;", "report", xref_to=[callee])
    upstream = FakeMethodAnalysis("Lcom/evil/app/Handler;", "onData", xref_to=[sink_caller])
    # sink_caller is called by upstream (reverse xref).
    sink_caller._xref_from = [upstream]
    dx = FakeDx([upstream, sink_caller, callee])
    ctx = FakeContext(
        {"deep_mode": True},
        FakeAndroguard(dx),
        {"user.email": ["Lcom/evil/app/Handler;->onData"]},
    )
    findings = _assess({}, ctx)
    assert len(findings) == 1
    assert findings[0].verification_status == VerificationStatus.NEEDS_DYNAMIC


def test_bare_column_word_in_prose_is_ignored():
    # "Error message: %s" whole-word-matches the column token "message" but is
    # prose (whitespace + a format specifier), not a column/pref key -> no source
    # is attributed, so no finding is minted from a trivially common sink.
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    caller = FakeMethodAnalysis("Lcom/evil/app/Leaker;", "leak", xref_to=[callee])
    ctx = FakeContext(
        {"deep_mode": True},
        FakeAndroguard(FakeDx([caller, callee])),
        {"Error message: %s": ["Lcom/evil/app/Leaker;->leak"]},
    )
    assert _assess({}, ctx) == []


# ---------------------------------------------- local log xref -> NEEDS_DYNAMIC
def test_pii_to_local_log_medium_needs_dynamic():
    log = FakeMethodAnalysis(_LOG, "d")
    caller = FakeMethodAnalysis("Lcom/evil/app/Logger;", "dump", xref_to=[log])
    ctx = FakeContext(
        {"deep_mode": True},
        FakeAndroguard(FakeDx([caller, log])),
        {"user.phone": ["Lcom/evil/app/Logger;->dump"]},
    )
    findings = _assess({}, ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == AnalysisSeverity.MEDIUM
    assert finding.verification_status == VerificationStatus.NEEDS_DYNAMIC
    assert finding.additional_data["off_device"] is False
    assert finding.additional_data["tracker"] == "android.util.Log"


# ------------------------------------------------- sink without a PII source
def test_sink_without_reaching_pii_source_no_finding():
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    caller = FakeMethodAnalysis("Lcom/evil/app/Clean;", "noPii", xref_to=[callee])
    # A PII source exists, but in an unrelated method that never reaches the sink.
    ctx = FakeContext(
        {"deep_mode": True},
        FakeAndroguard(FakeDx([caller, callee])),
        {"user.email": ["Lcom/evil/app/Other;->helper"]},
    )
    assert _assess({}, ctx) == []


def test_no_pii_source_at_all_no_finding():
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    caller = FakeMethodAnalysis("Lcom/evil/app/Clean;", "noPii", xref_to=[callee])
    ctx = FakeContext(
        {"deep_mode": True},
        FakeAndroguard(FakeDx([caller, callee])),
        {"some.unrelated.value": ["Lcom/evil/app/Clean;->noPii"]},
    )
    assert _assess({}, ctx) == []


# ------------------------------------------- coarse co-location -> NEEDS_DYNAMIC
def test_tracker_colocation_only_needs_dynamic():
    # No xref graph available; the only signal is a tracker whose code location
    # shares a class with a PII source string's location.
    ctx = FakeContext(
        {"deep_mode": True},
        androguard_obj=None,
        string_locations={"user.email": ["Lcom/shared/Analytics;->send"]},
    )
    analysis_results = {
        "tracker_analysis": {
            "detected_trackers": [
                {
                    "name": "Crashlytics",
                    "category": "Crash reporting",
                    "locations": ["Lcom/shared/Analytics;->init"],
                }
            ]
        }
    }
    findings = _assess(analysis_results, ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == AnalysisSeverity.HIGH
    assert finding.verification_status == VerificationStatus.NEEDS_DYNAMIC
    assert finding.confidence == 0.5
    assert finding.additional_data["off_device"] is True
    assert finding.additional_data["evidence_tier"] == "co-location"


def test_tracker_without_colocated_pii_no_finding():
    ctx = FakeContext(
        {"deep_mode": True},
        androguard_obj=None,
        string_locations={"user.email": ["Lcom/other/Class;->send"]},
    )
    analysis_results = {
        "tracker_analysis": {
            "detected_trackers": [
                {"name": "Crashlytics", "locations": ["Lcom/shared/Analytics;->init"]}
            ]
        }
    }
    assert _assess(analysis_results, ctx) == []


# ------------------------------------------------------- FP control: same SDK
def test_same_sdk_source_and_sink_down_ranked():
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    caller = FakeMethodAnalysis(
        "Lcom/google/firebase/crashlytics/internal/Reporter;", "report", xref_to=[callee]
    )
    ctx = FakeContext(
        {"deep_mode": True},
        FakeAndroguard(FakeDx([caller, callee])),
        {"user.email": ["Lcom/google/firebase/crashlytics/internal/Reporter;->report"]},
    )
    findings = _assess({}, ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.additional_data["down_ranked"] is True
    assert finding.severity == AnalysisSeverity.MEDIUM  # HIGH -> MEDIUM
    assert finding.verification_status == VerificationStatus.NEEDS_REVIEW


# ------------------------------------------------------ xref supersedes coarse
def test_xref_path_supersedes_colocation_for_same_flow():
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    caller = FakeMethodAnalysis("Lcom/shared/Analytics;", "send", xref_to=[callee])
    ctx = FakeContext(
        {"deep_mode": True},
        FakeAndroguard(FakeDx([caller, callee])),
        {"user.email": ["Lcom/shared/Analytics;->send"]},
    )
    analysis_results = {
        "tracker_analysis": {
            "detected_trackers": [
                {"name": "Crashlytics", "locations": ["Lcom/shared/Analytics;->init"]}
            ]
        }
    }
    findings = _assess(analysis_results, ctx)
    # Both tiers describe (email, Crashlytics.*, Crashlytics); both are now
    # NEEDS_DYNAMIC, so the xref (precise) tier wins the merge on the tie-break.
    assert len(findings) == 1
    assert findings[0].verification_status == VerificationStatus.NEEDS_DYNAMIC
    assert findings[0].additional_data["evidence_tier"] == "xref"


# ---------------------------------------- FP control: framework SOURCE class
def test_framework_source_class_down_ranked():
    # The SOURCE class alone is framework/SDK-owned (androidx.media3), flowing to
    # a DIFFERENT SDK sink (Crashlytics). This is not covered by the same-prefix
    # self-telemetry rule, but a library-origin source must still be down-ranked.
    callee = FakeMethodAnalysis(_CRASHLYTICS, "recordException")
    caller = FakeMethodAnalysis(
        "Landroidx/media3/exoplayer/Analytics;", "report", xref_to=[callee]
    )
    ctx = FakeContext(
        {"deep_mode": True},
        FakeAndroguard(FakeDx([caller, callee])),
        {"user.email": ["Landroidx/media3/exoplayer/Analytics;->report"]},
    )
    findings = _assess({}, ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.additional_data["down_ranked"] is True
    assert finding.additional_data["source_is_sdk"] is True
    assert finding.severity == AnalysisSeverity.MEDIUM  # HIGH -> MEDIUM
    assert finding.verification_status == VerificationStatus.NEEDS_REVIEW
