#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for DeepDataflowAssessment (Phase C1 + C2 security overhaul).

These detectors walk androguard cross-references under ``--deep`` and emit
review-queue SEEDS (VerificationStatus.NEEDS_DYNAMIC), never confirmed verdicts.
The tests drive the assessment with a lightweight FAKE ``dx`` — no base.apk and
no real androguard parse — so we can assert exact finding shapes:

- deep gate OFF -> no findings at all
- 7a: intent source + launch sink in an exported activity -> NEEDS_DYNAMIC seed
- 7a: same, but with setPackage -> downgraded to nothing (self-targeted)
- 7d: openFile with getLastPathSegment and NO canonicalization -> seed;
      WITH getCanonicalPath -> nothing
- C2: reads ApplicationInfo.flags + tests 0x2 + a validate token -> HIGH seed;
      flags & 0x2 + only a Log call -> nothing
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.core.base_classes import AnalysisSeverity  # noqa: E402
from dexray_insight.core.base_classes import VerificationStatus  # noqa: E402
from dexray_insight.security.deep_dataflow_assessment import DeepDataflowAssessment  # noqa: E402


# --------------------------------------------------------------------------- #
# Fake androguard objects
# --------------------------------------------------------------------------- #
class _FakeEncodedMethod:
    """Stands in for androguard's EncodedMethod (class/name + instructions)."""

    def __init__(self, class_name, name, instructions=None):
        self._class_name = class_name
        self._name = name
        self._instructions = instructions or []

    def get_class_name(self):
        return self._class_name

    def get_name(self):
        return self._name

    def get_instructions(self):
        return self._instructions


class _FakeInstruction:
    """Minimal instruction exposing get_name()/get_output()."""

    def __init__(self, name, output):
        self._name = name
        self._output = output

    def get_name(self):
        return self._name

    def get_output(self):
        return self._output


class _FakeField:
    """Minimal field exposing get_name()/get_class_name()."""

    def __init__(self, name, class_name):
        self._name = name
        self._class_name = class_name

    def get_name(self):
        return self._name

    def get_class_name(self):
        return self._class_name


class _FakeMethodAnalysis:
    """Stands in for androguard's MethodAnalysis.

    Exposes ``get_method()`` (-> EncodedMethod), ``get_xref_to()`` (list of
    ``(idx, callee_analysis, off)``), and ``get_xref_read()`` (field reads).
    """

    def __init__(self, encoded, xref_to=None, xref_read=None):
        self._encoded = encoded
        self._xref_to = xref_to or []
        self._xref_read = xref_read or []

    def get_method(self):
        return self._encoded

    def get_xref_to(self):
        return self._xref_to

    def get_xref_read(self):
        return self._xref_read


class _FakeDx:
    """Fake androguard Analysis object: only get_methods() is used."""

    def __init__(self, methods):
        self._methods = methods

    def get_methods(self):
        return self._methods


class _FakeAndroguardObj:
    """Exposes get_androguard_analysis_obj() -> the fake dx."""

    def __init__(self, dx):
        self._dx = dx

    def get_androguard_analysis_obj(self):
        return self._dx


class _FakeContext:
    """Minimal AnalysisContext stub carrying config + androguard_obj."""

    def __init__(self, dx, config=None):
        self.androguard_obj = _FakeAndroguardObj(dx)
        self.config = config if config is not None else {"deep_mode": True}


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #
def _callee(class_name, name):
    """Build a fake xref-to edge: (idx, callee_analysis, offset)."""
    analysis = _FakeMethodAnalysis(_FakeEncodedMethod(class_name, name))
    return (0, analysis, 0)


def _method(class_name, name, callees=(), instructions=None, field_reads=()):
    """Build a caller MethodAnalysis with the given one-hop callees."""
    xref_to = [_callee(cls, nm) for cls, nm in callees]
    encoded = _FakeEncodedMethod(class_name, name, instructions=list(instructions or []))
    xref_read = [(None, field, 0) for field in field_reads]
    return _FakeMethodAnalysis(encoded, xref_to=xref_to, xref_read=xref_read)


def _overview(exported_activities=None, exported_providers=None, package="com.example"):
    """Build an apk_overview analysis_results fragment."""
    return {
        "apk_overview": {
            "general_info": {"package_name": package},
            "components": {
                "exported_activities": list(exported_activities or []),
                "exported_providers": list(exported_providers or []),
            },
        }
    }


def _run(dx, analysis_results=None, config=None):
    """Instantiate the assessment and run it against a fake dx."""
    ctx = _FakeContext(dx, config=config)
    assessment = DeepDataflowAssessment({})
    return assessment.assess(analysis_results or {}, ctx)


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
@pytest.mark.unit
@pytest.mark.security
class TestDeepGate:
    """The whole pass must be inert unless deep mode is explicitly on."""

    def test_deep_gate_off_returns_empty(self):
        # A method that WOULD trip 7a, but deep mode is off.
        caller = "Lcom/example/EvilActivity;"
        method = _method(
            caller,
            "onCreate",
            callees=[
                ("Landroid/content/Intent;", "getStringExtra"),
                ("Landroid/app/Activity;", "startActivity"),
            ],
        )
        dx = _FakeDx([method])
        overview = _overview(exported_activities=["com.example.EvilActivity"])

        # deep flag absent -> nothing
        assert _run(dx, overview, config={}) == []
        # explicit False -> nothing
        assert _run(dx, overview, config={"deep_mode": False}) == []

    def test_nested_behaviour_deep_mode_enables(self):
        caller = "Lcom/example/EvilActivity;"
        method = _method(
            caller,
            "onCreate",
            callees=[
                ("Landroid/content/Intent;", "getStringExtra"),
                ("Landroid/app/Activity;", "startActivity"),
            ],
        )
        dx = _FakeDx([method])
        overview = _overview(exported_activities=["com.example.EvilActivity"])
        findings = _run(dx, overview, config={"behaviour_analysis": {"deep_mode": True}})
        assert len(findings) == 1

    def test_disabled_assessment_returns_empty(self):
        method = _method("Lcom/example/EvilActivity;", "onCreate")
        dx = _FakeDx([method])
        assessment = DeepDataflowAssessment({"enabled": False})
        assert assessment.assess({}, _FakeContext(dx)) == []


@pytest.mark.unit
@pytest.mark.security
class TestIntentRedirection:
    """7a - intent redirection (CWE-940)."""

    def test_source_and_sink_in_exported_method_seeds_finding(self):
        caller = "Lcom/example/RedirectActivity;"
        method = _method(
            caller,
            "onCreate",
            callees=[
                ("Landroid/content/Intent;", "getStringExtra"),
                ("Landroid/app/Activity;", "startActivity"),
            ],
        )
        dx = _FakeDx([method])
        overview = _overview(exported_activities=["com.example.RedirectActivity"])
        findings = _run(dx, overview)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.verification_status == VerificationStatus.NEEDS_DYNAMIC
        assert finding.severity == AnalysisSeverity.HIGH
        assert finding.additional_data["cwe"] == "CWE-940"
        assert 0.4 <= finding.confidence <= 0.5

    def test_setpackage_downgrades_to_nothing(self):
        caller = "Lcom/example/RedirectActivity;"
        method = _method(
            caller,
            "onCreate",
            callees=[
                ("Landroid/content/Intent;", "getStringExtra"),
                ("Landroid/app/Activity;", "startActivity"),
                ("Landroid/content/Intent;", "setPackage"),
            ],
        )
        dx = _FakeDx([method])
        overview = _overview(exported_activities=["com.example.RedirectActivity"])
        findings = _run(dx, overview)
        assert findings == []

    def test_non_exported_class_not_reported(self):
        caller = "Lcom/example/InternalActivity;"
        method = _method(
            caller,
            "onCreate",
            callees=[
                ("Landroid/content/Intent;", "getStringExtra"),
                ("Landroid/app/Activity;", "startActivity"),
            ],
        )
        dx = _FakeDx([method])
        # exported list does NOT contain InternalActivity
        overview = _overview(exported_activities=["com.example.OtherActivity"])
        findings = _run(dx, overview)
        assert findings == []


@pytest.mark.unit
@pytest.mark.security
class TestProviderTraversal:
    """7d - custom-provider openFile path traversal (CWE-22)."""

    def test_openfile_without_canonicalization_seeds_finding(self):
        caller = "Lcom/example/MyProvider;"
        method = _method(
            caller,
            "openFile",
            callees=[
                ("Landroid/net/Uri;", "getLastPathSegment"),
                ("Ljava/io/File;", "<init>"),
                ("Landroid/os/ParcelFileDescriptor;", "open"),
            ],
        )
        dx = _FakeDx([method])
        overview = _overview(exported_providers=["com.example.MyProvider"])
        findings = _run(dx, overview)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.verification_status == VerificationStatus.NEEDS_DYNAMIC
        assert finding.additional_data["cwe"] == "CWE-22"
        # exported provider -> HIGH
        assert finding.severity == AnalysisSeverity.HIGH

    def test_openfile_latent_when_not_exported_is_medium(self):
        caller = "Lcom/example/MyProvider;"
        method = _method(
            caller,
            "openFile",
            callees=[("Landroid/net/Uri;", "getLastPathSegment")],
        )
        dx = _FakeDx([method])
        # provider not in exported list
        findings = _run(dx, _overview())
        assert len(findings) == 1
        assert findings[0].severity == AnalysisSeverity.MEDIUM

    def test_openfile_with_canonicalization_reports_nothing(self):
        caller = "Lcom/example/MyProvider;"
        method = _method(
            caller,
            "openFile",
            callees=[
                ("Landroid/net/Uri;", "getLastPathSegment"),
                ("Ljava/io/File;", "getCanonicalPath"),
            ],
        )
        dx = _FakeDx([method])
        overview = _overview(exported_providers=["com.example.MyProvider"])
        findings = _run(dx, overview)
        assert findings == []

    def test_androidx_fileprovider_excluded(self):
        # The real androidx FileProvider (safe, scopes paths itself) is excluded.
        caller = "Landroidx/core/content/FileProvider;"
        method = _method(
            caller,
            "openFile",
            callees=[("Landroid/net/Uri;", "getLastPathSegment")],
        )
        dx = _FakeDx([method])
        assert _run(dx, _overview()) == []

    def test_custom_fileprovider_not_excluded(self):
        # A custom provider whose name merely CONTAINS "FileProvider" (e.g. Kik's
        # KikFileProvider — the R5 target) must NOT be swallowed by the androidx
        # exclusion: it is exactly what detector 7d should catch.
        caller = "Lcom/kik/android/KikFileProvider;"
        method = _method(
            caller,
            "openFile",
            callees=[("Landroid/net/Uri;", "getLastPathSegment")],
        )
        dx = _FakeDx([method])
        overview = _overview(exported_providers=["com.kik.android.KikFileProvider"], package="com.kik.android")
        findings = _run(dx, overview)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.additional_data["cwe"] == "CWE-22"
        assert finding.severity == AnalysisSeverity.HIGH  # exported provider


@pytest.mark.unit
@pytest.mark.security
class TestFrameworkSourceDownrank:
    """FIX B6 - a framework/SDK-owned SOURCE class down-ranks the seed."""

    def test_framework_source_class_is_downranked(self):
        # A media3 (androidx.media3) class trips 7d; because the SOURCE class is
        # framework-owned the seed is softened, not deleted, and stays for review.
        caller = "Landroidx/media3/exoplayer/CacheProvider;"
        method = _method(
            caller,
            "openFile",
            callees=[("Landroid/net/Uri;", "getLastPathSegment")],
        )
        dx = _FakeDx([method])
        findings = _run(dx, _overview())  # not exported -> MEDIUM before down-rank
        assert len(findings) == 1
        finding = findings[0]
        assert finding.additional_data.get("source_downranked") is True
        assert finding.severity == AnalysisSeverity.LOW  # MEDIUM -> LOW
        assert finding.verification_status == VerificationStatus.NEEDS_DYNAMIC

    def test_first_party_source_class_not_downranked(self):
        caller = "Lcom/example/MyProvider;"
        method = _method(
            caller,
            "openFile",
            callees=[("Landroid/net/Uri;", "getLastPathSegment")],
        )
        dx = _FakeDx([method])
        overview = _overview(exported_providers=["com.example.MyProvider"])
        findings = _run(dx, overview)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.additional_data.get("source_downranked") is not True
        assert finding.severity == AnalysisSeverity.HIGH


@pytest.mark.unit
@pytest.mark.security
class TestDebuggableGatedControl:
    """C2 - security control gated by the debuggable flag (CWE-693)."""

    _FLAG_READ = _FakeField("flags", "Landroid/content/pm/ApplicationInfo;")
    _BIT_TEST = [_FakeInstruction("and-int/lit8", "v0, v1, 0x2")]

    def test_flags_bit_and_validate_token_is_high_seed(self):
        caller = "Lcom/example/HostChecker;"
        method = _method(
            caller,
            "validateHost",
            callees=[("Lcom/example/Net;", "checkHost")],
            instructions=self._BIT_TEST,
            field_reads=[self._FLAG_READ],
        )
        dx = _FakeDx([method])
        findings = _run(dx, _overview())

        assert len(findings) == 1
        finding = findings[0]
        assert finding.verification_status == VerificationStatus.NEEDS_DYNAMIC
        assert finding.severity == AnalysisSeverity.HIGH
        assert finding.additional_data["cwe"] == "CWE-693"

    def test_flags_bit_with_only_logging_reports_nothing(self):
        caller = "Lcom/example/DebugLogger;"
        method = _method(
            caller,
            "maybeLog",
            callees=[("Landroid/util/Log;", "d")],
            instructions=self._BIT_TEST,
            field_reads=[self._FLAG_READ],
        )
        dx = _FakeDx([method])
        findings = _run(dx, _overview())
        assert findings == []

    def test_validate_token_without_flag_read_reports_nothing(self):
        # A validation method that never touches ApplicationInfo.flags.
        caller = "Lcom/example/HostChecker;"
        method = _method(
            caller,
            "validateHost",
            callees=[("Lcom/example/Net;", "checkHost")],
            instructions=self._BIT_TEST,
            field_reads=[],
        )
        dx = _FakeDx([method])
        findings = _run(dx, _overview())
        assert findings == []


@pytest.mark.unit
@pytest.mark.security
class TestRobustness:
    """The pass must never crash and must stay inert without a usable dx."""

    def test_missing_androguard_obj_returns_empty(self):
        assessment = DeepDataflowAssessment({})

        class _Ctx:
            config = {"deep_mode": True}
            androguard_obj = None

        assert assessment.assess({}, _Ctx()) == []

    def test_none_context_returns_empty(self):
        assessment = DeepDataflowAssessment({})
        assert assessment.assess({}, None) == []

    def test_dx_none_returns_empty(self):
        class _NullAndroguard:
            def get_androguard_analysis_obj(self):
                return None

        class _Ctx:
            config = {"deep_mode": True}
            androguard_obj = _NullAndroguard()

        assessment = DeepDataflowAssessment({})
        assert assessment.assess({}, _Ctx()) == []
