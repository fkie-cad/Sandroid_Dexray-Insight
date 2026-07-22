#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for ProviderPathsAssessment (Phase B2 security overhaul).

The assessment reads the AndroidManifest and FileProvider paths resources via
androguard. These tests drive it with SYNTHETIC manifests/paths XML built with
lxml and a small stub APK object, so they need neither base.apk nor a full
androguard parse.

Ground-truth targets locked in here:
- KikShareFileProvider ``<external-path path="."/>`` + grantUriPermissions=true
  -> MEDIUM A05 over-broad-root finding.
- Two providers sharing authority "kik.android.provider" -> MEDIUM duplicate
  authority finding.
- A signature-guarded provider -> NO finding (true negative).
"""

import os
import sys

import pytest
from lxml import etree

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.core.base_classes import AnalysisSeverity  # noqa: E402
from dexray_insight.core.base_classes import VerificationStatus  # noqa: E402
from dexray_insight.security.provider_paths_assessment import ProviderPathsAssessment  # noqa: E402

_ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _ns(attr: str) -> str:
    """Return an android-namespaced attribute name for lxml."""
    return f"{{{_ANDROID_NS}}}{attr}"


def _build_manifest(providers_xml: str, permissions_xml: str = "") -> etree._Element:
    """Build an AndroidManifest lxml root from provider/permission snippets."""
    xml = (
        f'<manifest xmlns:android="{_ANDROID_NS}" package="kik.android">'
        f"{permissions_xml}"
        f"<application>{providers_xml}</application>"
        "</manifest>"
    )
    return etree.fromstring(xml.encode("utf-8"))


def _paths_bytes(entries: str) -> bytes:
    """Build a FileProvider paths resource as plain-XML bytes."""
    return f"<paths>{entries}</paths>".encode("utf-8")


class _StubAndroguardObj:
    """Minimal stand-in exposing the two androguard entry points we use."""

    def __init__(self, manifest, files):
        self._manifest = manifest
        self._files = files

    def get_androguard_apk(self):
        return self

    def get_android_manifest_xml(self):
        return self._manifest

    def get_file(self, path):
        return self._files.get(path)


class _StubContext:
    """Minimal AnalysisContext stub carrying only androguard_obj."""

    def __init__(self, androguard_obj):
        self.androguard_obj = androguard_obj


def _run(manifest, files=None, analysis_results=None):
    """Instantiate the assessment and run it against synthetic inputs."""
    ctx = _StubContext(_StubAndroguardObj(manifest, files or {}))
    assessment = ProviderPathsAssessment({})
    return assessment.assess(analysis_results or {}, ctx)


@pytest.mark.unit
@pytest.mark.security
class TestProviderPathsAssessment:
    """Ground-truth and edge-case coverage for ProviderPathsAssessment."""

    def test_kik_share_file_provider_broad_external_root_with_grants(self):
        """external-path path="." + grantUriPermissions=true -> MEDIUM A05."""
        providers = (
            '<provider android:name="com.kik.KikShareFileProvider"'
            ' android:authorities="kik.android.share"'
            ' android:grantUriPermissions="true">'
            '<meta-data android:name="android.support.FILE_PROVIDER_PATHS"'
            ' android:resource="@xml/file_paths"/>'
            "</provider>"
        )
        manifest = _build_manifest(providers)
        files = {"res/xml/file_paths.xml": _paths_bytes('<external-path name="share" path="."/>')}

        findings = _run(manifest, files)

        broad = [f for f in findings if f.title == "Over-Broad FileProvider Root with URI Grants"]
        assert len(broad) == 1
        finding = broad[0]
        assert finding.category == "A05:2021-Security Misconfiguration"
        assert finding.severity == AnalysisSeverity.MEDIUM
        assert finding.confidence == 0.7
        assert finding.verification_status == VerificationStatus.CONFIRMED
        assert finding.recommendations

    def test_duplicate_authority_across_two_providers(self):
        """Two providers sharing an authority -> MEDIUM duplicate authority."""
        providers = (
            '<provider android:name="com.kik.ProviderA"'
            ' android:authorities="kik.android.provider"/>'
            '<provider android:name="com.kik.ProviderB"'
            ' android:authorities="kik.android.provider"/>'
        )
        manifest = _build_manifest(providers)

        findings = _run(manifest)

        dupes = [f for f in findings if f.title == "Duplicate Content Provider Authority"]
        assert len(dupes) == 1
        finding = dupes[0]
        assert finding.category == "A05:2021-Security Misconfiguration"
        assert finding.severity == AnalysisSeverity.MEDIUM
        assert finding.confidence == 0.8
        # Both classes are listed as evidence.
        evidence_blob = " ".join(finding.evidence)
        assert "com.kik.ProviderA" in evidence_blob
        assert "com.kik.ProviderB" in evidence_blob

    def test_signature_guarded_provider_is_true_negative(self):
        """An exported provider guarded by a signature permission -> NO finding."""
        permissions = (
            '<permission android:name="kik.android.perm.CONTACTS"'
            ' android:protectionLevel="signature"/>'
        )
        providers = (
            '<provider android:name="com.kik.ContactsProvider"'
            ' android:authorities="kik.android.contacts"'
            ' android:exported="true"'
            ' android:permission="kik.android.perm.CONTACTS"'
            ' android:readPermission="kik.android.perm.CONTACTS"/>'
        )
        manifest = _build_manifest(providers, permissions)

        findings = _run(manifest)

        assert findings == []

    def test_exported_provider_without_permission_flags_access_control(self):
        """Exported provider, no permission -> A01 finding (HIGH if sensitive name)."""
        providers = (
            '<provider android:name="com.kik.ContactsProvider"'
            ' android:authorities="kik.android.contacts"'
            ' android:exported="true"/>'
        )
        manifest = _build_manifest(providers)

        findings = _run(manifest)

        access = [f for f in findings if f.category == "A01:2021-Broken Access Control"]
        assert len(access) == 1
        finding = access[0]
        # "contacts" is a sensitive keyword -> HIGH.
        assert finding.severity == AnalysisSeverity.HIGH
        assert finding.confidence == 0.6
        assert finding.verification_status == VerificationStatus.CONFIRMED

    def test_exported_non_sensitive_provider_is_medium(self):
        """Exported provider without a sensitive name -> MEDIUM A01."""
        providers = (
            '<provider android:name="com.kik.SyncProvider"'
            ' android:authorities="kik.android.sync"'
            ' android:exported="true"/>'
        )
        manifest = _build_manifest(providers)

        findings = _run(manifest)

        access = [f for f in findings if f.category == "A01:2021-Broken Access Control"]
        assert len(access) == 1
        assert access[0].severity == AnalysisSeverity.MEDIUM

    def test_scoped_provider_produces_no_path_finding(self):
        """A properly scoped FileProvider root -> no over-broad-root finding."""
        providers = (
            '<provider android:name="com.kik.KikShareFileProvider"'
            ' android:authorities="kik.android.share"'
            ' android:grantUriPermissions="true"'
            ' android:exported="false">'
            '<meta-data android:name="androidx.core.content.FileProvider"'
            ' android:resource="@xml/file_paths"/>'
            "</provider>"
        )
        manifest = _build_manifest(providers)
        files = {"res/xml/file_paths.xml": _paths_bytes('<external-path name="share" path="shared/images"/>')}

        findings = _run(manifest, files)

        assert not [f for f in findings if "Over-Broad FileProvider Root" in f.title]

    def test_unset_exported_below_sdk17_is_reachable(self):
        """exported unset + minSdk<17 -> provider treated as externally reachable."""
        providers = (
            '<provider android:name="com.kik.LegacyProvider"'
            ' android:authorities="kik.android.legacy"/>'
        )
        manifest = _build_manifest(providers)
        analysis_results = {"apk_overview": {"general_info": {"min_sdk": 15}}}

        findings = _run(manifest, analysis_results=analysis_results)

        assert [f for f in findings if f.category == "A01:2021-Broken Access Control"]

    def test_unset_exported_above_sdk17_is_not_reachable(self):
        """exported unset + minSdk>=17 -> provider not reachable, no A01 finding."""
        providers = (
            '<provider android:name="com.kik.ModernProvider"'
            ' android:authorities="kik.android.modern"/>'
        )
        manifest = _build_manifest(providers)
        analysis_results = {"apk_overview": {"general_info": {"min_sdk": 21}}}

        findings = _run(manifest, analysis_results=analysis_results)

        assert not [f for f in findings if f.category == "A01:2021-Broken Access Control"]

    def test_no_context_returns_empty(self):
        """Missing context / androguard obj -> empty list, never raises."""
        assessment = ProviderPathsAssessment({})
        assert assessment.assess({}, None) == []

    def test_no_providers_returns_empty(self):
        """A manifest with no providers -> empty list."""
        manifest = _build_manifest("")
        assert _run(manifest) == []


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("DEXRAY_BASE_APK"),
    reason="Set DEXRAY_BASE_APK to a real APK path to run the integration check",
)
def test_integration_against_real_apk():
    """Optional smoke test against a real APK (gated behind DEXRAY_BASE_APK)."""
    from dexray_insight.Utils.androguardObjClass import AndroguardObj

    apk_path = os.environ["DEXRAY_BASE_APK"]
    androguard_obj = AndroguardObj(apk_path)
    ctx = _StubContext(androguard_obj)
    findings = ProviderPathsAssessment({}).assess({}, ctx)
    # Must not raise and must return a list of SecurityFinding-like objects.
    assert isinstance(findings, list)
