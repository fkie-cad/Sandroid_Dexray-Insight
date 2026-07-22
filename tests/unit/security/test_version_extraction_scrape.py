#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Phase B5 tests: library version extraction / path scraping (additive).

Covers the apktool detection engine's version-recovery helpers:
  * BuildConfig.smali VERSION_NAME extraction (regression).
  * BuildConfig.smali SDK_VERSION fallback extraction.
  * ``_scan_release_version_paths`` recovering versions from `.../release/<v>/` and
    generic `.../<lib>/<x.y.z>/` directory segments.
  * ``_apply_scraped_version`` filling a missing version with a low-confidence,
    path-scrape-tagged value (and never overwriting an existing version).
  * The absent/empty apktool tree guard returning ``{}`` without raising.

These scrapers only help WHEN apktool actually produced a decoded smali/asset tree;
the tests build synthetic temp directories rather than decoding a real APK.
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from dexray_insight.core.base_classes import AnalysisSeverity, VerificationStatus  # noqa: E402
from dexray_insight.modules.library_detection.engines.apktool_detection_engine import (  # noqa: E402
    PATH_SCRAPE_EVIDENCE,
    ApktoolDetectionEngine,
)
from dexray_insight.results.LibraryDetectionResults import DetectedLibrary  # noqa: E402
from dexray_insight.security.cve.models.vulnerability import (  # noqa: E402
    CVESeverity,
    CVEVulnerability,
)
from dexray_insight.security.cve_assessment import CVEAssessment  # noqa: E402


def _engine():
    # auto_update_definitions=False keeps construction offline (no JSONL download).
    return ApktoolDetectionEngine({"apktool_detection": {"auto_update_definitions": False}})


def _write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _buildconfig(class_pkg: str, field_line: str) -> str:
    return (
        f".class public final L{class_pkg}/BuildConfig;\n"
        ".super Ljava/lang/Object;\n\n"
        f"{field_line}\n"
    )


def test_buildconfig_version_name_extracted():
    """Regression: VERSION_NAME is read verbatim from BuildConfig.smali."""
    engine = _engine()
    with tempfile.TemporaryDirectory() as tmp:
        apktool_dir = Path(tmp)
        _write(
            apktool_dir / "smali" / "com" / "example" / "foo" / "BuildConfig.smali",
            _buildconfig(
                "com/example/foo",
                '.field public static final VERSION_NAME:Ljava/lang/String; = "9.4.3"',
            ),
        )

        errors: list[str] = []
        libs = engine._scan_buildconfig_smali(apktool_dir, errors)

        assert errors == []
        versions = {lib.version for lib in libs}
        assert "9.4.3" in versions


def test_buildconfig_sdk_version_fallback():
    """A BuildConfig with only SDK_VERSION (no VERSION_NAME) still yields a version."""
    engine = _engine()
    with tempfile.TemporaryDirectory() as tmp:
        apktool_dir = Path(tmp)
        _write(
            apktool_dir / "smali" / "com" / "vendor" / "sdk" / "BuildConfig.smali",
            _buildconfig(
                "com/vendor/sdk",
                '.field public static final SDK_VERSION:Ljava/lang/String; = "13.2.0"',
            ),
        )

        errors: list[str] = []
        libs = engine._scan_buildconfig_smali(apktool_dir, errors)

        assert errors == []
        versions = {lib.version for lib in libs}
        assert "13.2.0" in versions


def test_scan_release_version_paths_release_segment():
    """A `.../ironsource/release/7.2.1/Foo.smali` path yields version 7.2.1."""
    engine = _engine()
    with tempfile.TemporaryDirectory() as tmp:
        apktool_dir = Path(tmp)
        _write(
            apktool_dir / "smali" / "com" / "ironsource" / "release" / "7.2.1" / "Foo.smali",
            ".class public Lcom/ironsource/release/Foo;\n",
        )

        errors: list[str] = []
        scraped = engine._scan_release_version_paths(apktool_dir, errors)

        assert errors == []
        assert "7.2.1" in scraped.values()
        assert scraped.get("ironsource") == "7.2.1"


def test_scan_release_version_paths_generic_segment():
    """A generic `.../<lib>/<x.y.z>/` directory segment is scraped too."""
    engine = _engine()
    with tempfile.TemporaryDirectory() as tmp:
        apktool_dir = Path(tmp)
        _write(
            apktool_dir / "assets" / "coollib" / "3.4.5" / "data.bin",
            "x",
        )

        errors: list[str] = []
        scraped = engine._scan_release_version_paths(apktool_dir, errors)

        assert errors == []
        assert scraped.get("coollib") == "3.4.5"


def test_scan_release_version_paths_missing_dir_returns_empty():
    """A non-existent apktool dir returns {} and appends no error."""
    engine = _engine()
    errors: list[str] = []
    missing = Path(tempfile.gettempdir()) / "definitely_does_not_exist_b5_xyz"
    scraped = engine._scan_release_version_paths(missing, errors)
    assert scraped == {}
    assert errors == []


def test_scan_release_version_paths_empty_dir_returns_empty():
    """An existing-but-empty apktool dir returns {} and appends no error."""
    engine = _engine()
    with tempfile.TemporaryDirectory() as tmp:
        errors: list[str] = []
        scraped = engine._scan_release_version_paths(Path(tmp), errors)
        assert scraped == {}
        assert errors == []


def test_apply_scraped_version_fills_missing_low_confidence():
    """Scraped version fills a missing version, capped at 0.7 and evidence-tagged."""
    engine = _engine()
    engine._scraped_versions = {"ironsource": "7.2.1"}

    lib = DetectedLibrary(
        name="IronSource",
        package_name="com.ironsource.mediationsdk",
        version=None,
        confidence=0.95,
        smali_path="com/ironsource/mediationsdk",
    )
    engine._apply_scraped_version(lib)

    assert lib.version == "7.2.1"
    assert lib.confidence <= 0.7
    assert any(PATH_SCRAPE_EVIDENCE in e for e in lib.evidence)


def test_apply_scraped_version_does_not_overwrite_existing():
    """An existing (higher-confidence) version is never overwritten by scraping."""
    engine = _engine()
    engine._scraped_versions = {"ironsource": "7.2.1"}

    lib = DetectedLibrary(
        name="IronSource",
        package_name="com.ironsource.mediationsdk",
        version="9.9.9",
        confidence=0.95,
        smali_path="com/ironsource/mediationsdk",
    )
    engine._apply_scraped_version(lib)

    assert lib.version == "9.9.9"
    assert lib.confidence == 0.95
    assert not any(PATH_SCRAPE_EVIDENCE in e for e in lib.evidence)


def _disabled_cve_assessment():
    # Empty config -> CVE scanning disabled -> __init__ early-returns (offline, no
    # clients/network) while still setting logger and owasp_category.
    return CVEAssessment({})


def _cve_mapping(cve_id: str, library_name: str) -> dict:
    return {
        "cve_details": {cve_id: {"library_name": library_name}},
        "library_summary": {},
        "total_cves": 1,
        "libraries_affected": 1,
    }


def test_cve_finding_flags_scraped_version_for_review():
    """A CVE finding for a path-scraped library is labeled NEEDS_REVIEW (labeling only)."""
    cve = _disabled_cve_assessment()

    vuln = CVEVulnerability(
        cve_id="CVE-2021-0001", summary="test issue", severity=CVESeverity.HIGH, cvss_score=7.5
    )
    vuln.source_library = "IronSource"

    library_lookup = {
        "IronSource": {
            "name": "IronSource",
            "version": "7.2.1",
            "version_source": "scraped",
            "file_path": "",
        }
    }

    finding = cve._create_enhanced_severity_finding(
        [vuln],
        AnalysisSeverity.HIGH,
        "High-Risk CVE",
        "desc",
        library_lookup,
        _cve_mapping("CVE-2021-0001", "IronSource"),
    )

    assert finding.verification_status == VerificationStatus.NEEDS_REVIEW
    assert finding.additional_data.get("version_source") == "scraped"
    assert finding.additional_data.get("verify") == "NVD/OSV"
    assert "IronSource" in finding.additional_data.get("scraped_libraries", [])


def test_cve_finding_declared_version_stays_confirmed():
    """A CVE finding for a declared-version library keeps the default CONFIRMED status."""
    cve = _disabled_cve_assessment()

    vuln = CVEVulnerability(
        cve_id="CVE-2021-0002", summary="test issue", severity=CVESeverity.HIGH, cvss_score=7.5
    )
    vuln.source_library = "OkHttp"

    library_lookup = {
        "OkHttp": {
            "name": "OkHttp",
            "version": "4.9.0",
            "version_source": "declared",
            "file_path": "",
        }
    }

    finding = cve._create_enhanced_severity_finding(
        [vuln],
        AnalysisSeverity.HIGH,
        "High-Risk CVE",
        "desc",
        library_lookup,
        _cve_mapping("CVE-2021-0002", "OkHttp"),
    )

    assert finding.verification_status == VerificationStatus.CONFIRMED
    assert "version_source" not in finding.additional_data
