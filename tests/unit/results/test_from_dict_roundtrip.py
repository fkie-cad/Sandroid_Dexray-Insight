"""Round-trip contract tests for `from_dict` reconstruction of result classes.

These tests verify that ``Cls.from_dict(inst.to_dict())`` reproduces a result
whose ``to_dict()`` matches the original (round-trip stable), that the
downstream-consumed typed attributes survive reconstruction, and that the
``status`` field is restored as an ``AnalysisStatus`` enum. They back the
per-module result cache which persists results via ``to_dict`` and rehydrates
them via ``from_dict``.
"""

from dexray_insight.core.base_classes import AnalysisStatus
from dexray_insight.core.base_classes import BaseResult
from dexray_insight.modules.apk_overview_analysis import APKOverviewResult
from dexray_insight.modules.dotnet_analysis import DotnetAnalysisResult
from dexray_insight.modules.manifest_analysis import ManifestAnalysisResult
from dexray_insight.modules.permission_analysis import PermissionAnalysisResult
from dexray_insight.modules.signature_analysis import SignatureAnalysisResult
from dexray_insight.modules.string_analysis.string_analysis_module import StringAnalysisResult


def test_base_result_roundtrip():
    original = BaseResult(
        module_name="base_module",
        status=AnalysisStatus.FAILURE,
        execution_time=1.25,
        error_message="something went wrong",
    )
    restored = BaseResult.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()
    assert isinstance(restored.status, AnalysisStatus)
    assert restored.status == AnalysisStatus.FAILURE
    assert restored.module_name == "base_module"
    assert restored.execution_time == 1.25
    assert restored.error_message == "something went wrong"


def test_string_analysis_roundtrip():
    original = StringAnalysisResult(
        module_name="string_analysis",
        status=AnalysisStatus.SUCCESS,
        execution_time=2.5,
        emails=["a@example.com", "b@example.com"],
        ip_addresses=["10.0.0.1", "192.168.1.1"],
        urls=["https://example.com", "http://test.org"],
        domains=["example.com", "test.org"],
        android_properties={"ro.build.version.sdk": "30"},
        all_strings=["hello", "world", "https://example.com"],
        total_strings_analyzed=3,
    )
    restored = StringAnalysisResult.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()
    assert isinstance(restored.status, AnalysisStatus)

    # Downstream-consumed typed attributes must survive exactly.
    assert restored.all_strings == original.all_strings
    assert restored.urls == original.urls
    assert restored.domains == original.domains
    assert restored.emails == original.emails
    assert restored.ip_addresses == original.ip_addresses
    assert restored.android_properties == original.android_properties
    assert restored.total_strings_analyzed == original.total_strings_analyzed


def test_string_analysis_ignores_unknown_keys():
    original = StringAnalysisResult(
        module_name="string_analysis",
        status=AnalysisStatus.SUCCESS,
        all_strings=["x"],
    )
    data = original.to_dict()
    data["analysis_summary"] = {"unexpected": True}  # extra/derived key
    restored = StringAnalysisResult.from_dict(data)

    assert restored.all_strings == ["x"]
    assert restored.to_dict() == original.to_dict()


def test_manifest_analysis_roundtrip():
    original = ManifestAnalysisResult(
        module_name="manifest_analysis",
        status=AnalysisStatus.SUCCESS,
        execution_time=0.75,
        package_name="com.example.app",
        main_activity="com.example.app.MainActivity",
        permissions=["android.permission.INTERNET", "android.permission.CAMERA"],
        activities=["MainActivity", "SettingsActivity"],
        services=["SyncService"],
        receivers=["BootReceiver"],
        content_providers=["FileProvider"],
        intent_filters=[{"action": "android.intent.action.MAIN"}],
    )
    restored = ManifestAnalysisResult.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()
    assert isinstance(restored.status, AnalysisStatus)

    # Downstream-consumed typed attributes must survive exactly.
    assert restored.permissions == original.permissions
    assert restored.activities == original.activities
    assert restored.package_name == original.package_name


def test_manifest_analysis_restores_manifest_xml_when_present():
    # manifest_xml is a constructor field that to_dict does not emit, but
    # from_dict must still restore it defensively when the key is supplied.
    data = {
        "module_name": "manifest_analysis",
        "status": AnalysisStatus.SUCCESS.value,
        "manifest_xml": "<manifest></manifest>",
    }
    restored = ManifestAnalysisResult.from_dict(data)
    assert restored.manifest_xml == "<manifest></manifest>"


def test_manifest_analysis_drops_components_summary():
    original = ManifestAnalysisResult(
        module_name="manifest_analysis",
        status=AnalysisStatus.SUCCESS,
        activities=["A", "B"],
        permissions=["P"],
    )
    data = original.to_dict()
    # components_summary is a derived key present in to_dict output.
    assert "components_summary" in data
    restored = ManifestAnalysisResult.from_dict(data)

    # It must not break reconstruction and must be recomputed on serialization.
    assert restored.activities == ["A", "B"]
    assert restored.to_dict() == original.to_dict()
    assert restored.to_dict()["components_summary"]["total_activities"] == 2


def test_permission_analysis_roundtrip():
    original = PermissionAnalysisResult(
        module_name="permission_analysis",
        status=AnalysisStatus.SUCCESS,
        execution_time=0.5,
        all_permissions=["INTERNET", "CAMERA", "READ_SMS"],
        critical_permissions=["READ_SMS"],
        permissions_used=3,
        critical_permissions_found=1,
    )
    restored = PermissionAnalysisResult.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()
    assert isinstance(restored.status, AnalysisStatus)
    assert restored.all_permissions == original.all_permissions
    assert restored.critical_permissions == original.critical_permissions
    assert restored.permissions_used == 3
    assert restored.critical_permissions_found == 1


def test_signature_analysis_roundtrip():
    original = SignatureAnalysisResult(
        module_name="signature_detection",
        status=AnalysisStatus.SUCCESS,
        execution_time=3.0,
        signatures={"vt": {"detections": 5}},
        apk_hash="abc123def456",
        providers_checked=["virustotal", "triage"],
    )
    restored = SignatureAnalysisResult.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()
    assert isinstance(restored.status, AnalysisStatus)
    assert restored.signatures == original.signatures
    assert restored.apk_hash == "abc123def456"
    assert restored.providers_checked == original.providers_checked


def test_dotnet_analysis_roundtrip():
    original = DotnetAnalysisResult(
        module_name="dotnet_analysis",
        status=AnalysisStatus.SUCCESS,
        execution_time=4.2,
        found_assemblies=["Mono.Android.dll", "System.dll"],
        found_strings=["secret", "config"],
        dll_files_analyzed=["a.dll", "b.dll"],
        blob_files_processed=["assemblies.blob"],
        decompiled_files_count=7,
        manifest_found=True,
        extraction_method="blob_unpacking",
    )
    restored = DotnetAnalysisResult.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()
    assert isinstance(restored.status, AnalysisStatus)
    assert restored.found_assemblies == original.found_assemblies
    assert restored.found_strings == original.found_strings
    assert restored.dll_files_analyzed == original.dll_files_analyzed
    assert restored.blob_files_processed == original.blob_files_processed
    assert restored.decompiled_files_count == 7
    assert restored.manifest_found is True
    assert restored.extraction_method == "blob_unpacking"


def test_apk_overview_roundtrip():
    original = APKOverviewResult(
        module_name="apk_overview",
        status=AnalysisStatus.SUCCESS,
        execution_time=1.1,
        general_info={"package_name": "com.example.app", "version": "1.0"},
        components={"activities": ["MainActivity"]},
        permissions={"declared": ["INTERNET"]},
        certificates={"sha256": "deadbeef"},
        native_libs=["libnative.so"],
        directory_listing=["classes.dex", "AndroidManifest.xml"],
        is_cross_platform=True,
        cross_platform_framework="Xamarin",
    )
    restored = APKOverviewResult.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()
    assert isinstance(restored.status, AnalysisStatus)
    assert restored.general_info == original.general_info
    assert restored.components == original.components
    assert restored.permissions == original.permissions
    assert restored.certificates == original.certificates
    assert restored.native_libs == original.native_libs
    assert restored.directory_listing == original.directory_listing
    assert restored.is_cross_platform is True
    assert restored.cross_platform_framework == "Xamarin"
