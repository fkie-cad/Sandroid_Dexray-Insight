#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for permission_analysis and api_invocation result extraction."""

from unittest.mock import MagicMock
from unittest.mock import patch

from dexray_insight.core.base_classes import AnalysisContext
from dexray_insight.core.base_classes import AnalysisStatus
from dexray_insight.modules.api_invocation_analysis import APIInvocationAnalysisModule
from dexray_insight.modules.permission_analysis import PermissionAnalysisModule


def _context(androguard_obj=None) -> AnalysisContext:
    return AnalysisContext(apk_path="/tmp/app.apk", config={}, androguard_obj=androguard_obj)


class TestPermissionAnalysis:
    PERMISSIONS = [
        "android.permission.INTERNET",
        "android.permission.ACCESS_FINE_LOCATION",
        "com.google.android.gms.permission.AD_ID",
    ]

    def test_reads_permissions_from_the_shared_androguard_object(self):
        apk = MagicMock()
        apk.get_permissions.return_value = self.PERMISSIONS
        androguard_obj = MagicMock()
        androguard_obj.get_androguard_apk.return_value = apk

        with patch("dexray_insight.modules.permission_analysis.APK") as apk_cls:
            result = PermissionAnalysisModule({}).analyze("/tmp/app.apk", _context(androguard_obj))

        apk_cls.assert_not_called()  # the already-parsed APK is reused
        assert result.status == AnalysisStatus.SUCCESS
        assert result.all_permissions == self.PERMISSIONS
        assert "android.permission.ACCESS_FINE_LOCATION" in result.critical_permissions
        assert result.permissions_used == 3

    def test_parses_the_apk_when_no_androguard_object(self):
        with patch("dexray_insight.modules.permission_analysis.APK") as apk_cls:
            apk_cls.return_value.get_permissions.return_value = self.PERMISSIONS
            result = PermissionAnalysisModule({}).analyze("/tmp/app.apk", _context())

        apk_cls.assert_called_once_with("/tmp/app.apk")
        assert result.all_permissions == self.PERMISSIONS


def _method(class_name: str, name: str, calls=()):
    """Build a fake androguard MethodAnalysis with outgoing xrefs."""
    encoded = MagicMock()
    encoded.get_class_name.return_value = class_name
    encoded.get_name.return_value = name
    method = MagicMock()
    method.get_method.return_value = encoded
    method.get_xref_to.return_value = [(None, callee, 0) for callee in calls]
    return method


class TestApiInvocation:
    def _run(self, methods):
        dx = MagicMock()
        dx.get_methods.return_value = methods
        androguard_obj = MagicMock()
        androguard_obj.get_androguard_analysis_obj.return_value = dx
        return APIInvocationAnalysisModule({}).analyze("/tmp/app.apk", _context(androguard_obj))

    def test_suspicious_patterns_match_smali_descriptors(self):
        location = _method("Landroid/location/LocationManager;", "getLastKnownLocation")
        settings = _method("Landroid/provider/Settings$Secure;", "getString")
        caller = _method("Lcom/example/app/Main;", "onCreate", calls=[location, settings])

        result = self._run([caller])

        patterns = {call["suspicious_pattern"] for call in result.suspicious_api_calls}
        assert patterns == {"android.location.LocationManager", "android.provider.Settings.Secure"}

    def test_reflection_usage_is_detected(self):
        for_name = _method("Ljava/lang/Class;", "forName")
        caller = _method("Lcom/example/app/Loader;", "load", calls=[for_name])

        result = self._run([caller])

        assert [r["reflection_api"] for r in result.reflection_usage] == ["java.lang.Class.forName"]

    def test_records_calls_into_bundled_privacy_sdks(self):
        ad_id = _method("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;", "getAdvertisingIdInfo")
        fused = _method("Lcom/google/android/gms/location/FusedLocationProviderClient;", "getLastLocation")
        unrelated = _method("Lcom/squareup/okhttp/OkHttpClient;", "newCall")
        caller = _method("Lcom/appsflyer/internal/AFa1;", "run", calls=[ad_id, fused, unrelated])

        result = self._run([caller])

        called = {(c["called_class"], c["called_method"]) for c in result.api_calls}
        assert ("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;", "getAdvertisingIdInfo") in called
        assert ("Lcom/google/android/gms/location/FusedLocationProviderClient;", "getLastLocation") in called
        assert all("okhttp" not in cls for cls, _ in called)
        assert {c["api_type"] for c in result.api_calls} == {"third_party_sdk"}

    def test_skips_calls_inside_the_same_sdk(self):
        ad_id = _method("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;", "zza")
        caller = _method("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;", "getAdvertisingIdInfo", [ad_id])

        assert self._run([caller]).api_calls == []

    def test_skips_google_internal_packages_calling_public_apis(self):
        fused = _method("Lcom/google/android/gms/location/FusedLocationProviderClient;", "getLastLocation")
        internal = _method("Lcom/google/android/gms/internal/location/zzbe;", "zza", calls=[fused])
        measurement = _method("Lcom/google/android/gms/measurement/internal/zzk;", "run", calls=[fused])

        assert self._run([internal, measurement]).api_calls == []

    def test_reflection_patterns_match_exact_methods_only(self):
        get_name = _method("Ljava/lang/reflect/Field;", "getName")
        get_type = _method("Ljava/lang/reflect/Field;", "getType")
        field_get = _method("Ljava/lang/reflect/Field;", "get")
        caller = _method("Lcom/example/app/Loader;", "load", calls=[get_name, get_type, field_get])

        result = self._run([caller])

        assert [r["reflection_api"] for r in result.reflection_usage] == ["java.lang.reflect.Field.get"]


class TestPiiCorrelationUsesCalledApiOnly:
    def test_caller_method_name_does_not_satisfy_a_sink(self):
        from dexray_insight.security.pii_assessment import PIIAssessment

        call = {
            "caller_class": "Lcom/example/app/Geo;",
            "caller_method": "getLastKnownLocation",
            "called_class": "Landroid/util/Log;",
            "called_method": "d",
        }
        assert "getlastknownlocation" not in PIIAssessment._api_call_text(call)
        assert PIIAssessment._api_call_text({**call, "called_method": "getLastKnownLocation"}).endswith(
            "getlastknownlocation"
        )
