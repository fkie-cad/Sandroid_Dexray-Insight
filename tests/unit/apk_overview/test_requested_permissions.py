#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Requested-permission extraction: both request tags, maxSdkVersion, effective counts.

The fixture mirrors Firefox 145's manifest shape that exposed the miscount: 35
``<uses-permission>`` names (three with maxSdkVersion 26/28/32) plus one
``<uses-permission-sdk-23>``. Insight used to report 35; the manifest requests 36,
and an API 35 device keeps 33 (what ``dumpsys package`` lists as requested).
"""

from unittest.mock import MagicMock
from unittest.mock import patch

from dexray_insight.apk_overview.requested_permissions import effective_permission_names
from dexray_insight.apk_overview.requested_permissions import requested_permission_entries
from dexray_insight.apk_overview.requested_permissions import requested_permission_names
from dexray_insight.core.base_classes import AnalysisContext
from dexray_insight.modules.permission_analysis import PermissionAnalysisModule


class _Tag:
    def __init__(self, **attrs):
        self.attrs = attrs


class _FakeApk:
    """Just enough of androguard's APK: find_tags / get_value_from_tag / get_permissions."""

    def __init__(self, tags):
        self._tags = tags

    def find_tags(self, tag_name):
        return [tag for name, tag in self._tags if name == tag_name]

    def get_value_from_tag(self, tag, attribute):
        return tag.attrs.get(attribute)

    def get_permissions(self):
        # androguard only reads <uses-permission>, unordered
        return list({tag.attrs["name"] for name, tag in self._tags if name == "uses-permission"})


def _firefox_like_apk():
    tags = [("uses-permission", _Tag(name=f"android.permission.P{i}")) for i in range(32)]
    tags += [
        ("uses-permission", _Tag(name="android.permission.READ_EXTERNAL_STORAGE", maxSdkVersion="32")),
        ("uses-permission", _Tag(name="android.permission.WRITE_EXTERNAL_STORAGE", maxSdkVersion="28")),
        ("uses-permission", _Tag(name="com.android.launcher.permission.INSTALL_SHORTCUT", maxSdkVersion="26")),
        ("uses-permission-sdk-23", _Tag(name="android.permission.REQUEST_INSTALL_PACKAGES")),
    ]
    return _FakeApk(tags)


def test_both_request_tags_are_counted():
    apk = _firefox_like_apk()
    assert len(apk.get_permissions()) == 35  # the old (androguard) count
    names = requested_permission_names(apk)
    assert len(names) == 36
    assert "android.permission.REQUEST_INSTALL_PACKAGES" in names


def test_entries_keep_tag_and_max_sdk_in_manifest_order():
    entries = requested_permission_entries(_firefox_like_apk())
    assert entries[0] == {"name": "android.permission.P0", "tag": "uses-permission", "max_sdk_version": None}
    by_name = {entry["name"]: entry for entry in entries}
    assert by_name["android.permission.WRITE_EXTERNAL_STORAGE"]["max_sdk_version"] == 28
    assert by_name["android.permission.REQUEST_INSTALL_PACKAGES"]["tag"] == "uses-permission-sdk-23"


def test_effective_names_drop_requests_capped_below_the_api_level():
    entries = requested_permission_entries(_firefox_like_apk())
    assert len(effective_permission_names(entries, 35)) == 33
    assert len(effective_permission_names(entries, 32)) == 34  # READ_EXTERNAL_STORAGE still applies
    assert len(effective_permission_names(entries, 23)) == 36


def test_duplicates_count_once_and_invalid_max_sdk_is_ignored():
    apk = _FakeApk(
        [
            ("uses-permission", _Tag(name="android.permission.CAMERA")),
            ("uses-permission-sdk-23", _Tag(name="android.permission.CAMERA")),
            ("uses-permission", _Tag(name="android.permission.INTERNET", maxSdkVersion="@integer/x")),
        ]
    )
    assert requested_permission_names(apk) == ["android.permission.CAMERA", "android.permission.INTERNET"]
    assert len(requested_permission_entries(apk)) == 3
    assert requested_permission_entries(apk)[2]["max_sdk_version"] is None


def test_object_without_tag_access_falls_back_to_get_permissions():
    apk = MagicMock(spec=["get_permissions"])
    apk.get_permissions.return_value = ["android.permission.INTERNET"]
    assert requested_permission_names(apk) == ["android.permission.INTERNET"]
    assert requested_permission_names(None) == []


def test_permission_module_counts_sdk23_requests():
    androguard_obj = MagicMock()
    androguard_obj.get_androguard_apk.return_value = _firefox_like_apk()
    context = AnalysisContext(apk_path="/tmp/app.apk", config={}, androguard_obj=androguard_obj)

    with patch("dexray_insight.modules.permission_analysis.APK"):
        result = PermissionAnalysisModule({}).analyze("/tmp/app.apk", context)

    assert result.permissions_used == 36
