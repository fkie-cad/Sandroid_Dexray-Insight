#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

"""Unit tests for the SDK remote-code attack-surface assessment (A06).

These tests drive the assessment with synthetic analysis_results dicts and
assert the decoupling of SDK-RCE surface from CVE/version matching.
"""

from dexray_insight.core.base_classes import AnalysisSeverity
from dexray_insight.core.base_classes import VerificationStatus
from dexray_insight.security.data.sdk_risk_surface import SDK_RISK_SURFACE
from dexray_insight.security.sdk_risk_surface_assessment import SdkRiskSurfaceAssessment


def _assess(analysis_results):
    """Instantiate the assessment and run it against a synthetic result dict."""
    return SdkRiskSurfaceAssessment({}).assess(analysis_results, None)


def test_pangle_bridge_string_yields_high_finding_version_unknown():
    """A Pangle library (version None) + a download-manager bridge descriptor in
    the string pool yields ONE HIGH A06 finding noting the unknown version.
    """
    results = {
        "library_detection": {
            "detected_libraries": [{"name": "Pangle", "version": None}],
        },
        "string_analysis": {
            "all_strings": [
                "com/bytedance/sdk/openadsdk/core/widget/AdWebViewDownloadManagerImpl;",
                "some/unrelated/String",
            ],
        },
    }

    findings = _assess(results)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "A06:2021-Vulnerable and Outdated Components"
    assert finding.severity == AnalysisSeverity.HIGH  # download_and_install capability
    assert finding.verification_status == VerificationStatus.NEEDS_REVIEW
    assert finding.confidence == 0.6
    assert "Pangle" in finding.title
    assert finding.additional_data["sdk"] == "Pangle"
    assert finding.additional_data["verify_dynamically"] is True
    assert "download_and_install" in finding.additional_data["capabilities"]
    # Version-unknown must be reflected in the evidence.
    assert any("version unknown" in ev.lower() for ev in finding.evidence)
    # And the matched bridge descriptor must be recorded.
    assert any("AdWebViewDownloadManagerImpl" in ev for ev in finding.evidence)


def test_pangle_matches_below_headline_threshold():
    """The Pangle finding must stay off the confirmed headline (conf < 0.7 and
    NEEDS_REVIEW status).
    """
    results = {
        "library_detection": {"detected_libraries": [{"name": "Pangle", "version": None}]},
        "string_analysis": {"all_strings": ["AdWebViewDownloadManagerImpl"]},
    }

    finding = _assess(results)[0]

    assert finding.confidence < 0.7
    assert finding.verification_status != VerificationStatus.CONFIRMED


def test_medialab_library_match_without_version_yields_finding():
    """MediaLab present via library detection (no version, no bridge string)
    still yields a finding.
    """
    results = {
        "library_detection": {
            "detected_libraries": [{"name": "MediaLab", "version": None}],
        },
        "string_analysis": {"all_strings": []},
    }

    findings = _assess(results)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.additional_data["sdk"] == "MediaLab"
    assert finding.severity == AnalysisSeverity.MEDIUM
    assert any("version unknown" in ev.lower() for ev in finding.evidence)


def test_no_ad_sdks_yields_zero_findings():
    """An app with no ad SDKs and no bridge descriptors yields zero findings."""
    results = {
        "library_detection": {
            "detected_libraries": [
                {"name": "OkHttp", "version": "4.9.0"},
                {"name": "Gson", "version": "2.8.6"},
            ],
        },
        "string_analysis": {
            "all_strings": ["com/example/app/MainActivity", "https://api.example.com"],
        },
    }

    assert _assess(results) == []


def test_bare_package_substring_is_not_a_finding():
    """A bare package substring without a concrete bridge class and without a
    confirmed library match must NOT produce a finding.
    """
    results = {
        # No detected library entry for the SDK.
        "library_detection": {"detected_libraries": []},
        "string_analysis": {
            # Bare top-level package references only; no concrete bridge class.
            "all_strings": [
                "com.pubmatic.sdk",
                "com/pubmatic/sdk",
                "com.tapjoy",
            ],
        },
    }

    assert _assess(results) == []


def test_deduplicated_single_finding_when_both_signals_hit():
    """When BOTH a library match and a bridge string hit for the same SDK, only
    ONE finding is emitted (de-duplication per SDK).
    """
    results = {
        "library_detection": {"detected_libraries": [{"name": "Tapjoy", "version": "12.9.0"}]},
        "string_analysis": {"all_strings": ["com/tapjoy/TJAdUnitJSBridge"]},
    }

    findings = _assess(results)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.additional_data["sdk"] == "Tapjoy"
    # Version is known here, so it must be reflected (not "version unknown").
    assert any("12.9.0" in ev for ev in finding.evidence)


def test_library_objects_without_version_attribute_are_tolerated():
    """detected_libraries may contain objects (not dicts); name/version are read
    via attributes and a missing version degrades to 'version unknown'.
    """

    class _Lib:
        def __init__(self, name):
            self.name = name

    results = {
        "library_detection": {"detected_libraries": [_Lib("MediaLab")]},
        "string_analysis": {"all_strings": []},
    }

    findings = _assess(results)

    assert len(findings) == 1
    assert findings[0].additional_data["sdk"] == "MediaLab"


def _old_nested_match(bridge_classes, all_strings):
    """The pre-optimization O(descriptors × strings) nested-loop matcher."""
    for descriptor in bridge_classes:
        for s in all_strings:
            if descriptor in s:
                return descriptor
    return None


def test_joined_corpus_matching_equals_old_nested_loop():
    """The joined-buffer matcher returns the same descriptor as the old nested
    loop for representative inputs across every SDK in the knowledge base.
    """
    corpora = [
        [],
        ["com/example/app/MainActivity", "https://api.example.com"],
        [
            "com/bytedance/sdk/openadsdk/core/widget/AdWebViewDownloadManagerImpl;",
            "com/tapjoy/TJAdUnitJSBridge",
            "com/applovin/impl/adview/AdViewController",
        ],
        ["prefix-WindVaneWebView-suffix", "com/ironsource/sdk/controller/Foo"],
    ]

    for all_strings in corpora:
        joined = "\n".join(all_strings)
        for surface in SDK_RISK_SURFACE.values():
            bridge_classes = surface.get("bridge_classes", [])
            expected = _old_nested_match(bridge_classes, all_strings)
            actual = SdkRiskSurfaceAssessment._matched_bridge_descriptor(bridge_classes, joined)
            assert actual == expected
