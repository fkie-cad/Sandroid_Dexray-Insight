#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for Phase B3: reflection/onJsPrompt WebView JavaScript-bridge detection.

Covers ``MobileSpecificAssessment._assess_webview_bridge_surface`` — the higher-signal
bridge shape (WebChromeClient.onJsPrompt + reflective dispatch, as used by Kik Cards)
that the classic addJavascriptInterface WebView check cannot see.

Key behaviours under test:
- Conjunction guard: a bridge marker must co-occur with a prompt/reflection token.
- React-Native / Cordova false-positive guard: a lone ``invokeFunction`` never fires.
- Capability classification and R1 HIGH escalation when auth/messaging is reachable.
- Findings are NEEDS_DYNAMIC (review queue, out of the headline score).
"""

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.core.base_classes import VerificationStatus
from src.dexray_insight.security.mobile_specific_assessment import MobileSpecificAssessment


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _bridge_findings(all_strings, config=None):
    """Run the detector directly against a synthetic DEX string pool."""
    assessment = MobileSpecificAssessment(config or {})
    analysis_results = {"string_analysis": {"all_strings": all_strings}}
    return assessment._assess_webview_bridge_surface(analysis_results, None)


# --------------------------------------------------------------------------- #
# Ground-truth target: Kik Cards R1 shape -> ONE HIGH finding
# --------------------------------------------------------------------------- #
def test_reflection_prompt_bridge_with_auth_and_messaging_is_high():
    all_strings = [
        "onJsPrompt",
        "getDeclaredMethod",
        "invoke",
        "invokeFunction",
        "signRequest",
        "sendKik",
        "com/example/unrelated/Helper",
    ]

    findings = _bridge_findings(all_strings)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == AnalysisSeverity.HIGH
    assert finding.title == "WebView Reflection/Prompt JavaScript Bridge"
    assert finding.category.endswith(" - M1")
    assert finding.verification_status == VerificationStatus.NEEDS_DYNAMIC
    assert finding.confidence == 0.5

    capabilities = finding.additional_data["capabilities"]
    assert "auth" in capabilities
    assert "messaging" in capabilities
    assert finding.additional_data["verify_dynamically"] is True


# --------------------------------------------------------------------------- #
# React-Native / Cordova false-positive guard
# --------------------------------------------------------------------------- #
def test_lone_invoke_function_does_not_fire():
    all_strings = [
        "invokeFunction",
        "com/facebook/react/bridge/ReactContext",
        "renderApplication",
    ]

    findings = _bridge_findings(all_strings)

    assert findings == []


def test_bridge_marker_without_prompt_or_reflection_does_not_fire():
    # Bridge marker present, but no onJsPrompt/WebChromeClient and no reflection token.
    all_strings = ["nativeCall", "JavascriptGlue", "signRequest", "sendMessage"]

    findings = _bridge_findings(all_strings)

    assert findings == []


def test_reflection_token_not_matched_inside_invoke_function():
    # "invoke" as a reflection token must NOT be matched inside "invokeFunction":
    # otherwise a lone React-Native invokeFunction would satisfy the conjunction.
    all_strings = ["invokeFunction", "onJsPrompt"]

    findings = _bridge_findings(all_strings)

    # onJsPrompt (prompt) + invokeFunction (bridge) -> fires, but on the prompt path,
    # not because "invoke" leaked out of "invokeFunction".
    assert len(findings) == 1
    reflection_evidence = [e for e in findings[0].evidence if "Reflective dispatch" in e]
    assert reflection_evidence == []


# --------------------------------------------------------------------------- #
# MEDIUM when no auth/messaging capability co-occurs
# --------------------------------------------------------------------------- #
def test_prompt_reflection_bridge_without_auth_or_messaging_is_medium():
    all_strings = [
        "onJsPrompt",
        "getDeclaredMethod",
        "invokeFunction",
        "getContacts",  # pii capability, not auth/messaging
        "openFile",     # file capability
    ]

    findings = _bridge_findings(all_strings)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == AnalysisSeverity.MEDIUM
    capabilities = finding.additional_data["capabilities"]
    assert "pii" in capabilities
    assert "file" in capabilities
    assert "auth" not in capabilities
    assert "messaging" not in capabilities


def test_reflection_bridge_without_any_capability_is_medium():
    all_strings = ["nativeCall", "getMethod", "invoke"]

    findings = _bridge_findings(all_strings)

    assert len(findings) == 1
    assert findings[0].severity == AnalysisSeverity.MEDIUM
    assert findings[0].additional_data["capabilities"] == []


# --------------------------------------------------------------------------- #
# Prompt-only path (no reflection) still fires via the WebChromeClient channel
# --------------------------------------------------------------------------- #
def test_prompt_channel_without_reflection_fires():
    all_strings = ["WebChromeClient", "onJsPrompt", "JavascriptGlue", "sendMessage"]

    findings = _bridge_findings(all_strings)

    assert len(findings) == 1
    assert findings[0].severity == AnalysisSeverity.HIGH  # messaging capability present


# --------------------------------------------------------------------------- #
# Opt-in extra bridge markers
# --------------------------------------------------------------------------- #
def test_extra_bridge_marker_is_opt_in():
    # Only one signal class here by default (prompt), so nothing corroborates it.
    all_strings = ["CardsBridge", "onJsPrompt"]

    # Default: app-specific literal is NOT a bridge marker -> only the prompt class is
    # present -> single signal class -> no finding (avoids single-sample overfit).
    assert _bridge_findings(all_strings) == []

    # Opt-in via config: CardsBridge becomes a bridge marker, so now marker + prompt
    # are two independent signal classes and the finding fires.
    findings = _bridge_findings(all_strings, config={"webview_extra_bridge_markers": ["CardsBridge"]})
    assert len(findings) == 1
    assert "CardsBridge" in findings[0].evidence[0]


# --------------------------------------------------------------------------- #
# Robustness: empty / malformed input
# --------------------------------------------------------------------------- #
def test_empty_strings_no_finding():
    assert _bridge_findings([]) == []


def test_non_string_entries_are_ignored():
    findings = _bridge_findings([None, 123, {"k": "v"}, "invokeFunction"])
    assert findings == []


# --------------------------------------------------------------------------- #
# Integration: the detector is actually invoked from assess()
# --------------------------------------------------------------------------- #
def test_assess_includes_bridge_finding():
    assessment = MobileSpecificAssessment({})
    analysis_results = {
        "string_analysis": {
            "all_strings": ["onJsPrompt", "getDeclaredMethod", "invoke", "signRequest", "sendKik"]
        }
    }

    findings = assessment.assess(analysis_results)

    bridge = [f for f in findings if f.title == "WebView Reflection/Prompt JavaScript Bridge"]
    assert len(bridge) == 1
    assert bridge[0].severity == AnalysisSeverity.HIGH
