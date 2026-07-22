#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Dexray Insight Contributors
#
# This file is part of Dexray Insight - Android APK Security Analysis Tool
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""DEEP PII-flow assessment (Phase C3).

Correlates a validated PII *source* (a sensitive field/column/literal) with a
per-tracker *sink*, and only fires on the source->sink conjunction — never on a
sink alone. This is the deliberate successor to the old false-positive-prone
"ssn substring in a log call" heuristic: a leak is reported only when a PII
source actually reaches an exfiltration/logging sink.

The assessment runs **only under ``--deep``** because it walks the Androguard
cross-reference graph (``create_xref`` is expensive) and consumes the opt-in
per-method ``string_locations`` attribution produced by tracker analysis.

Two evidence tiers, mirroring the framework's verification discipline:

* **Precise (xref path)** — a method both handles a PII source string (via
  ``string_locations``) *and* calls a sink method (via ``get_xref_to``), or a
  one-hop caller of the sink-calling method handles the source (``get_xref_from``).
  The data-flow fact is statically shown. Off-device sinks -> HIGH / CONFIRMED
  (confidence ~0.7).
* **Coarse (co-location)** — a detected tracker's code location shares a class
  with a PII source string's location. This is a bridge signal, not a proven
  path. Off-device sinks -> HIGH / NEEDS_DYNAMIC (confidence ~0.5).

Severity splits by sink destination: an on-device local log
(``android.util.Log``) is MEDIUM / NEEDS_DYNAMIC; an off-device third-party sink
(Crashlytics / Firebase / Branch / Mixpanel) is HIGH. When the PII source and the
sink both live under the same SDK package (framework prefix) the finding is
down-ranked — an SDK logging its own telemetry is not a first-party leak.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import VerificationStatus
from ..core.base_classes import register_assessment
from .deep_cache import cached_deep_findings
from .evidence import FRAMEWORK_PREFIXES
from .evidence import matches_algorithm_token
from .evidence.pii_taxonomy import ART9_TOKENS
from .evidence.pii_taxonomy import PII_TAXONOMY
from .evidence.pii_taxonomy import SENSITIVE_COLUMN_TOKENS
from .evidence.pii_taxonomy import PIIValidator
from .evidence.pii_taxonomy import is_placeholder_or_library_email

# Personal-data field tokens that mark a source. Columns + GDPR Art.9 special
# categories only; credential/secret pref tokens are a *secrets* concern handled
# elsewhere, not personal-data flow.
_SOURCE_TOKENS: frozenset[str] = SENSITIVE_COLUMN_TOKENS | ART9_TOKENS

# Rank used to keep the strongest finding when two tiers describe the same flow.
_STATUS_RANK = {
    VerificationStatus.CONFIRMED: 2,
    VerificationStatus.NEEDS_DYNAMIC: 1,
    VerificationStatus.NEEDS_REVIEW: 0,
}


@dataclass(frozen=True)
class SinkDescriptor:
    """A PII sink: a tracker/API method that receives personal data.

    Attributes:
        name: Stable sink identifier (e.g. "Crashlytics.recordException").
        tracker: Tracker/SDK family the sink belongs to.
        class_token: Lowercased substring matched against the callee DEX class
            name (e.g. "crashlytics", "landroid/util/log").
        methods: Exact callee method names that constitute the sink.
        off_device: True for third-party sinks that ship data off the device
            (HIGH); False for an on-device local log (MEDIUM).
        tracker_keyword: Lowercased token matched against a detected tracker's
            name for the coarse co-location bridge.
    """

    name: str
    tracker: str
    class_token: str
    methods: frozenset[str]
    off_device: bool
    tracker_keyword: str


# Sink catalog. Off-device sinks exfiltrate personal data to a third party;
# android.util.Log stays on-device. A callee matches when its lowercased class
# contains ``class_token`` AND its method name is in ``methods``.
PII_SINK_CATALOG: tuple[SinkDescriptor, ...] = (
    SinkDescriptor(
        name="Crashlytics.log/recordException",
        tracker="Crashlytics",
        class_token="crashlytics",
        methods=frozenset({"log", "recordException"}),
        off_device=True,
        tracker_keyword="crashlytics",
    ),
    SinkDescriptor(
        name="FirebaseAnalytics.logEvent",
        tracker="FirebaseAnalytics",
        class_token="firebase/analytics",
        methods=frozenset({"logEvent"}),
        off_device=True,
        tracker_keyword="firebase",
    ),
    SinkDescriptor(
        name="Branch.setIdentity",
        tracker="Branch",
        class_token="branch",
        methods=frozenset({"setIdentity"}),
        off_device=True,
        tracker_keyword="branch",
    ),
    SinkDescriptor(
        name="Mixpanel.identify",
        tracker="Mixpanel",
        class_token="mixpanel",
        methods=frozenset({"identify"}),
        off_device=True,
        tracker_keyword="mixpanel",
    ),
    SinkDescriptor(
        name="android.util.Log",
        tracker="android.util.Log",
        class_token="landroid/util/log",
        methods=frozenset({"d", "v", "i", "w", "e"}),
        off_device=False,
        tracker_keyword="android.util.log",
    ),
)


@dataclass
class _PIISources:
    """PII source attribution derived from ``string_locations``.

    ``locations`` maps a hosting method full-name ("Lclass;->method") to the
    source label; ``classes`` maps the class part to a label for the coarse
    tracker co-location bridge.
    """

    locations: dict[str, str] = field(default_factory=dict)
    classes: dict[str, str] = field(default_factory=dict)

    def any(self) -> bool:
        """Return True when at least one PII source was attributed to code."""
        return bool(self.locations or self.classes)


@register_assessment("pii_flow")
class PIIFlowAssessment(BaseSecurityAssessment):
    """DEEP PRIVACY:2024 assessment correlating PII sources with tracker sinks."""

    def __init__(self, config: dict[str, Any]):
        """Initialize the PII-flow assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "PRIVACY:2024-Personal Data Exposure"
        self.validator = PIIValidator()

    def assess(
        self, analysis_results: dict[str, Any], context: AnalysisContext | None = None
    ) -> list[SecurityFinding]:
        """Correlate PII sources with tracker sinks (deep-only).

        The deep gate is evaluated FIRST so a non-deep run stays a cheap ``[]``
        (never cached). The xref-driven correlation body is wrapped so a cached
        result for the same (apk_md5, "pii_flow", config) skips the androguard
        ``create_xref()`` rebuild entirely.
        """
        if not self._is_deep(context):
            return []

        return cached_deep_findings(
            context,
            "pii_flow",
            self.config,
            lambda: self._assess_deep(analysis_results, context),
        )

    def _assess_deep(
        self, analysis_results: dict[str, Any], context: AnalysisContext | None
    ) -> list[SecurityFinding]:
        """Run the xref/co-location correlation (the create_xref-heavy work)."""
        findings: dict[tuple[str, str, str], SecurityFinding] = {}
        try:
            sources = self._collect_pii_sources(context)
            if not sources.any():
                # No PII source attributed to code -> the required source->sink
                # conjunction can never be formed. Never fire on a sink alone.
                return []
            for finding in self._xref_findings(context, sources):
                self._merge(findings, finding)
            for finding in self._colocation_findings(analysis_results, sources):
                self._merge(findings, finding)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.error(f"PII-flow assessment failed: {exc}")
        return list(findings.values())

    # ----------------------------------------------------------- deep gate
    @staticmethod
    def _is_deep(context: AnalysisContext | None) -> bool:
        """Return True only when analysis is running in deep mode."""
        cfg = getattr(context, "config", {}) or {}
        behaviour = cfg.get("behaviour_analysis") or {}
        return bool(cfg.get("deep_mode") or behaviour.get("deep_mode"))

    # -------------------------------------------------------- source model
    def _collect_pii_sources(self, context: AnalysisContext | None) -> _PIISources:
        """Attribute PII source strings to the code locations that reference them.

        Uses the opt-in ``string_locations`` map (string -> [method full-names])
        produced by tracker analysis under deep mode. Only strings that validate
        as a PII source are kept, so the source set is precise, not the raw pool.
        """
        sources = _PIISources()
        string_locations = getattr(context, "string_locations", None)
        if not isinstance(string_locations, dict):
            return sources

        for value, locations in string_locations.items():
            if not isinstance(value, str):
                continue
            label = self._pii_label(value)
            if label is None:
                continue
            for location in locations or []:
                if not isinstance(location, str) or "->" not in location:
                    continue
                sources.locations.setdefault(location, label)
                sources.classes.setdefault(self._class_of(location), label)
        return sources

    def _pii_label(self, value: str) -> str | None:
        """Return a source label if ``value`` is a validated PII source, else None."""
        for token in _SOURCE_TOKENS:
            if matches_algorithm_token(value, token):
                return token
        for pattern in PII_TAXONOMY:
            match = pattern.regex.search(value)
            if not match:
                continue
            literal = match.group(0)
            if pattern.name == "email":
                if is_placeholder_or_library_email(literal):
                    continue
                return "email"
            if not self.validator.evaluate(literal, value, pattern).rejected:
                return pattern.name
        return None

    # -------------------------------------------------------- precise xref
    def _xref_findings(
        self, context: AnalysisContext | None, sources: _PIISources
    ) -> list[SecurityFinding]:
        """Walk the xref graph for sink calls reachable from a PII-handling method."""
        dx = self._analysis_obj(context)
        if dx is None:
            return []

        findings: list[SecurityFinding] = []
        for method in dx.get_methods():
            try:
                caller = method.get_method()
                caller_class = caller.get_class_name()
                caller_full = f"{caller_class}->{caller.get_name()}"
                for call in method.get_xref_to():
                    sink = self._match_sink(call)
                    if sink is None:
                        continue
                    source = self._reaching_source(method, caller_full, sources)
                    if source is None:
                        continue
                    label, via = source
                    findings.append(
                        self._precise_finding(label, sink, via, caller_class, self._callee_class(call))
                    )
            except Exception as exc:  # pragma: no cover - defensive per-method
                self.logger.debug(f"xref walk skipped a method: {exc}")
        return findings

    def _reaching_source(
        self, method: Any, caller_full: str, sources: _PIISources
    ) -> tuple[str, str] | None:
        """Find a PII source handled by the sink-calling method or a 1-hop caller."""
        if caller_full in sources.locations:
            return sources.locations[caller_full], caller_full
        try:
            for call in method.get_xref_from():
                upstream = call[1].get_method()
                upstream_full = f"{upstream.get_class_name()}->{upstream.get_name()}"
                if upstream_full in sources.locations:
                    return sources.locations[upstream_full], upstream_full
        except Exception:  # pragma: no cover - reverse xref optional
            return None
        return None

    # ------------------------------------------------------ coarse bridge
    def _colocation_findings(
        self, analysis_results: dict[str, Any], sources: _PIISources
    ) -> list[SecurityFinding]:
        """Bridge detected trackers to PII sources by shared code class (coarse)."""
        tracker_section = self._section(analysis_results, "tracker_analysis")
        trackers = tracker_section.get("detected_trackers") or []

        findings: list[SecurityFinding] = []
        for tracker in trackers:
            tracker_name, locations = self._tracker_fields(tracker)
            sink = self._match_tracker(tracker_name)
            if sink is None:
                continue
            for location in locations:
                if not isinstance(location, str):
                    continue
                tracker_class = self._class_of(location)
                label = sources.classes.get(tracker_class)
                if label is None:
                    continue
                findings.append(
                    self._coarse_finding(label, sink, tracker_class, tracker_name)
                )
                break  # one co-location finding per tracker is enough
        return findings

    # --------------------------------------------------------- findings
    def _precise_finding(
        self,
        source_label: str,
        sink: SinkDescriptor,
        via: str,
        source_class: str,
        sink_class: str,
    ) -> SecurityFinding:
        """Build a finding for a statically shown source->sink path."""
        # Off-device with a real xref path is CONFIRMED; a local log is a proven
        # write but its sensitivity/runtime-reachability still needs a dynamic check.
        status = VerificationStatus.CONFIRMED if sink.off_device else VerificationStatus.NEEDS_DYNAMIC
        confidence = 0.7 if sink.off_device else 0.55
        return self._build_finding(
            source_label, sink, via, status, confidence, source_class, sink_class, coarse=False
        )

    def _coarse_finding(
        self, source_label: str, sink: SinkDescriptor, sink_class: str, tracker_name: str
    ) -> SecurityFinding:
        """Build a finding for a co-location-only (coarse) source->sink signal."""
        return self._build_finding(
            source_label,
            sink,
            via=f"co-location in {sink_class}",
            status=VerificationStatus.NEEDS_DYNAMIC,
            confidence=0.5,
            source_class=sink_class,
            sink_class=sink_class,
            coarse=True,
        )

    def _build_finding(
        self,
        source_label: str,
        sink: SinkDescriptor,
        via: str,
        status: VerificationStatus,
        confidence: float,
        source_class: str,
        sink_class: str,
        coarse: bool,
    ) -> SecurityFinding:
        down_ranked = self._same_sdk(source_class, sink_class)
        severity = AnalysisSeverity.HIGH if sink.off_device else AnalysisSeverity.MEDIUM
        if down_ranked:
            # SDK logging its own telemetry is not a first-party leak.
            severity = AnalysisSeverity.MEDIUM if sink.off_device else AnalysisSeverity.LOW
            status = VerificationStatus.NEEDS_REVIEW
            confidence = round(confidence * 0.7, 2)

        destination = "off-device third-party sink" if sink.off_device else "on-device local log"
        return SecurityFinding(
            category=self.owasp_category,
            severity=severity,
            title=f"PII flow to {destination}: {source_label} -> {sink.tracker}",
            description=(
                f"A validated personal-data source ('{source_label}') reaches the "
                f"{sink.tracker} sink ({sink.name}). "
                + (
                    "The path is co-located (shared code class) rather than statically traced; "
                    "dynamic verification is required."
                    if coarse
                    else "The path is shown by static cross-references."
                )
                + (
                    " Down-ranked: source and sink share the same SDK package (self-telemetry)."
                    if down_ranked
                    else ""
                )
            ),
            evidence=[
                f"source field: {source_label}",
                f"sink: {sink.name}",
                f"tracker: {sink.tracker}",
                f"path: {via}",
            ],
            recommendations=[
                "Confirm the personal data sent to this sink is necessary and disclosed",
                "Avoid sending raw personal data to third-party trackers / crash reporters"
                if sink.off_device
                else "Avoid logging personal data; strip PII before android.util.Log calls",
                "Verify a lawful basis and data minimization for the transmitted field",
            ],
            confidence=confidence,
            verification_status=status,
            additional_data={
                "tracker": sink.tracker,
                "sink": sink.name,
                "off_device": sink.off_device,
                "source": source_label,
                "path": via,
                "down_ranked": down_ranked,
                "evidence_tier": "co-location" if coarse else "xref",
            },
        )

    def _merge(
        self,
        findings: dict[tuple[str, str, str], SecurityFinding],
        finding: SecurityFinding,
    ) -> None:
        """Keep the strongest finding per (source, sink, tracker) tuple."""
        data = finding.additional_data
        key = (data["source"], data["sink"], data["tracker"])
        existing = findings.get(key)
        if existing is None or self._is_stronger(finding, existing):
            findings[key] = finding

    @staticmethod
    def _is_stronger(candidate: SecurityFinding, existing: SecurityFinding) -> bool:
        """A CONFIRMED (xref) finding supersedes a NEEDS_DYNAMIC (co-location) one."""
        return _STATUS_RANK[candidate.verification_status] > _STATUS_RANK[existing.verification_status]

    # ----------------------------------------------------------- helpers
    @staticmethod
    def _analysis_obj(context: AnalysisContext | None) -> Any | None:
        """Return the Androguard Analysis (xref) object, or None when unavailable."""
        androguard_obj = getattr(context, "androguard_obj", None)
        if androguard_obj is None:
            return None
        try:
            return androguard_obj.get_androguard_analysis_obj()
        except Exception:  # pragma: no cover - defensive
            return None

    @staticmethod
    def _callee_class(call: Any) -> str:
        """Return the DEX class name of an xref_to callee, or ''."""
        try:
            return call[1].get_method().get_class_name()
        except Exception:  # pragma: no cover - defensive
            return ""

    def _match_sink(self, call: Any) -> SinkDescriptor | None:
        """Return the sink descriptor an xref_to call targets, or None."""
        try:
            callee = call[1].get_method()
            return self._descriptor_for(callee.get_class_name(), callee.get_name())
        except Exception:  # pragma: no cover - defensive
            return None

    @staticmethod
    def _descriptor_for(class_name: str, method_name: str) -> SinkDescriptor | None:
        """Match a callee (class, method) against the sink catalog."""
        lowered_class = (class_name or "").lower()
        for sink in PII_SINK_CATALOG:
            if sink.class_token in lowered_class and method_name in sink.methods:
                return sink
        return None

    @staticmethod
    def _match_tracker(tracker_name: str) -> SinkDescriptor | None:
        """Match a detected tracker's name against off-device sink families."""
        lowered = (tracker_name or "").lower()
        for sink in PII_SINK_CATALOG:
            if sink.off_device and sink.tracker_keyword in lowered:
                return sink
        return None

    @staticmethod
    def _tracker_fields(tracker: Any) -> tuple[str, list[str]]:
        """Extract (name, locations) from a tracker dict or DetectedTracker."""
        if isinstance(tracker, dict):
            return tracker.get("name", ""), tracker.get("locations") or []
        return getattr(tracker, "name", ""), getattr(tracker, "locations", None) or []

    @staticmethod
    def _class_of(location: str) -> str:
        """Return the class part of a 'Lclass;->method' location string."""
        return location.split("->", 1)[0]

    @staticmethod
    def _same_sdk(class_a: str, class_b: str) -> bool:
        """True when both classes fall under the same framework/SDK prefix."""
        prefix_a = PIIFlowAssessment._framework_prefix(class_a)
        prefix_b = PIIFlowAssessment._framework_prefix(class_b)
        return prefix_a is not None and prefix_a == prefix_b

    @staticmethod
    def _framework_prefix(class_name: str) -> str | None:
        """Return the framework prefix a DEX class belongs to, or None."""
        dotted = class_name.lstrip("L").rstrip(";").replace("/", ".")
        if not dotted.endswith("."):
            dotted += "."
        for prefix in FRAMEWORK_PREFIXES:
            if dotted.startswith(prefix):
                return prefix
        return None

    @staticmethod
    def _section(analysis_results: dict[str, Any], key: str) -> dict[str, Any]:
        """Return a module's result as a dict, tolerating result objects."""
        section = analysis_results.get(key, {})
        if hasattr(section, "to_dict"):
            section = section.to_dict()
        return section if isinstance(section, dict) else {}
