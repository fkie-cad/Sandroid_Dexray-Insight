#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) {{ year }} Dexray Insight Contributors
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

"""Security finding post-processing pass (PR-7).

Runs after all OWASP assessments have produced their findings but BEFORE the
engine backfills severity-derived confidence and computes the risk score. Two
ordered stages:

1. Confidence / false-positive pass (SECRET / sensitive-data findings only):
   uses the (now-activated) :class:`FalsePositiveFilter` and
   :class:`CodeContextAnalyzer` to compute a false-positive probability and fold
   it into ``finding.confidence`` as ``base_confidence x (1 - fp_probability)``.
   Severity is NEVER mutated here — the scorer uses ``severity x confidence`` and
   confidence already carries the FP signal, so a severity downgrade would double
   penalise. Any display-only tier is recorded in ``additional_data``.

2. Cross-finding cleartext correlation: assessments run in isolation and never see
   one another's findings, so a manifest cleartext-traffic fact can only be joined
   with a PII or WebView-bridge finding here, once the full finding list is known.
   Emits at most one correlated "A05:2021-Security Misconfiguration" finding.

3. Cross-assessment dedup: findings that describe the same underlying issue
   (same location/value + normalized title stem) are merged, keeping the strongest
   severity and confidence and unioning evidence/recommendations/cve_references.

Design Pattern: Pipeline (ordered, independently-toggleable stages).
SOLID: Single Responsibility (post-processing only; does not detect anything).
"""

import logging
import re
from typing import Any

from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import SecurityFinding
from ..core.base_classes import VerificationStatus
from .context_analysis.code_context_analyzer import CodeContextAnalyzer
from .context_analysis.false_positive_filter import FalsePositiveFilter
from .context_analysis.models.context_models import CodeContext
from .manifest_facts import get_manifest_facts


class FindingPostProcessor:
    """Applies the false-positive confidence pass and cross-assessment dedup."""

    # Severity-derived default confidence for findings an assessment left unscored.
    # Mirrors the engine's backfill defaults so the two stages agree.
    SEVERITY_DEFAULT_CONFIDENCE = {
        AnalysisSeverity.CRITICAL: 0.8,
        AnalysisSeverity.HIGH: 0.5,
        AnalysisSeverity.MEDIUM: 0.4,
        AnalysisSeverity.LOW: 0.3,
    }

    # OWASP categories whose findings represent secrets / sensitive data and are
    # therefore eligible for the false-positive confidence pass.
    SECRET_CATEGORIES = {"A02:2021-Cryptographic Failures"}

    _SEVERITY_RANK = {
        AnalysisSeverity.LOW: 1,
        AnalysisSeverity.MEDIUM: 2,
        AnalysisSeverity.HIGH: 3,
        AnalysisSeverity.CRITICAL: 4,
    }

    # Category shared by every correlated finding this stage emits.
    _MISCONFIG_CATEGORY = "A05:2021-Security Misconfiguration"

    # Category identifying PII (Personal Data Exposure) findings to correlate with.
    _PII_CATEGORY = "PRIVACY:2024-Personal Data Exposure"

    # http:// upload paths that suggest transmission of user data in the clear.
    _UPLOAD_PATH_RE = re.compile(r"(?i)(profilepic|upload|avatar|contact|photo)")

    # Local endpoints that are not real cleartext exposure (mirror sibling M3 logic).
    _LOCAL_HOSTS = ("localhost", "127.0.0.1", "10.0.2.2")

    def __init__(self):
        """Initialize the post-processor."""
        self.logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------ public API

    def process(
        self,
        findings: list[SecurityFinding],
        analysis_results: dict[str, Any],
        config: dict[str, Any] | None,
    ) -> list[SecurityFinding]:
        """Run the post-processing pipeline.

        Args:
            findings: All findings collected from the assessment loop.
            analysis_results: Combined analysis results (used for context scanning).
            config: The ``security.context_analysis`` config block.

        Returns:
            The processed findings. When disabled, the input list is returned
            unchanged (byte-identical) for backward compatibility.
        """
        if not config or not config.get("enabled", False):
            return findings

        analysis_results = analysis_results or {}
        fp_cfg = config.get("false_positive", {}) or {}
        dedup_cfg = config.get("dedup", {}) or {}
        allow_downgrade = bool(config.get("allow_severity_downgrade", True))
        max_context_strings = config.get("max_context_strings", CodeContextAnalyzer.DEFAULT_MAX_CONTEXT_STRINGS)

        # Stage 1: confidence / false-positive pass.
        self._apply_confidence_pass(findings, analysis_results, fp_cfg, allow_downgrade, max_context_strings)

        # Stage 2: cross-finding cleartext correlation (append-only, runs before
        # dedup so any correlated finding is subject to the same merge rules).
        findings = self._apply_cleartext_correlation(findings, analysis_results)

        # Stage 3: dedup.
        if dedup_cfg.get("enabled", True):
            findings = self._dedup(
                findings, merge_across_categories=bool(dedup_cfg.get("merge_across_categories", True))
            )

        return findings

    # -------------------------------------------------------- stage 1: confidence

    def _apply_confidence_pass(
        self,
        findings: list[SecurityFinding],
        analysis_results: dict[str, Any],
        fp_cfg: dict[str, Any],
        allow_downgrade: bool,
        max_context_strings: int | None,
    ) -> None:
        """Fold false-positive probability into confidence for secret findings."""
        fp_filter = FalsePositiveFilter()
        analyzer = CodeContextAnalyzer(max_context_strings=max_context_strings)

        # PERF GUARD: build the corpus reference ONCE and reuse it across findings.
        string_analysis = analysis_results.get("string_analysis", {}) or {}

        high_thr = float(fp_cfg.get("downgrade_high_threshold", 0.8))
        med_thr = float(fp_cfg.get("downgrade_medium_threshold", 0.5))

        for finding in findings:
            if not self._is_secret_finding(finding):
                continue

            fp_dict = self._finding_to_fp_dict(finding)
            value = fp_dict.get("value") or ""
            if not value:
                continue

            code_context = self._build_code_context(finding, fp_dict, analyzer, string_analysis, analysis_results)

            contextual = fp_filter.filter_finding(fp_dict, code_context)
            fp_probability = contextual.context_metadata.false_positive_probability

            base_confidence = (
                finding.confidence
                if finding.confidence is not None
                else self.SEVERITY_DEFAULT_CONFIDENCE.get(finding.severity, 0.3)
            )
            final_confidence = round(base_confidence * (1.0 - fp_probability), 6)
            finding.confidence = final_confidence

            # Record FP metadata WITHOUT mutating severity (scorer uses
            # severity x confidence; confidence already carries the FP signal).
            finding.additional_data = dict(finding.additional_data or {})
            finding.additional_data["fp_probability"] = round(fp_probability, 6)
            if allow_downgrade:
                tier = self._display_tier(finding.severity, fp_probability, high_thr, med_thr)
                if tier is not None:
                    finding.additional_data["adjusted_severity"] = tier
                    finding.additional_data["tier"] = tier

    def _build_code_context(
        self,
        finding: SecurityFinding,
        fp_dict: dict[str, Any],
        analyzer: CodeContextAnalyzer,
        string_analysis: dict[str, Any],
        analysis_results: dict[str, Any],
    ) -> CodeContext:
        """Build a code context for the finding.

        PERF GUARD: findings that already carry a precise ``file_location`` are
        short-circuited — we derive location context from the path only and SKIP
        the all-strings corpus scan entirely.
        """
        if finding.file_location and finding.file_location.uri:
            # Skip the corpus scan; pass empty analysis_results so
            # analyze_string_context does not iterate the string corpus.
            return analyzer.analyze_string_context(fp_dict, {})

        # No precise location: scan the (capped) corpus for surrounding context.
        scan_results = dict(analysis_results)
        scan_results["string_analysis"] = string_analysis
        return analyzer.analyze_string_context(fp_dict, scan_results)

    def _is_secret_finding(self, finding: SecurityFinding) -> bool:
        """Return True if the finding represents a secret / sensitive-data hit.

        Non-secret findings lack a ``value``/``type`` and are skipped so the pass
        never fabricates a value for them.
        """
        ad = finding.additional_data or {}
        if "value" in ad or "type" in ad:
            return True
        return finding.category in self.SECRET_CATEGORIES

    def _finding_to_fp_dict(self, finding: SecurityFinding) -> dict[str, Any]:
        """Adapt a SecurityFinding into the dict shape the FP filter/analyzer expect.

        Pulls the primary evidence value and file location. Falls back to the first
        evidence entry when no explicit ``value`` is present in ``additional_data``.
        """
        ad = finding.additional_data or {}
        value = ad.get("value")
        if not value and finding.evidence:
            value = str(finding.evidence[0])

        finding_type = ad.get("type") or finding.title or ""
        location = ad.get("location", "")
        line_number = ad.get("line_number")
        file_path = ad.get("file_path")

        if finding.file_location and finding.file_location.uri:
            file_path = finding.file_location.uri
            if finding.file_location.start_line is not None:
                line_number = finding.file_location.start_line

        return {
            "value": value or "",
            "type": finding_type,
            "location": location,
            "file_path": file_path,
            "line_number": line_number,
        }

    @staticmethod
    def _display_tier(
        severity: AnalysisSeverity, fp_probability: float, high_thr: float, med_thr: float
    ) -> str | None:
        """Compute a DISPLAY-only severity tier from the false-positive probability.

        Returns None when no downgrade applies.
        """
        if fp_probability > high_thr:
            return "LOW"
        if fp_probability > med_thr:
            return "MEDIUM"
        return None

    # ----------------------------------------------- stage 2: cleartext correlation

    def _apply_cleartext_correlation(
        self, findings: list[SecurityFinding], analysis_results: dict[str, Any]
    ) -> list[SecurityFinding]:
        """Correlate the manifest cleartext-traffic fact with sibling findings.

        Fires only when ``usesCleartextTraffic`` is a *known* True. Joins a cleartext
        http upload endpoint with a PII finding (statically decidable -> CONFIRMED),
        or a cleartext channel with a WebView bridge finding (RCE precondition needs
        runtime confirmation -> NEEDS_DYNAMIC). Appends AT MOST ONE finding and is
        idempotent by title. Missing/partial inputs no-op safely.
        """
        try:
            facts = get_manifest_facts(analysis_results)
            if facts.get("uses_cleartext_traffic") is not True:
                return findings

            cleartext_uploads = self._cleartext_upload_urls(analysis_results)
            pii_finding = next((f for f in findings if self._is_pii_finding(f)), None)
            bridge_finding = next((f for f in findings if self._is_webview_bridge_finding(f)), None)

            correlated = self._correlated_finding(cleartext_uploads, pii_finding, bridge_finding)
            if correlated is None:
                return findings

            # Idempotency: never emit a second correlated finding of the same title.
            if any((f.title or "") == correlated.title for f in findings):
                return findings

            findings.append(correlated)
        except Exception:
            self.logger.debug("cleartext correlation stage skipped", exc_info=True)
        return findings

    def _correlated_finding(
        self,
        cleartext_uploads: list[str],
        pii_finding: SecurityFinding | None,
        bridge_finding: SecurityFinding | None,
    ) -> SecurityFinding | None:
        """Select and build the single correlated finding for the current signals."""
        if cleartext_uploads and pii_finding is not None:
            evidence = [
                *cleartext_uploads,
                "usesCleartextTraffic=true",
                f"Correlated with PII finding: {pii_finding.title}",
            ]
            return self._build_correlated_finding(
                title="Cleartext PII Transmission",
                severity=AnalysisSeverity.HIGH,
                confidence=0.7,
                verification_status=VerificationStatus.CONFIRMED,
                description=(
                    "The app declares usesCleartextTraffic=true and uploads user data "
                    "to an http:// endpoint while personal data exposure was detected, "
                    "so PII is transmitted in the clear."
                ),
                evidence=evidence,
                recommendations=[
                    "Disable cleartext traffic and upload user data over HTTPS only.",
                    "Restrict any remaining cleartext endpoints via a network security config.",
                ],
            )

        if bridge_finding is not None:
            evidence = [
                "usesCleartextTraffic=true",
                f"Correlated with WebView bridge finding: {bridge_finding.title}",
            ]
            return self._build_correlated_finding(
                title="Cleartext Content Into WebView",
                severity=AnalysisSeverity.HIGH,
                confidence=0.6,
                verification_status=VerificationStatus.NEEDS_DYNAMIC,
                description=(
                    "The app declares usesCleartextTraffic=true and exposes a WebView "
                    "JavaScript bridge; cleartext content loaded into that WebView could "
                    "reach the bridge, so the RCE precondition needs runtime confirmation."
                ),
                evidence=evidence,
                recommendations=[
                    "Disable cleartext traffic so WebView content cannot be MITM-injected.",
                    "Restrict the JavaScript bridge surface and validate all loaded URLs.",
                ],
            )

        if cleartext_uploads:
            return self._build_correlated_finding(
                title="Cleartext Upload Endpoint",
                severity=AnalysisSeverity.MEDIUM,
                confidence=0.6,
                verification_status=VerificationStatus.CONFIRMED,
                description=(
                    "The app declares usesCleartextTraffic=true and uploads user data to "
                    "an http:// endpoint, exposing that data on the network."
                ),
                evidence=[*cleartext_uploads, "usesCleartextTraffic=true"],
                recommendations=["Upload user data over HTTPS and disable cleartext traffic."],
            )

        return None

    def _build_correlated_finding(
        self,
        *,
        title: str,
        severity: AnalysisSeverity,
        confidence: float,
        verification_status: VerificationStatus,
        description: str,
        evidence: list[str],
        recommendations: list[str],
    ) -> SecurityFinding:
        """Construct a correlated A05 finding with the correlation marker set."""
        return SecurityFinding(
            category=self._MISCONFIG_CATEGORY,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendations=recommendations,
            confidence=confidence,
            verification_status=verification_status,
            additional_data={"correlated": True},
        )

    def _cleartext_upload_urls(self, analysis_results: dict[str, Any]) -> list[str]:
        """Return first-party http:// URLs whose path suggests a user-data upload."""
        string_results = analysis_results.get("string_analysis", {}) or {}
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        if not isinstance(string_data, dict):
            return []
        urls = string_data.get("urls") or []
        if not isinstance(urls, list):
            return []
        return [
            url
            for url in urls
            if isinstance(url, str)
            and url.startswith("http://")
            and not any(host in url for host in self._LOCAL_HOSTS)
            and self._UPLOAD_PATH_RE.search(url)
        ]

    def _is_pii_finding(self, finding: SecurityFinding) -> bool:
        """Return True for PRIVACY:2024 Personal Data Exposure findings."""
        return (finding.category or "") == self._PII_CATEGORY

    def _is_webview_bridge_finding(self, finding: SecurityFinding) -> bool:
        """Return True for an OWASP Mobile bridge / WebView finding.

        Matches defensively by attribute since assessment ordering is not guaranteed:
        the dedicated bridge finding (title contains "Bridge") and the M1 "Improper
        Platform Usage" finding that lists WebView APIs in its evidence both qualify.
        """
        if "OWASP Mobile Top 10" not in (finding.category or ""):
            return False
        title = finding.title or ""
        if "Bridge" in title:
            return True
        haystack = " ".join([title, *(finding.evidence or [])])
        return "WebView" in haystack

    # ------------------------------------------------------------- stage 3: dedup

    def _dedup(
        self, findings: list[SecurityFinding], merge_across_categories: bool
    ) -> list[SecurityFinding]:
        """Merge findings that describe the same underlying issue.

        Grouping rules:
        * Aggregate count-bucket secret findings (titles carrying a count, e.g.
          "173 Potential Secrets Found") only dedup WITHIN their own category — they
          are never cross-merged, since each category's bucket counts something
          different.
        * All other findings merge across categories when ``merge_across_categories``
          is set, otherwise only within their own category.
        """
        groups: dict[tuple, list[SecurityFinding]] = {}
        order: list[tuple] = []

        for finding in findings:
            key = self._group_key(finding, merge_across_categories)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(finding)

        result: list[SecurityFinding] = []
        for key in order:
            group = groups[key]
            if len(group) == 1:
                result.append(group[0])
            else:
                result.append(self._merge_group(group))
        return result

    def _group_key(self, finding: SecurityFinding, merge_across_categories: bool) -> tuple:
        """Compute the dedup grouping key for a finding."""
        if self._is_count_bucket(finding):
            return ("bucket", finding.category, finding.dedup_key())
        if merge_across_categories:
            return ("merged", finding.dedup_key())
        return ("category", finding.category, finding.dedup_key())

    @staticmethod
    def _is_count_bucket(finding: SecurityFinding) -> bool:
        """Detect aggregate count-bucket findings (a count followed by a word)."""
        return bool(re.search(r"\b\d[\d,]*\s+\S", finding.title or ""))

    def _merge_group(self, group: list[SecurityFinding]) -> SecurityFinding:
        """Merge a group of duplicate findings into a single strongest finding.

        Keeps max severity and max confidence and unions the list fields. The base
        finding (strongest severity, then highest confidence) is mutated in place and
        records the members it absorbed in ``additional_data['merged_from']``. This
        can only ever raise (never lower) the finding's contribution to the score.
        """
        base = max(group, key=lambda f: (self._SEVERITY_RANK.get(f.severity, 0), f.confidence or 0.0))

        max_severity = max(group, key=lambda f: self._SEVERITY_RANK.get(f.severity, 0)).severity
        confidences = [f.confidence for f in group if f.confidence is not None]
        max_confidence = max(confidences) if confidences else None

        base.severity = max_severity
        if max_confidence is not None:
            base.confidence = max_confidence
        base.evidence = self._union(f.evidence for f in group)
        base.recommendations = self._union(f.recommendations for f in group)
        base.cve_references = self._union(f.cve_references for f in group)

        base.additional_data = dict(base.additional_data or {})
        base.additional_data["merged_from"] = [
            {"category": f.category, "title": f.title, "severity": f.severity.value} for f in group
        ]
        return base

    @staticmethod
    def _union(list_of_lists) -> list:
        """Order-preserving union of several lists, dropping duplicates."""
        seen = set()
        merged: list = []
        for sub in list_of_lists:
            for item in sub or []:
                marker = item if isinstance(item, (str, int, float, bool)) else repr(item)
                if marker not in seen:
                    seen.add(marker)
                    merged.append(item)
        return merged
