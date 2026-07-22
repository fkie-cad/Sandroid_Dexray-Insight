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

2. Cross-assessment dedup: findings that describe the same underlying issue
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
from .context_analysis.code_context_analyzer import CodeContextAnalyzer
from .context_analysis.false_positive_filter import FalsePositiveFilter
from .context_analysis.models.context_models import CodeContext


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

        # Stage 2: dedup.
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

    # ------------------------------------------------------------- stage 2: dedup

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
