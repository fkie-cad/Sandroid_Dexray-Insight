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

"""Markdown security-report generation.

:class:`MarkdownSecurityReporter` turns a completed analysis (a
``FullAnalysisResults`` object, or the plain dicts it serializes to) into a
self-contained, analyst-facing Markdown report — the same triage story the
terminal summary tells, but persisted and shareable.

The reporter is deliberately tolerant of input shape: it reads via safe getters
so it works on live result objects and on cache-reconstructed dicts alike, and it
never raises on missing sections (they are simply omitted). All ranking/tiering
is delegated to :mod:`risk_ranking` so the Markdown and terminal outputs agree.
"""

from __future__ import annotations

from typing import Any

from . import risk_ranking


class MarkdownSecurityReporter:
    """Render a security-focused Markdown report from analysis results."""

    def __init__(self, top_n: int = 5, config: Any = None):
        """Initialize the reporter.

        Args:
            top_n: Number of findings to surface in the Top Risks section.
            config: Optional configuration (Configuration object or dict) used to
                resolve tier thresholds. Defaults keep behaviour sensible when absent.
        """
        self.top_n = top_n
        self.config = config

    # ------------------------------------------------------------------ #
    # Input normalization
    # ------------------------------------------------------------------ #
    @staticmethod
    def _apk_overview_dict(results: Any) -> dict[str, Any]:
        """Return the apk_overview section as a dict, from an object or a dict."""
        if isinstance(results, dict):
            overview = results.get("apk_overview", {}) or {}
            return overview if isinstance(overview, dict) else {}
        overview = getattr(results, "apk_overview", None)
        if overview is None:
            return {}
        if hasattr(overview, "to_dict"):
            try:
                return overview.to_dict() or {}
            except Exception:
                return {}
        return overview if isinstance(overview, dict) else {}

    @staticmethod
    def _security_dict(results: Any) -> dict[str, Any]:
        """Return the security assessment section as a dict."""
        if isinstance(results, dict):
            security = results.get("security_assessment", {}) or {}
            return security if isinstance(security, dict) else {}
        security = getattr(results, "security_assessment", None)
        return security if isinstance(security, dict) else {}

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def generate(self, results: Any) -> str:
        """Generate the full Markdown report string for ``results``."""
        overview = self._apk_overview_dict(results)
        security = self._security_dict(results)
        findings = security.get("findings", []) or []

        sections = [
            self._render_header(overview),
            self._render_executive_summary(security, findings),
            self._render_top_risks(findings),
            self._render_tier_tables(findings),
            self._render_full_findings(findings),
            self._render_informational_appendix(findings),
            self._render_metadata(security, overview),
        ]
        return "\n\n".join(s for s in sections if s).strip() + "\n"

    # ------------------------------------------------------------------ #
    # Sections
    # ------------------------------------------------------------------ #
    def _render_header(self, overview: dict[str, Any]) -> str:
        general = overview.get("general_info", {}) or {}
        app_name = general.get("app_name") or general.get("package_name") or "Unknown Application"

        lines = [f"# Security Report: {app_name}", ""]
        rows = [
            ("Package", general.get("package_name")),
            ("App name", general.get("app_name")),
            ("MD5", general.get("md5")),
            ("SHA1", general.get("sha1")),
            ("SHA256", general.get("sha256")),
            ("Target SDK", general.get("target_sdk")),
            ("Min SDK", general.get("min_sdk")),
            ("File size", general.get("file_size")),
        ]
        rows = [(label, value) for label, value in rows if value]
        if rows:
            lines.append("| Field | Value |")
            lines.append("| --- | --- |")
            for label, value in rows:
                lines.append(f"| {label} | `{value}` |")
        return "\n".join(lines)

    def _render_executive_summary(self, security: dict[str, Any], findings: list) -> str:
        if not security:
            return "## Executive Summary\n\n_No security assessment was performed._"

        risk_score = security.get("overall_risk_score", 0) or 0
        risk_confirmed = security.get("risk_score_confirmed")
        total = security.get("total_findings", len(findings))

        lines = ["## Executive Summary", ""]
        score_line = f"- **Risk score (triage aid):** {risk_score:.1f}/100"
        if risk_confirmed is not None:
            score_line += f"  ·  **confirmed-only:** {risk_confirmed:.1f}/100"
        lines.append(score_line)
        lines.append(
            "  - _The score pair is a triage aid, not a verdict: the first value weights "
            "all findings by confidence; the second counts only high-confidence findings._"
        )
        lines.append(f"- **Total findings:** {total}")

        distribution = security.get("findings_by_severity", {}) or {}
        if distribution:
            parts = []
            for severity in ("critical", "high", "medium", "low", "info"):
                count = distribution.get(severity, 0)
                if count:
                    parts.append(f"{severity.title()}: {count}")
            for severity, count in distribution.items():
                if severity not in ("critical", "high", "medium", "low", "info") and count:
                    parts.append(f"{str(severity).title()}: {count}")
            if parts:
                lines.append(f"- **Severity distribution:** {', '.join(parts)}")

        lines.append("")
        lines.append(f"> {self._verdict(security, findings)}")
        return "\n".join(lines)

    def _verdict(self, security: dict[str, Any], findings: list) -> str:
        """One-line plain-language verdict driven by the tiered findings."""
        tiers = risk_ranking.tier_findings(findings, self.config)
        confirmed = len(tiers["confirmed"])
        review = len(tiers["needs_review"])
        if confirmed:
            return (
                f"{confirmed} high-confidence finding(s) warrant immediate attention; "
                f"{review} more merit manual review."
            )
        if review:
            return f"No confirmed high-severity findings; {review} finding(s) warrant manual review."
        return "No confirmed or review-tier findings surfaced by this assessment."

    def _render_top_risks(self, findings: list) -> str:
        top = risk_ranking.top_risks(findings, self.top_n)
        if not top:
            return ""

        lines = [f"## Top Risks (highest {len(top)} by severity × confidence)", ""]
        for index, finding in enumerate(top, start=1):
            severity = risk_ranking.severity_str(finding).upper()
            confidence = risk_ranking.confidence_of(finding)
            title = risk_ranking.title_of(finding) or "Security Finding"
            category = str(risk_ranking.get_attr(finding, "category", "Unknown"))
            lines.append(f"### {index}. [{severity} · conf {confidence:.2f}] {title}")
            lines.append(f"- **Category:** {category}")
            evidence = self._first_evidence(finding)
            if evidence:
                lines.append(f"- **Evidence:** `{evidence}`")
            location = self._location_str(finding)
            if location:
                lines.append(f"- **Location:** `{location}`")
            lines.append(f"- **Why it matters:** {risk_ranking.hint_for(finding)}")
            lines.append("")
        return "\n".join(lines).rstrip()

    def _render_tier_tables(self, findings: list) -> str:
        tiers = risk_ranking.tier_findings(findings, self.config)
        blocks = []

        confirmed = tiers["confirmed"]
        blocks.append(self._render_finding_table("Confirmed", confirmed,
                                                 "High-confidence critical/high findings — act on these first."))

        review = tiers["needs_review"]
        blocks.append(self._render_finding_table("Needs Manual Review", review,
                                                 "Medium-confidence or medium-severity findings worth a human look."))

        return "\n\n".join(b for b in blocks if b)

    def _render_finding_table(self, heading: str, findings: list, subtitle: str) -> str:
        lines = [f"## {heading}", "", f"_{subtitle}_", ""]
        if not findings:
            lines.append("_None._")
            return "\n".join(lines)

        lines.append("| Severity | Conf | Category | Title | Evidence |")
        lines.append("| --- | --- | --- | --- | --- |")
        for finding in findings:
            severity = risk_ranking.severity_str(finding).upper()
            confidence = risk_ranking.confidence_of(finding)
            category = self._escape(str(risk_ranking.get_attr(finding, "category", "Unknown")))
            title = self._escape(risk_ranking.title_of(finding) or "Security Finding")
            evidence = self._escape(self._first_evidence(finding) or "")
            lines.append(f"| {severity} | {confidence:.2f} | {category} | {title} | {evidence} |")
        return "\n".join(lines)

    def _render_full_findings(self, findings: list) -> str:
        if not findings:
            return ""
        ranked = risk_ranking.rank_findings(findings)
        lines = [f"## All Findings ({len(ranked)})", "", "| # | Severity | Conf | Category | Title |",
                 "| --- | --- | --- | --- | --- |"]
        for index, finding in enumerate(ranked, start=1):
            severity = risk_ranking.severity_str(finding).upper()
            confidence = risk_ranking.confidence_of(finding)
            category = self._escape(str(risk_ranking.get_attr(finding, "category", "Unknown")))
            title = self._escape(risk_ranking.title_of(finding) or "Security Finding")
            lines.append(f"| {index} | {severity} | {confidence:.2f} | {category} | {title} |")
        return "\n".join(lines)

    def _render_informational_appendix(self, findings: list) -> str:
        tiers = risk_ranking.tier_findings(findings, self.config)
        info = tiers["informational"]
        if not info:
            return ""
        lines = [f"## Suppressed / Informational ({len(info)})", "",
                 "_Low-confidence or informational findings, retained for completeness._", "",
                 "| Severity | Conf | Category | Title |", "| --- | --- | --- | --- |"]
        for finding in info:
            severity = risk_ranking.severity_str(finding).upper()
            confidence = risk_ranking.confidence_of(finding)
            category = self._escape(str(risk_ranking.get_attr(finding, "category", "Unknown")))
            title = self._escape(risk_ranking.title_of(finding) or "Security Finding")
            lines.append(f"| {severity} | {confidence:.2f} | {category} | {title} |")
        return "\n".join(lines)

    def _render_metadata(self, security: dict[str, Any], overview: dict[str, Any]) -> str:
        lines = ["## Scan Metadata", ""]
        version = security.get("risk_score_version")
        if version is not None:
            lines.append(f"- **Risk score version:** v{version}")
        categories = security.get("owasp_categories_affected", []) or []
        if categories:
            lines.append(f"- **OWASP categories affected:** {', '.join(str(c) for c in categories)}")
        summary = security.get("summary", {}) or {}
        run = summary.get("total_assessments_run")
        if run is not None:
            lines.append(f"- **Assessments run:** {run}")
        failed = summary.get("total_assessments_failed")
        if failed:
            lines.append(f"- **Assessments failed:** {failed}")
        lines.append("")
        lines.append("_Generated by Dexray Insight._")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _first_evidence(finding: Any) -> str:
        evidence = risk_ranking.get_attr(finding, "evidence", []) or []
        if isinstance(evidence, (list, tuple)) and evidence:
            return str(evidence[0])
        if isinstance(evidence, str):
            return evidence
        return ""

    @staticmethod
    def _location_str(finding: Any) -> str:
        location = risk_ranking.get_attr(finding, "file_location", None) or risk_ranking.get_attr(
            finding, "fileLocation", None
        )
        if not location:
            return ""
        if isinstance(location, dict):
            uri = location.get("uri", "")
            line = location.get("start_line") or location.get("startLine")
            return f"{uri}:{line}" if line else str(uri)
        uri = getattr(location, "uri", "")
        line = getattr(location, "start_line", None)
        return f"{uri}:{line}" if line else str(uri)

    @staticmethod
    def _escape(text: str) -> str:
        """Escape pipe characters and collapse newlines for Markdown table cells."""
        return text.replace("|", "\\|").replace("\n", " ").strip()
