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

"""Security Engine.

This module implements the security analysis engine that coordinates OWASP security assessments.
It manages the execution of multiple security assessment modules for comprehensive vulnerability detection.
"""

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

import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .base_classes import AnalysisContext
from .base_classes import AnalysisSeverity
from .base_classes import BaseSecurityAssessment
from .base_classes import SecurityFinding
from .base_classes import registry
from .configuration import Configuration


@dataclass
class SecurityAssessmentResults:
    """Results from OWASP Top 10 security assessment."""

    findings: list[SecurityFinding]
    summary: dict[str, Any]
    overall_risk_score: float
    owasp_categories_affected: list[str]
    # Evidence-weighted scoring metadata (additive; default None keeps older constructors
    # and consumers working). Populated by the engine when the v2 scorer runs.
    risk_score_version: int = 1
    overall_risk_score_raw: float | None = None
    risk_score_confirmed: float | None = None
    risk_score_legacy: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert security results to dictionary format."""
        return {
            "findings": [
                finding.to_dict() for finding in self.findings
            ],  # Use to_dict() method for proper serialization
            "summary": self.summary,
            "overall_risk_score": self.overall_risk_score,
            "owasp_categories_affected": self.owasp_categories_affected,
            "total_findings": len(self.findings),
            "findings_by_severity": self._group_by_severity(),
            # Additive scoring discriminators so downstream consumers can migrate.
            "risk_score_version": self.risk_score_version,
            "overall_risk_score_raw": self.overall_risk_score_raw,
            "risk_score_confirmed": self.risk_score_confirmed,
            "risk_score_legacy": self.risk_score_legacy,
        }

    def to_json(self) -> str:
        """Convert security results to JSON string for file output."""
        import json

        return json.dumps(self.to_dict(), indent=4, default=str)

    def _group_by_severity(self) -> dict[str, int]:
        """Group findings by severity level."""
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
        return dict(severity_counts)


class SecurityAssessmentEngine:
    """Engine for coordinating OWASP Top 10 security assessments."""

    def __init__(self, config: Configuration):
        """Initialize the security assessment engine with configuration.

        Args:
            config: Configuration instance containing security settings.
        """
        self.config = config
        self.security_config = config.get_security_config()
        self.logger = logging.getLogger(__name__)
        self.assessments = self._load_assessments()

        # Evidence-weighted scoring config (v2 is the default; see MIGRATION notes).
        scoring_cfg = self.security_config.get("risk_scoring", {}) or {}
        self.scoring_version = int(scoring_cfg.get("version", 2))
        self.scoring_denominator = float(scoring_cfg.get("denominator", 100.0))
        self.confirmed_confidence_threshold = float(scoring_cfg.get("confirmed_threshold", 0.7))
        # A single high-confidence CRITICAL must keep the app in the critical band,
        # regardless of how few findings there are.
        self.critical_floor = float(scoring_cfg.get("critical_floor", 75.0))
        self.severity_default_confidence = {
            AnalysisSeverity.CRITICAL: 0.8,
            AnalysisSeverity.HIGH: 0.5,
            AnalysisSeverity.MEDIUM: 0.4,
            AnalysisSeverity.LOW: 0.3,
        }
        cfg_defaults = scoring_cfg.get("severity_defaults", {}) or {}
        for sev_name, value in cfg_defaults.items():
            try:
                self.severity_default_confidence[AnalysisSeverity(sev_name)] = float(value)
            except (ValueError, TypeError):
                self.logger.debug(f"Ignoring invalid severity default confidence: {sev_name}={value}")

    def assess(
        self, analysis_results: dict[str, Any], context: AnalysisContext | None = None
    ) -> SecurityAssessmentResults:
        """Perform comprehensive security assessment using OWASP Top 10 with file location tracking.

        Args:
            analysis_results: Combined results from all analysis modules.
            context: Analysis context for file location creation (optional for backward compatibility).

        Returns:
            SecurityAssessmentResults with all security findings including precise file locations.
        """
        all_findings = []
        assessment_summary = {}

        self.logger.info("Starting OWASP Top 10 security assessment")

        for assessment_name, assessment in self.assessments.items():
            if not assessment.is_enabled():
                self.logger.info(f"Assessment {assessment_name} is disabled, skipping")
                continue

            try:
                self.logger.info(f"Running {assessment_name} assessment")
                findings = assessment.assess(analysis_results, context)

                all_findings.extend(findings)
                assessment_summary[assessment_name] = {
                    "findings_count": len(findings),
                    "owasp_category": assessment.get_owasp_category(),
                    "status": "completed",
                }

                self.logger.info(f"{assessment_name} completed with {len(findings)} findings")

                # Print findings to terminal with details including file locations
                if findings:
                    for finding in findings:
                        print(f"[+] {finding.category} - {finding.title}")
                        if finding.file_location:
                            print(f"    📁 File: {finding.file_location.uri}")
                            if finding.file_location.start_line:
                                print(f"    📍 Line: {finding.file_location.start_line}")
                            if finding.file_location.start_offset is not None:
                                print(f"    📍 Offset: 0x{finding.file_location.start_offset:x}")
                        if finding.description:
                            # Truncate description for terminal output
                            desc = (
                                finding.description[:100] + "..."
                                if len(finding.description) > 100
                                else finding.description
                            )
                            print(f"    📄 Description: {desc}")

            except Exception as e:
                self.logger.error(f"Assessment {assessment_name} failed: {str(e)}")
                assessment_summary[assessment_name] = {
                    "findings_count": 0,
                    "owasp_category": assessment.get_owasp_category(),
                    "status": "failed",
                    "error": str(e),
                }

        # PR-7: context-analysis / false-positive post-processing pass. Runs AFTER the
        # assessment loop but BEFORE confidence backfill and scoring. Gated by config;
        # a no-op (returns findings unchanged) when disabled.
        all_findings = self._run_post_processing(all_findings, analysis_results)

        # Backfill a severity-derived confidence for any finding an assessment did not
        # score, so the scorer and report ranking always have a value (never None → 0).
        self._backfill_confidence(all_findings)

        # Calculate risk scores. v2 (evidence-weighted) is the default; v1 (legacy
        # count-weighted) is always computed too and emitted as risk_score_legacy.
        legacy_score = self._calculate_risk_score_v1(all_findings)
        if self.scoring_version == 1:
            overall_risk_score = legacy_score
            raw_score = None
            confirmed_score = None
        else:
            overall_risk_score, raw_score = self._calculate_risk_score_v2(all_findings)
            confirmed_score, _ = self._calculate_risk_score_v2(
                [f for f in all_findings if (f.confidence or 0.0) >= self.confirmed_confidence_threshold]
            )
        owasp_categories = list({finding.category for finding in all_findings})

        summary = {
            "total_assessments_run": len([a for a in assessment_summary.values() if a["status"] == "completed"]),
            "total_assessments_failed": len([a for a in assessment_summary.values() if a["status"] == "failed"]),
            "assessments": assessment_summary,
            "risk_distribution": self._calculate_risk_distribution(all_findings),
        }

        results = SecurityAssessmentResults(
            findings=all_findings,
            summary=summary,
            overall_risk_score=overall_risk_score,
            owasp_categories_affected=owasp_categories,
            risk_score_version=self.scoring_version,
            overall_risk_score_raw=raw_score,
            risk_score_confirmed=confirmed_score,
            risk_score_legacy=legacy_score,
        )

        self.logger.info(
            f"Security assessment completed with {len(all_findings)} total findings, risk score: {overall_risk_score:.2f}"
        )

        # Print summary to terminal
        if all_findings:
            print("\n[+] Security Assessment Summary:")
            print(f"    Total findings: {len(all_findings)}")
            print(f"    Risk score: {overall_risk_score:.2f}")
            print(f"    OWASP categories affected: {', '.join(owasp_categories)}")
        else:
            print("\n[+] Security Assessment completed with no findings")

        return results

    def _load_assessments(self) -> dict[str, BaseSecurityAssessment]:
        """Load and initialize all enabled security assessments."""
        assessments = {}
        assessment_configs = self.security_config.get("assessments", {})

        # Get all registered assessments
        for assessment_name in registry.list_assessments():
            assessment_class = registry.get_assessment(assessment_name)
            if not assessment_class:
                continue

            assessment_config = assessment_configs.get(assessment_name, {})

            # Create assessment instance
            try:
                # For CVE assessment, pass the full security config instead of just assessment config
                if assessment_name == "cve_scanning":
                    assessment = assessment_class(self.security_config)
                else:
                    assessment = assessment_class(assessment_config)
                assessments[assessment_name] = assessment
                self.logger.info(f"Loaded assessment: {assessment_name} ({assessment.get_owasp_category()})")
            except Exception as e:
                self.logger.error(f"Failed to load assessment {assessment_name}: {str(e)}")

        return assessments

    # Severity weights shared by both scorers.
    _SEVERITY_WEIGHTS = {
        AnalysisSeverity.CRITICAL: 10,
        AnalysisSeverity.HIGH: 7,
        AnalysisSeverity.MEDIUM: 4,
        AnalysisSeverity.LOW: 1,
    }

    def _calculate_risk_score(self, findings: list[SecurityFinding]) -> float:
        """Dispatch to the configured scorer (kept for backward-compatible callers).

        Returns the v1 legacy score when version==1, otherwise the v2 normalized score.
        """
        if self.scoring_version == 1:
            return self._calculate_risk_score_v1(findings)
        normalized, _ = self._calculate_risk_score_v2(findings)
        return normalized

    def _run_post_processing(
        self, findings: list[SecurityFinding], analysis_results: dict[str, Any]
    ) -> list[SecurityFinding]:
        """Apply the PR-7 finding post-processing pass (FP confidence + dedup).

        Gated by ``security.context_analysis.enabled``. When disabled (or on any
        error) the original findings are returned unchanged so scoring behaviour is
        never accidentally altered.
        """
        context_config = self.config.get_context_analysis_config()
        if not context_config or not context_config.get("enabled", False):
            return findings

        try:
            # Imported lazily to avoid importing the security context-analysis stack
            # (and its heavier dependencies) when post-processing is disabled.
            from ..security.finding_postprocessor import FindingPostProcessor

            processor = FindingPostProcessor()
            return processor.process(findings, analysis_results, context_config)
        except Exception as e:
            self.logger.error(f"Finding post-processing failed, using unprocessed findings: {str(e)}")
            return findings

    def _backfill_confidence(self, findings: list[SecurityFinding]) -> None:
        """Assign a severity-derived default confidence to any unscored finding.

        Producers (assessments) may set finding.confidence explicitly; those are left
        untouched. This guarantees the scorer and report ranking always see a value.
        """
        for finding in findings:
            if finding.confidence is None:
                finding.confidence = self.severity_default_confidence.get(finding.severity, 0.3)

    def _calculate_risk_score_v1(self, findings: list[SecurityFinding]) -> float:
        """Legacy count-weighted risk score (Critical=10/High=7/Medium=4/Low=1, /500).

        Preserved verbatim so consumers can pin the pre-2.0 score via risk_scoring.version=1
        or read risk_score_legacy.
        """
        if not findings:
            return 0.0

        total_score = sum(self._SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)
        # Normalize to 0-100 scale (assuming max of 50 critical findings as worst case)
        max_possible_score = 50 * self._SEVERITY_WEIGHTS[AnalysisSeverity.CRITICAL]
        normalized_score = min(100.0, (total_score / max_possible_score) * 100)
        return round(normalized_score, 2)

    def _calculate_risk_score_v2(self, findings: list[SecurityFinding]) -> tuple[float, float]:
        """Evidence-weighted risk score: Σ (severity_weight × confidence).

        Confidence (0-1) is the single likelihood axis — it already folds in any
        false-positive probability applied by the post-processor. Severity is the stable
        impact axis. There is no count_factor: severity × confidence already dampens
        count-inflated low-confidence findings, and a per-finding cap avoids the six-figure
        "174k leakage" distortion.

        A single high-confidence CRITICAL floors the normalized score into the critical
        band so a real critical is never diluted by aggregate arithmetic.

        Returns (normalized_score 0-100, raw_weighted_sum).
        """
        if not findings:
            return 0.0, 0.0

        raw = 0.0
        for finding in findings:
            weight = self._SEVERITY_WEIGHTS.get(finding.severity, 0)
            confidence = finding.confidence if finding.confidence is not None else 0.3
            raw += weight * confidence

        denominator = self.scoring_denominator if self.scoring_denominator > 0 else 100.0
        normalized = min(100.0, (raw / denominator) * 100.0)

        # Single high-confidence CRITICAL floor.
        has_confirmed_critical = any(
            f.severity == AnalysisSeverity.CRITICAL and (f.confidence or 0.0) >= self.confirmed_confidence_threshold
            for f in findings
        )
        if has_confirmed_critical:
            normalized = max(normalized, self.critical_floor)

        return round(normalized, 2), round(raw, 2)

    def _calculate_risk_distribution(self, findings: list[SecurityFinding]) -> dict[str, dict[str, int]]:
        """Calculate risk distribution by severity and OWASP category."""
        distribution = {
            "by_severity": defaultdict(int),
            "by_category": defaultdict(int),
            "by_category_and_severity": defaultdict(lambda: defaultdict(int)),
        }

        for finding in findings:
            severity = finding.severity.value
            category = finding.category

            distribution["by_severity"][severity] += 1
            distribution["by_category"][category] += 1
            distribution["by_category_and_severity"][category][severity] += 1

        # Convert defaultdicts to regular dicts for JSON serialization
        return {
            "by_severity": dict(distribution["by_severity"]),
            "by_category": dict(distribution["by_category"]),
            "by_category_and_severity": {
                cat: dict(sevs) for cat, sevs in distribution["by_category_and_severity"].items()
            },
        }

    def get_assessment_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all available assessments."""
        status = {}

        for assessment_name, assessment in self.assessments.items():
            status[assessment_name] = {
                "enabled": assessment.is_enabled(),
                "owasp_category": assessment.get_owasp_category(),
                "class_name": assessment.__class__.__name__,
            }

        return status

    def run_specific_assessment(self, assessment_name: str, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Run a specific security assessment.

        Args:
            assessment_name: Name of the assessment to run.
            analysis_results: Analysis results to assess.

        Returns:
            List of security findings from the specific assessment.
        """
        if assessment_name not in self.assessments:
            raise ValueError(f"Assessment {assessment_name} not found")

        assessment = self.assessments[assessment_name]
        if not assessment.is_enabled():
            self.logger.warning(f"Assessment {assessment_name} is disabled")
            return []

        try:
            findings = assessment.assess(analysis_results)
            self.logger.info(f"Assessment {assessment_name} completed with {len(findings)} findings")
            return findings
        except Exception as e:
            self.logger.error(f"Assessment {assessment_name} failed: {str(e)}")
            raise

    def get_owasp_coverage(self) -> dict[str, bool]:
        """Get OWASP Top 10 coverage based on available assessments."""
        owasp_top_10_2021 = {
            "A01:2021-Broken Access Control": False,
            "A02:2021-Cryptographic Failures": False,
            "A03:2021-Injection": False,
            "A04:2021-Insecure Design": False,
            "A05:2021-Security Misconfiguration": False,
            "A06:2021-Vulnerable and Outdated Components": False,
            "A07:2021-Identification and Authentication Failures": False,
            "A08:2021-Software and Data Integrity Failures": False,
            "A09:2021-Security Logging and Monitoring Failures": False,
            "A10:2021-Server-Side Request Forgery": False,
        }

        # Check which categories are covered by available assessments
        for assessment in self.assessments.values():
            category = assessment.get_owasp_category()
            if category in owasp_top_10_2021:
                owasp_top_10_2021[category] = True

        return owasp_top_10_2021
