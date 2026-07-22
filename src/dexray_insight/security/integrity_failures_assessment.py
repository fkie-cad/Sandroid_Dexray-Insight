#!/usr/bin/env python3
"""OWASP A08:2021 - Software and Data Integrity Failures security assessment."""

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
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import register_assessment
from .evidence import list_sink_calls


@register_assessment("integrity_failures")
class IntegrityFailuresAssessment(BaseSecurityAssessment):
    """OWASP A08:2021 - Software and Data Integrity Failures assessment."""

    def __init__(self, config: dict[str, Any]):
        """Initialize integrity failures assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A08:2021-Software and Data Integrity Failures"

        # Retained for backward-compatible attribute access, but the bare
        # "Serializable"/"Gson"/"Jackson" substrings are no longer used to raise a
        # HIGH RCE finding - they matched nearly every app. Deserialization RCE now
        # requires a real ObjectInputStream.readObject sink (see evidence.sinks).
        self.deserialization_patterns = [
            r"ObjectInputStream.*readObject\(",
            r"Gson.*fromJson\(",
            r"Jackson.*readValue\(",
            r"Serializable",
            r"Externalizable",
        ]

        self.integrity_checks = ["certificate pinning", "signature verification", "checksum validation"]

    def assess(self, analysis_results: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """Perform integrity failures assessment."""
        findings = []

        try:
            # Check for unsafe deserialization
            deserialization_findings = self._assess_unsafe_deserialization(analysis_results)
            findings.extend(deserialization_findings)

            # Check for missing integrity controls
            integrity_findings = self._assess_missing_integrity_controls(analysis_results)
            findings.extend(integrity_findings)

        except Exception as e:
            self.logger.error(f"Integrity failures assessment failed: {str(e)}")

        return findings

    def _assess_unsafe_deserialization(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Flag unsafe deserialization only when a real readObject sink exists.

        The former behaviour also matched bare "Serializable"/"Gson.fromJson"
        substrings, which raised a HIGH RCE finding on nearly every app. Those
        substrings are not evidence of untrusted-data deserialization, so the HIGH
        finding now requires a ``java.io.ObjectInputStream.readObject`` sink.
        """
        findings = []

        sink_calls = list_sink_calls(analysis_results, "deserialization")
        if not sink_calls:
            return findings

        deserialization_usage = [
            f"Unsafe deserialization: {c.get('called_class', '')}.{c.get('called_method', '')}"
            for c in sink_calls
        ]

        findings.append(
            SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Unsafe Deserialization Detected",
                description="Application uses deserialization mechanisms that could allow remote code execution if untrusted data is processed.",
                evidence=deserialization_usage[:8],
                confidence=0.8,
                recommendations=[
                    "Avoid deserializing untrusted data",
                    "Use safe serialization formats like JSON with schema validation",
                    "Implement input validation before deserialization",
                    "Use allowlists for deserializable classes",
                    "Consider alternative data exchange formats",
                ],
            )
        )

        return findings

    def _assess_missing_integrity_controls(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Report integrity-hardening posture as a single low-confidence note.

        Previously each missing control (cert pinning, signature verification)
        emitted its own MEDIUM finding. Absence of a hardening measure is not a
        vulnerability, so these are folded into one low-confidence posture finding.
        """
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])
        if not isinstance(all_strings, list):
            all_strings = []

        posture_notes = []

        has_cert_pinning = any("pin" in s.lower() and "cert" in s.lower() for s in all_strings if isinstance(s, str))
        if not has_cert_pinning:
            posture_notes.append("No certificate pinning implementation detected")

        has_signature_check = any(
            "signature" in s.lower() and "verify" in s.lower() for s in all_strings if isinstance(s, str)
        )
        if not has_signature_check:
            posture_notes.append("No signature verification implementation detected")

        if posture_notes:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.LOW,
                    title="Integrity Hardening Posture",
                    description=(
                        "Informational: the app does not appear to implement optional integrity-hardening "
                        "controls. Absence is not itself a vulnerability; review whether these controls are "
                        "warranted for this app's threat model."
                    ),
                    evidence=posture_notes,
                    confidence=0.2,
                    recommendations=[
                        "Implement certificate pinning for network communications",
                        "Add signature verification for critical operations",
                        "Use checksums for data integrity validation",
                        "Implement tamper detection mechanisms",
                        "Verify the integrity of downloaded content",
                    ],
                )
            )

        return findings
