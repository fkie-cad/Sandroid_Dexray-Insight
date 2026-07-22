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

"""SDK Remote-Code Attack-Surface Assessment (OWASP A06:2021).

This assessment complements the CVE / vulnerable-components assessments by
flagging ad SDKs that ship a remote-code attack surface (a JavaScript<->native
bridge, MRAID/VPAID, a runtime code loader, or a download-and-install path)
*regardless of whether a CVE-matched version is known*.

The core point: the SDK's presence plus its risk surface is a review lead in its
own right — a malicious ad-serving endpoint can drive such a bridge — so a
finding is emitted even when the detected library reports no version. Because
the actual RCE pivot is not statically confirmed, findings are raised with a
NEEDS_REVIEW verification status and a sub-headline confidence, keeping them off
the headline risk score while still surfacing them for triage.
"""

import logging
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import VerificationStatus
from ..core.base_classes import register_assessment
from .data.sdk_risk_surface import SDK_RISK_SURFACE
from .data.sdk_risk_surface import severity_for_capabilities


@register_assessment("sdk_risk_surface")
class SdkRiskSurfaceAssessment(BaseSecurityAssessment):
    """OWASP A06:2021 - ad-SDK remote-code attack-surface assessment.

    Emits one A06 finding per ad SDK whose remote-code attack surface is present,
    decoupled from CVE/version matching. A match requires EITHER:

    - a concrete bridge-class descriptor from the knowledge base present in the
      DEX string pool (``string_analysis.all_strings``), OR
    - a confirmed ``library_detection`` match (by display-name) with declared
      capabilities.

    A bare top-level package substring on its own is deliberately NOT a match,
    to avoid over-flagging apps that merely reference an SDK package name.
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize the SDK risk-surface assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A06:2021-Vulnerable and Outdated Components"

    def assess(self, analysis_results: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """Assess detected ad SDKs for a remote-code attack surface.

        Args:
            analysis_results: Combined results from all analysis modules.
            context: Optional analysis context (unused; kept for interface parity).

        Returns:
            One SecurityFinding per matched ad SDK (de-duplicated by SDK name).
        """
        findings: list[SecurityFinding] = []

        try:
            detected = self._get_detected_libraries(analysis_results)
            all_strings = self._get_all_strings(analysis_results)
            # Join the whole DEX string pool into one buffer ONCE, so descriptor
            # matching is O(SDKs × descriptors) substring searches over a single
            # buffer instead of the former O(SDKs × descriptors × strings) nested
            # scan over the ~174k-string pool. The newline join is safe: bridge
            # descriptors never contain newlines, so it cannot create or destroy a
            # match relative to the old "substring of ANY string" semantics.
            joined_strings = "\n".join(all_strings)

            for sdk_name, surface in SDK_RISK_SURFACE.items():
                capabilities = surface.get("capabilities", [])
                bridge_classes = surface.get("bridge_classes", [])

                matched_descriptor = self._matched_bridge_descriptor(bridge_classes, joined_strings)
                library_match = detected.get(self._normalize(sdk_name))

                # Match requires a concrete bridge descriptor OR a confirmed
                # library-detection match with declared capabilities — never a
                # bare package substring.
                if matched_descriptor is None and (library_match is None or not capabilities):
                    continue

                findings.append(
                    self._build_finding(sdk_name, capabilities, matched_descriptor, library_match)
                )

        except Exception as e:
            self.logger.error(f"SDK risk-surface assessment failed: {str(e)}")

        return findings

    def _build_finding(
        self,
        sdk_name: str,
        capabilities: list[str],
        matched_descriptor: str | None,
        library_match: dict | None,
    ) -> SecurityFinding:
        """Build a single A06 finding for a matched SDK."""
        severity = severity_for_capabilities(capabilities)

        version = None
        if library_match is not None:
            version = library_match.get("version")
        version_text = version if version else "version unknown"

        evidence = [
            f"Ad SDK detected: {sdk_name}",
            f"Remote-code attack surface capabilities: {', '.join(capabilities)}",
            f"Version: {version_text}",
        ]
        if matched_descriptor is not None:
            evidence.append(f"Matched bridge-class descriptor: {matched_descriptor}")
        else:
            evidence.append("Matched via confirmed library detection (no bridge descriptor in strings)")

        return SecurityFinding(
            category=self.owasp_category,
            severity=severity,
            title=f"Ad SDK with remote-code attack surface: {sdk_name}",
            description=(
                f"The ad SDK '{sdk_name}' exposes a remote-code attack surface "
                f"({', '.join(capabilities)}). A malicious or compromised ad-serving "
                "endpoint can drive such a JavaScript/native bridge or code loader to "
                "exfiltrate data, load additional code, or trigger installs. This risk "
                "surface exists independently of any specific CVE-matched version "
                f"({version_text}), so it is surfaced as a review lead."
            ),
            evidence=evidence,
            recommendations=[
                f"Review how '{sdk_name}' is initialized and which ad endpoints it contacts",
                "Confirm the SDK is on a current, vendor-supported version",
                "Dynamically verify the JS<->native bridge exposure and reachable native methods",
                "Restrict or disable the SDK if the ad-mediation feature is not required",
                "Enforce TLS and certificate pinning on ad-serving traffic",
            ],
            confidence=0.6,
            verification_status=VerificationStatus.NEEDS_REVIEW,
            additional_data={
                "sdk": sdk_name,
                "capabilities": list(capabilities),
                "verify_dynamically": True,
            },
        )

    @staticmethod
    def _normalize(name: str) -> str:
        """Normalize an SDK/library name for case-insensitive comparison."""
        return str(name or "").strip().lower()

    def _get_detected_libraries(self, analysis_results: dict[str, Any]) -> dict[str, dict]:
        """Return detected libraries keyed by normalized display-name.

        Each value is a small dict carrying the library's ``name`` and
        ``version`` (version may be None). Only entries with a name are kept.
        """
        library_results = analysis_results.get("library_detection", {})
        library_data = library_results.to_dict() if hasattr(library_results, "to_dict") else library_results
        detected_libraries = library_data.get("detected_libraries", []) if isinstance(library_data, dict) else []

        by_name: dict[str, dict] = {}
        for library in detected_libraries:
            if isinstance(library, dict):
                name = library.get("name", "")
                version = library.get("version")
            else:
                name = getattr(library, "name", "")
                version = getattr(library, "version", None)

            if not name:
                continue
            by_name[self._normalize(name)] = {"name": name, "version": version}

        return by_name

    def _get_all_strings(self, analysis_results: dict[str, Any]) -> list[str]:
        """Return the DEX string pool from string_analysis (best-effort)."""
        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        if not isinstance(string_data, dict):
            return []
        all_strings = string_data.get("all_strings", []) or []
        return [s for s in all_strings if isinstance(s, str)]

    @staticmethod
    def _matched_bridge_descriptor(bridge_classes: list[str], joined_strings: str) -> str | None:
        """Return the first bridge-class descriptor found in the string pool.

        ``joined_strings`` is the whole DEX string pool concatenated into one
        buffer (newline-separated) by the caller. A descriptor matches when it
        appears as a substring of that buffer, which is equivalent to the former
        "substring of ANY individual string" test (descriptors contain no
        newlines, so the join neither merges nor splits a match) while being a
        single O(len(buffer)) scan per descriptor instead of a per-string loop.

        The first matching descriptor in knowledge-base order is returned,
        preserving the prior first-match identity. Note that some descriptors are
        intentionally weaker than others: AppLovin's ``com/applovin/impl/adview``
        is a subpackage prefix rather than a concrete bridge class, so it is less
        specific and matches more broadly — it is kept as-is deliberately.
        """
        for descriptor in bridge_classes:
            if descriptor in joined_strings:
                return descriptor
        return None
