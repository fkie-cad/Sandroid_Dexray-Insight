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

"""Authentication Failures Assessment.

This module implements OWASP A07:2021 - Identification and Authentication Failures assessment.
It identifies weak authentication mechanisms and insecure session management in Android applications.
"""

import logging
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import register_assessment


@register_assessment("authentication_failures")
class AuthenticationFailuresAssessment(BaseSecurityAssessment):
    """OWASP A07:2021 - Identification and Authentication Failures assessment."""

    def __init__(self, config: dict[str, Any]):
        """Initialize authentication failures assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A07:2021-Identification and Authentication Failures"

        self.authentication_patterns = {
            "weak_credentials": [
                r'password.*=.*["\'](?:password|123456|admin|test)["\']',
                r"SharedPreferences.*putString.*(?:password|token|auth)",
                r'String.*(?:password|pwd).*=.*["\'][^"\']{1,8}["\']',  # Short passwords
            ],
            "session_management": [r"HttpURLConnection.*(?:session|cookie|auth)", r"CookieManager", r"SessionManager"],
        }

        # Concrete, evidence-backed signals of insecure session handling. Unlike
        # the previous "class name lacks the substring 'timeout'" inference (which
        # tripped nearly every app), these match an actual insecure configuration
        # in the decompiled code: cookies explicitly marked non-secure, or
        # setSecure(false) on a cookie/session.
        self.insecure_session_patterns = [
            r"setSecure\s*\(\s*false\s*\)",
            r"setHttpOnly\s*\(\s*false\s*\)",
            r"cookie[^\n]{0,40}secure\s*=\s*false",
            r'"?\s*secure\s*"?\s*[:=]\s*false',  # Cookie/session config secure=false
        ]

        self.session_management_checks = [
            "session timeout implementation",
            "secure session storage",
            "session invalidation",
        ]

    def assess(self, analysis_results: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """Perform authentication failures assessment."""
        findings = []

        try:
            # Check for weak authentication mechanisms
            auth_findings = self._assess_weak_authentication(analysis_results)
            findings.extend(auth_findings)

            # Check session management
            session_findings = self._assess_session_management(analysis_results)
            findings.extend(session_findings)

        except Exception as e:
            self.logger.error(f"Authentication failures assessment failed: {str(e)}")

        return findings

    def _assess_weak_authentication(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        auth_issues = []
        weak_patterns = self.authentication_patterns["weak_credentials"]

        for string in all_strings:
            if isinstance(string, str):
                for pattern in weak_patterns:
                    import re

                    try:
                        if re.search(pattern, string, re.IGNORECASE):
                            auth_issues.append(f"Weak credential pattern: {string[:80]}...")
                            break
                    except Exception as e:
                        self.logger.debug(f"Regex pattern error for pattern '{pattern}': {e}")
                        continue

        # Concrete weak-credential hits are evidence-backed: emit at MEDIUM with a
        # moderate confidence. The absence of biometric permissions is NOT a
        # vulnerability by itself (it tripped nearly every app), so it no longer
        # contributes to this HIGH finding - see the demoted posture note below.
        if auth_issues:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.MEDIUM,
                    confidence=0.5,
                    title="Weak Authentication Mechanisms",
                    description="Application uses weak authentication mechanisms or stores credentials insecurely.",
                    evidence=auth_issues[:8],
                    recommendations=[
                        "Implement strong authentication mechanisms",
                        "Store credentials securely using Android Keystore",
                        "Implement proper password policies",
                        "Use multi-factor authentication where appropriate",
                    ],
                )
            )

        # Missing biometric permission is a low-value posture observation, not a
        # HIGH finding. Demoted to a LOW note with low confidence so it never
        # dominates the risk score while remaining discoverable.
        manifest_results = analysis_results.get("manifest_analysis", {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, "to_dict") else manifest_results
        permissions = manifest_data.get("permissions", []) or []
        try:
            has_biometric = any("FINGERPRINT" in str(p) or "BIOMETRIC" in str(p) for p in permissions)
        except TypeError:
            has_biometric = False
        if not has_biometric:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.LOW,
                    confidence=0.2,
                    title="Authentication Hardening Posture",
                    description=(
                        "No biometric authentication permission was observed. This is a posture "
                        "observation, not a confirmed weakness - many apps legitimately do not use biometrics."
                    ),
                    evidence=["No biometric authentication permissions detected"],
                    recommendations=[
                        "Consider biometric authentication for sensitive operations where appropriate",
                    ],
                )
            )

        return findings

    def _assess_session_management(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])
        if not isinstance(all_strings, (list, tuple)):
            all_strings = []

        import re

        # Only flag session management when there is a CONCRETE insecure signal
        # (setSecure(false), non-secure cookie, etc.). The previous heuristic
        # inferred insecurity from a class name merely lacking the substring
        # "timeout", which false-positived on almost every app.
        session_issues = []
        for string in all_strings:
            if not isinstance(string, str):
                continue
            for pattern in self.insecure_session_patterns:
                try:
                    if re.search(pattern, string, re.IGNORECASE):
                        session_issues.append(f"Insecure session/cookie configuration: {string[:80]}...")
                        break
                except Exception as e:
                    self.logger.debug(f"Regex pattern error for pattern '{pattern}': {e}")
                    continue

        if session_issues:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.MEDIUM,
                    confidence=0.5,
                    title="Insecure Session Management",
                    description="Application implements session management with concrete insecure configuration signals.",
                    evidence=session_issues[:8],
                    recommendations=[
                        "Implement proper session timeout mechanisms",
                        "Use secure session storage practices",
                        "Implement session invalidation on logout",
                        "Use secure cookie attributes (Secure, HttpOnly) for web sessions",
                        "Monitor and log authentication events",
                    ],
                )
            )

        return findings
