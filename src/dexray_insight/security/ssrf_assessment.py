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

"""Server-Side Request Forgery (SSRF) Assessment.

This module implements OWASP A10:2021 - Server-Side Request Forgery (SSRF) assessment.
It identifies potential SSRF vulnerabilities in Android applications.
"""

import logging
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import register_assessment


@register_assessment("ssrf")
class SSRFAssessment(BaseSecurityAssessment):
    """OWASP A10:2021 - Server-Side Request Forgery (SSRF) assessment."""

    def __init__(self, config: dict[str, Any]):
        """Initialize SSRF assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A10:2021-Server-Side Request Forgery (SSRF)"

        self.url_validation_patterns = [
            r"Uri\.parse\([^)]*user[^)]*\)",
            r"URL\([^)]*user[^)]*\)",
            r"HttpURLConnection.*setRequestProperty.*user",
            r"Intent\.setData\(Uri\.parse\([^)]*user[^)]*\)\)",
        ]

        self.internal_service_patterns = [
            r"https?://(?:localhost|127\.0\.0\.1|10\.0\.2\.2)",
            r"https?://.*\.internal\.",
            r"https?://192\.168\.",
            r"https?://10\.",
            r"file://",
            r"content://",
        ]

    def assess(self, analysis_results: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """Perform SSRF vulnerability assessment."""
        findings = []

        try:
            string_results = analysis_results.get("string_analysis", {})
            if hasattr(string_results, "to_dict"):
                string_data = string_results.to_dict()
            else:
                string_data = string_results

            all_strings = string_data.get("all_strings", [])
            urls = string_data.get("urls", [])

            # Check for potential SSRF vulnerabilities
            ssrf_risks = []
            internal_access = []

            import re

            for string in all_strings:
                if isinstance(string, str):
                    # Check for user-controlled URL patterns
                    for pattern in self.url_validation_patterns:
                        if re.search(pattern, string, re.IGNORECASE):
                            ssrf_risks.append(f"User-controlled URL: {string[:80]}...")
                            break

                    # Check for internal service access patterns
                    for pattern in self.internal_service_patterns:
                        if re.search(pattern, string, re.IGNORECASE):
                            internal_access.append(f"Internal service access: {string[:80]}...")
                            break

            # Check URLs for SSRF indicators
            for url in urls:
                if isinstance(url, str):
                    # Check for localhost, private IPs, or internal domains
                    if any(
                        indicator in url.lower() for indicator in ["localhost", "127.0.0.1", "10.0.2.2", ".internal"]
                    ):
                        internal_access.append(f"Internal URL detected: {url}")

                    # Check for dynamic URL construction
                    if any(dynamic_indicator in url for dynamic_indicator in ["{", "}", "$", "%s", "%d"]):
                        ssrf_risks.append(f"Dynamic URL construction: {url}")

            # Create findings based on detected risks
            if ssrf_risks:
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.HIGH,
                        title="Potential SSRF Vulnerability",
                        description="Application may be vulnerable to Server-Side Request Forgery (SSRF) attacks through user-controlled URLs.",
                        evidence=ssrf_risks[:10],  # Limit evidence items
                        recommendations=[
                            "Implement strict URL validation and allowlisting",
                            "Avoid using user input directly in URL construction",
                            "Use predefined URL templates with parameter validation",
                            "Implement network-level restrictions for internal services",
                            "Validate and sanitize all URL parameters and query strings",
                            "Use URL parsing libraries with built-in validation",
                        ],
                    )
                )

            if internal_access:
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.MEDIUM,
                        title="Internal Service Access Detected",
                        description="Application accesses internal services which could be exploited in SSRF attacks.",
                        evidence=internal_access[:8],
                        recommendations=[
                            "Restrict access to internal services and localhost",
                            "Use network segmentation to isolate internal services",
                            "Implement proper authentication for internal service access",
                            "Validate service endpoints before making requests",
                            "Use service discovery mechanisms instead of hardcoded URLs",
                            "Monitor and log internal service access attempts",
                        ],
                    )
                )

            # Check for WebView-related SSRF risks
            webview_ssrf = []
            for string in all_strings:
                if isinstance(string, str):
                    if "webview" in string.lower() and any(
                        url_part in string.lower() for url_part in ["loadurl", "loaddatawithbaseurl"]
                    ):
                        if any(user_input in string.lower() for user_input in ["user", "input", "param", "query"]):
                            webview_ssrf.append(f"WebView SSRF risk: {string[:70]}...")

            if webview_ssrf:
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.MEDIUM,
                        title="WebView SSRF Risk",
                        description="WebView implementation may be vulnerable to SSRF through URL loading mechanisms.",
                        evidence=webview_ssrf[:5],
                        recommendations=[
                            "Implement URL allowlisting for WebView content",
                            "Validate all URLs before loading in WebView",
                            "Disable JavaScript interface if not needed",
                            "Use WebView security configurations to prevent SSRF",
                            "Implement Content Security Policy for WebView content",
                        ],
                    )
                )

        except Exception as e:
            self.logger.error(f"SSRF assessment failed: {str(e)}")
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.LOW,
                    title="Assessment Error",
                    description="An error occurred during SSRF assessment",
                    evidence=[str(e)],
                    recommendations=["Review application URL handling manually"],
                )
            )

        return findings
