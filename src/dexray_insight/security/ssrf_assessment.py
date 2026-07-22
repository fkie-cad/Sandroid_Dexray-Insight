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
from urllib.parse import urlparse

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import register_assessment
from .evidence.package_allowlist import classify_component
from .evidence.package_allowlist import should_downrank

# Ad / tracking / analytics hosts whose format-string URL constants are library
# artifacts, not first-party SSRF sinks. ``package_allowlist`` covers java
# package prefixes (and via reversed-host classification catches google/
# facebook/gms/...); this list covers the DNS hosts of common SDKs that are not
# expressible as a java package prefix (e.g. pubmatic, doubleclick).
_LIBRARY_URL_HOSTS: tuple[str, ...] = (
    "pubmatic.com",
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "crashlytics.com",
    "app-measurement.com",
    "applovin.com",
    "adcolony.com",
    "unity3d.com",
    "mopub.com",
    "inmobi.com",
    "vungle.com",
    "chartboost.com",
    "ironsrc.com",
    "supersonicads.com",
    "adjust.com",
    "appsflyer.com",
    "branch.io",
    "onesignal.com",
    "fbcdn.net",
    "mbridge.com",
    "flurry.com",
    "tapjoy.com",
    "smaato.net",
)

# Tokens that indicate user/attacker-controlled input flowing into a URL (the
# real SSRF shape). A bare ``%s``/``%d`` template constant is NOT one of these.
_USER_INPUT_URL_TOKENS: tuple[str, ...] = (
    "user",
    "input",
    "param",
    "session",
    "token",
    "redirect",
    "callback",
    "next=",
    "target=",
    "dest",
    "url=",
    "uri=",
)


def _extract_host(url: str) -> str:
    """Return the lowercased hostname of a URL, or '' when it has none."""
    if not isinstance(url, str):
        return ""
    try:
        netloc = urlparse(url).netloc
    except (ValueError, TypeError):
        return ""
    return netloc.split("@")[-1].split(":")[0].strip().lower()


def _is_library_origin_url(url: str) -> bool:
    """True when a URL belongs to a known library / ad-SDK / analytics host.

    Reuses ``package_allowlist.classify_component`` by reversing the hostname
    into a java-package-like prefix (``play.google.com`` -> ``com.google.play``)
    so the framework prefix list is the single source of truth, then falls back
    to :data:`_LIBRARY_URL_HOSTS` for SDK hosts not expressible as a package.
    """
    host = _extract_host(url)
    if not host:
        return False
    reversed_pkg = ".".join(reversed(host.split(".")))
    if should_downrank(classify_component(reversed_pkg)):
        return True
    return any(host == h or host.endswith("." + h) for h in _LIBRARY_URL_HOSTS)


def _url_looks_user_controlled(url: str) -> bool:
    """True when a URL both interpolates AND references user-controllable data.

    This is the genuine SSRF shape. A bare ``%s``/``%d`` template constant with
    no user-controlled token is only a parameterized URL, not an SSRF sink.
    """
    if not isinstance(url, str):
        return False
    has_interpolation = any(tok in url for tok in ("{", "}", "$", "%s", "%d"))
    if not has_interpolation:
        return False
    lower = url.lower()
    return any(tok in lower for tok in _USER_INPUT_URL_TOKENS)


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

        # NOTE: file:// and content:// were removed - they are present in ~100% of
        # apps and are not SSRF indicators. Only HTTP(S) internal-host references
        # remain, and even those are gated on URL provenance below.
        self.internal_service_patterns = [
            r"https?://(?:localhost|127\.0\.0\.1|10\.0\.2\.2)",
            r"https?://.*\.internal\.",
            r"https?://192\.168\.",
            r"https?://10\.",
        ]

    def assess(self, analysis_results: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """Perform SSRF vulnerability assessment."""
        findings = []

        try:
            string_results = analysis_results.get("string_analysis", {})
            string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results

            all_strings = string_data.get("all_strings", [])
            urls = string_data.get("urls", [])

            # Check for potential SSRF vulnerabilities
            ssrf_risks, internal_access, dynamic_url_templates = self._detect_ssrf_risks(all_strings, urls)

            # Create findings based on detected risks
            if ssrf_risks:
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.HIGH,
                        title="Potential SSRF Vulnerability",
                        description="Application may be vulnerable to Server-Side Request Forgery (SSRF) attacks through user-controlled URLs.",
                        evidence=ssrf_risks[:10],  # Limit evidence items
                        confidence=0.7,
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
                # Gate on provenance: an internal-host reference is only elevated to
                # MEDIUM when a user-controlled-URL sink also exists (real SSRF
                # surface). On its own it is a LOW, unprovable posture note - the
                # mere presence of an internal URL is common and not a vulnerability.
                has_user_controlled_url = bool(ssrf_risks)
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.MEDIUM if has_user_controlled_url else AnalysisSeverity.LOW,
                        title=(
                            "Internal Service Access Detected"
                            if has_user_controlled_url
                            else "Internal Service Reference (unproven)"
                        ),
                        description=(
                            "Application accesses internal services which could be exploited in SSRF attacks."
                            if has_user_controlled_url
                            else "Application references internal-host URLs. Without a user-controlled URL "
                            "sink this is not proven exploitable; included for manual review."
                        ),
                        evidence=internal_access[:8],
                        confidence=0.6 if has_user_controlled_url else 0.2,
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

            # First-party printf-style URL template constants with no user-controlled
            # input are NOT confirmed SSRF. They are routed to a LOW review item
            # (library / ad-SDK templates were already dropped in _detect_ssrf_risks).
            if dynamic_url_templates:
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.LOW,
                        title="Dynamic URL Template (unproven, review)",
                        description=(
                            "Application contains parameterized URL template constants "
                            "(printf-style %s/%d). No user-controlled URL sink was demonstrated, "
                            "so this is not a confirmed SSRF vulnerability; included for manual review."
                        ),
                        evidence=dynamic_url_templates[:8],
                        confidence=0.2,
                        recommendations=[
                            "Confirm the template parameters are not attacker-controlled",
                            "Use predefined URL templates with parameter validation",
                            "Validate and sanitize any values interpolated into URLs",
                        ],
                    )
                )

            # Check for WebView-related SSRF risks
            webview_ssrf = self._detect_webview_ssrf(all_strings)

            if webview_ssrf:
                findings.append(
                    SecurityFinding(
                        category=self.owasp_category,
                        severity=AnalysisSeverity.MEDIUM,
                        title="WebView SSRF Risk",
                        description="WebView implementation may be vulnerable to SSRF through URL loading mechanisms.",
                        evidence=webview_ssrf[:5],
                        confidence=0.4,
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

    def _detect_ssrf_risks(self, all_strings: list, urls: list) -> tuple[list, list, list]:
        """Detect SSRF risks and internal service access in strings and URLs.

        Returns ``(ssrf_risks, internal_access, dynamic_url_templates)``.

        ``ssrf_risks`` (drives the HIGH finding) contains only *genuine*
        SSRF-shaped evidence: code-level user-controlled URL construction
        (``url_validation_patterns``) and dynamic URLs that both interpolate and
        reference user-controllable data. Bare printf-style URL template
        constants are NOT SSRF sinks: library / ad-SDK templates are dropped and
        first-party bare templates are routed to ``dynamic_url_templates`` (a LOW
        review item), never confirmed as HIGH.
        """
        ssrf_risks = []
        internal_access = []
        dynamic_url_templates = []

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

                # Dynamic URL construction: gate on provenance + SSRF shape.
                if any(dynamic_indicator in url for dynamic_indicator in ["{", "}", "$", "%s", "%d"]):
                    if _is_library_origin_url(url):
                        # Ad-SDK / library format-string URL constant: down-ranked
                        # (dropped from findings). It is not a first-party sink.
                        continue
                    if _url_looks_user_controlled(url):
                        ssrf_risks.append(f"Dynamic URL construction (user-controlled): {url}")
                    else:
                        # First-party bare printf-style template constant: not a
                        # confirmed SSRF sink, routed to a LOW review item.
                        dynamic_url_templates.append(f"Dynamic URL template (constant, review): {url}")

        return ssrf_risks, internal_access, dynamic_url_templates

    def _detect_webview_ssrf(self, all_strings: list) -> list:
        """Detect WebView-related SSRF risks in strings."""
        webview_ssrf = []
        for string in all_strings:
            if isinstance(string, str) and "webview" in string.lower() and any(
                url_part in string.lower() for url_part in ["loadurl", "loaddatawithbaseurl"]
            ) and any(user_input in string.lower() for user_input in ["user", "input", "param", "query"]):
                webview_ssrf.append(f"WebView SSRF risk: {string[:70]}...")
        return webview_ssrf
