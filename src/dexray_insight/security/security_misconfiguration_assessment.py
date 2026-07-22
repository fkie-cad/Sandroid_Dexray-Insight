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

"""Security Misconfiguration Assessment.

This module implements OWASP A05:2021 - Security Misconfiguration assessment.
It identifies security misconfigurations that weaken application security.
"""

import logging
import re
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import VerificationStatus
from ..core.base_classes import register_assessment
from .evidence import FRAMEWORK_PREFIXES
from .manifest_facts import get_manifest_facts
from .mobile_specific_assessment import _NON_ENDPOINT_HOSTS as _MOBILE_NON_ENDPOINT_HOSTS

# Compiled AXML resource files start with this little-endian chunk header.
_AXML_MAGIC = b"\x03\x00\x08\x00"

# Documentation / XML-namespace / placeholder / connectivity-check / captive-portal
# hosts whose cleartext ``http://`` URLs are namespace identifiers, doc links, or
# deliberate test/connectivity probes, NOT first-party network endpoints, and so
# must be dropped from the "Insecure Network Configuration" cleartext evidence
# (base_analys.md A05/B6 false positives: www.w3.org, www.example.com,
# www.google.com, apple.com captive portal, neverssl.com, schemas.microsoft.com,
# ...). Reuses the shared mobile-specific denylist so both assessments filter
# identically, and extends it. Genuine first-party cleartext hosts (meme.kik.com,
# kik.com, piranhakik.com, cdn.kik.com, ...) are NOT on this list and are always
# kept — the filter drops noise, it never suppresses a real endpoint.
_NON_ENDPOINT_HOSTS: tuple[str, ...] = _MOBILE_NON_ENDPOINT_HOSTS + (
    "google.com",  # plain doc links + clients3.google.com/generate_204 connectivity check
    "apple.com",  # Apple captive-portal connectivity check (www.apple.com/library/test/success.html)
    "neverssl.com",  # deliberate always-cleartext test host (*.neverssl.com)
    "schemas.microsoft.com",  # Microsoft XML namespace / DRM schema host
    "msftconnecttest.com",  # Microsoft connectivity check
    "gstatic.com",  # includes connectivitycheck.gstatic.com / generate_204
)

# Extracts the host from the first ``http://`` URL embedded anywhere in a string.
_HTTP_URL_HOST_RE = re.compile(r"http://([^/\s\"'<>?#\\]+)", re.IGNORECASE)


@register_assessment("security_misconfiguration")
class SecurityMisconfigurationAssessment(BaseSecurityAssessment):
    """
    OWASP A05:2021 - Security Misconfiguration vulnerability assessment.

    This assessment identifies security misconfigurations that weaken the
    application's security posture through incorrect settings, default
    configurations, or missing security hardening.

    Mobile-specific focus areas:
    - Debug flags and development configurations in production
    - Insecure network security configurations
    - Permissive file permissions and storage settings
    - Unsafe intent filters and component exports
    - Missing security headers and policies
    - Incorrect cryptographic configurations
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize security misconfiguration assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A05:2021-Security Misconfiguration"

        # Debug and development configuration checks
        self.debug_checks = {
            "manifest_debug_flags": [
                'android:debuggable="true"',
                'android:allowBackup="true"',
                'android:testOnly="true"',
                'android:exported="true"',  # when inappropriate
            ],
            "debug_code_patterns": [
                r"Log\.[dwiev]\(",
                r"System\.out\.println\(",
                r"printStackTrace\(\)",
                r"BuildConfig\.DEBUG",
                r"__DEV__",
                r"Log\.isLoggable\(",
                r"android\.util\.Log",
            ],
            "development_endpoints": [
                r"http://(?:localhost|127\.0\.0\.1|10\.0\.2\.2|debug|dev|staging)",
                r"://.*\.(?:dev|debug|test|staging|local)\.",
                r"debug\..*\.com",
                r"api-dev\.",
                r"staging-api\.",
            ],
        }

        # Network security configuration checks
        self.network_security_checks = {
            "insecure_connections": [
                r"http://(?!localhost|127\.0\.0\.1)",  # Non-localhost HTTP
                r"setHostnameVerifier\(.*ALLOW_ALL",
                r"setDefaultHostnameVerifier\(",
                r"TrustManager.*checkServerTrusted.*\{\s*\}",  # Empty trust manager
                r"X509TrustManager.*\{\s*\}",
                r"SSLContext.*TLS.*null",
                r"HttpsURLConnection.*setDefaultSSLSocketFactory",
            ],
            "disabled_security_features": [
                r"setAllowFileAccess\(true\)",
                r"setAllowContentAccess\(true\)",
                r"setAllowUniversalAccessFromFileURLs\(true\)",
                r"setJavaScriptEnabled\(true\)",
                r"setDomStorageEnabled\(true\)",
                r"setDatabaseEnabled\(true\)",
            ],
            "weak_ssl_configurations": [
                r"SSL_?(?:v2|v3|TLS_?(?:v1|1\.0|1\.1))",
                r"DH.*512|RSA.*1024",  # Weak key sizes
                r"RC4|DES|3DES",  # Weak ciphers
                r"MD5|SHA1",  # Weak hash functions
            ],
        }

        # File and storage permission checks
        self.storage_permission_checks = {
            "world_accessible_files": [
                r"MODE_WORLD_READABLE",
                r"MODE_WORLD_WRITEABLE",
                r"openFileOutput\([^,]+,\s*[12]\)",  # MODE_WORLD_READABLE=1, MODE_WORLD_WRITEABLE=2
                r'File\([^)]*"/sdcard/',
                r"Environment\.getExternalStorageDirectory\(\)",
                r"Context\.MODE_WORLD_READABLE",
            ],
            "insecure_shared_preferences": [
                r"getSharedPreferences\([^,]+,\s*MODE_WORLD_READABLE\)",
                r"getSharedPreferences\([^,]+,\s*MODE_WORLD_WRITEABLE\)",
                r"getSharedPreferences.*MODE_WORLD",
            ],
            "external_storage_misuse": [
                r"getExternalFilesDir\([^)]*\).*password",
                r"getExternalStorageDirectory\(\).*token",
                r"/sdcard/.*(?:password|token|key|secret)",
                r"Environment\.getExternalStoragePublicDirectory",
            ],
        }

        # Component and permission misconfigurations
        self.component_misconfigurations = {
            "overprivileged_exports": [
                'android:exported="true"',
                'android:permission=""',  # Empty permission
                'android:protectionLevel="normal"',  # For sensitive operations
            ],
            "dangerous_intent_filters": [
                "android.intent.action.BOOT_COMPLETED",
                "android.intent.action.PACKAGE_INSTALL",
                "android.intent.action.PACKAGE_REMOVED",
                "android.provider.Telephony.SMS_RECEIVED",
                "android.intent.action.PHONE_STATE",
            ],
            "content_provider_risks": [
                'android:grantUriPermissions="true"',
                'android:multiprocess="true"',
                'android:syncable="true"',
            ],
        }

        # Security policy misconfigurations
        self.security_policy_checks = {
            "missing_policies": [
                "network-security-config",
                "content-security-policy",
                "certificate-pinning",
                "backup-rules",
                "data-extraction-rules",
            ],
            "weak_policies": [
                'cleartextTrafficPermitted="true"',
                'usesCleartextTraffic="true"',
                'android:allowBackup="true"',
                'android:fullBackupContent=""',  # Empty backup rules
            ],
        }

    def assess(self, analysis_results: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """
        Assess for security misconfiguration vulnerabilities.

        Args:
            analysis_results: Combined results from all analysis modules

        Returns:
            List of security findings related to security misconfigurations
        """
        findings = []

        try:
            # 1. Check debug and development configurations
            debug_findings = self._assess_debug_configurations(analysis_results)
            findings.extend(debug_findings)

            # 2. Analyze network security configurations
            network_findings = self._assess_network_security_config(analysis_results)
            findings.extend(network_findings)

            # 3. Check file and storage permissions
            storage_findings = self._assess_storage_configurations(analysis_results)
            findings.extend(storage_findings)

            # 4. Evaluate component configurations
            component_findings = self._assess_component_configurations(analysis_results)
            findings.extend(component_findings)

            # 5. Check security policies
            policy_findings = self._assess_security_policies(analysis_results)
            findings.extend(policy_findings)

            # 6. Validate cryptographic configurations
            crypto_findings = self._assess_crypto_configurations(analysis_results)
            findings.extend(crypto_findings)

            # 7. WebView JavaScript bridge exposure (real API sinks)
            findings.extend(self._assess_webview_js_bridges(analysis_results))

            # 8. Manifest-driven cleartext traffic feeding first-party endpoints
            findings.extend(self._assess_cleartext_traffic(analysis_results))

            # 9. Network-security-config `user` trust anchor (weakens MITM resistance)
            findings.extend(self._assess_nsc_user_trust_anchors(analysis_results, context))

        except Exception as e:
            self.logger.error(f"Security misconfiguration assessment failed: {str(e)}")

        return findings

    def _assess_debug_configurations(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess debug and development configurations."""
        findings = []

        # Get manifest analysis for debug flags
        manifest_results = analysis_results.get("manifest_analysis", {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, "to_dict") else manifest_results

        debug_flags = manifest_data.get("debug_flags", {})
        debug_issues = []

        # Check manifest debug flags
        if debug_flags.get("debuggable"):
            debug_issues.append("Application is marked as debuggable in production manifest")

        if debug_flags.get("allow_backup"):
            debug_issues.append("Application allows full backup without restrictions")

        if debug_flags.get("test_only"):
            debug_issues.append("Application is marked as test-only but may be in production")

        # Get string analysis for debug code patterns
        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        # Check for debug code patterns
        debug_code_count = self._count_debug_code_patterns(all_strings)

        if debug_code_count > 10:  # Threshold for excessive debug code
            debug_issues.append(f"Excessive debug/logging code detected: {debug_code_count} instances")

        # Check for development endpoints
        dev_endpoints = self._detect_development_endpoints(string_data, all_strings)

        if dev_endpoints:
            debug_issues.extend([f"Development endpoint: {endpoint}" for endpoint in dev_endpoints[:5]])

        if debug_issues:
            severity = AnalysisSeverity.HIGH if debug_flags.get("debuggable") else AnalysisSeverity.MEDIUM

            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=severity,
                    title="Debug and Development Configuration Issues",
                    description="Application contains debug configurations or development artifacts that should not be present in production builds.",
                    evidence=debug_issues,
                    recommendations=[
                        "Remove android:debuggable='true' from production manifest",
                        "Disable backup or configure proper backup rules",
                        "Remove debug logging and development endpoints from production code",
                        "Use build variants to separate debug and release configurations",
                        "Implement proper build pipeline to strip debug artifacts",
                    ],
                )
            )

        return findings

    def _count_debug_code_patterns(self, all_strings: list) -> int:
        """Count strings matching known debug/logging code patterns."""
        debug_code_count = 0
        debug_patterns = self.debug_checks["debug_code_patterns"]

        for string in all_strings:
            if isinstance(string, str):
                for pattern in debug_patterns:
                    import re

                    if re.search(pattern, string, re.IGNORECASE):
                        debug_code_count += 1
                        break

        return debug_code_count

    def _detect_development_endpoints(self, string_data: dict, all_strings: list) -> list:
        """Detect development endpoints across URLs, domains and strings."""
        dev_endpoints = []
        dev_patterns = self.debug_checks["development_endpoints"]

        urls = string_data.get("urls", [])
        domains = string_data.get("domains", [])
        all_network_strings = urls + domains + all_strings

        for string in all_network_strings:
            if isinstance(string, str):
                for pattern in dev_patterns:
                    import re

                    if re.search(pattern, string, re.IGNORECASE):
                        dev_endpoints.append(string)
                        break

        return dev_endpoints

    def _assess_network_security_config(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess network security configurations."""
        findings = []

        # Get string analysis for network patterns
        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        network_issues = []
        # A cleartext-only finding is MEDIUM (base_analys.md A2); a *strong* signal
        # (missing NSC, TLS trust-bypass, disabled security feature, weak SSL)
        # escalates it to HIGH. Cleartext HTTP alone must not carry HIGH.
        strong_signal = False

        # Check for missing network security config using authoritative manifest
        # facts. Only flag when the manifest attribute is a KNOWN absence; skip
        # when it is present or the fact is unavailable to avoid false positives.
        manifest_facts = get_manifest_facts(analysis_results)
        if manifest_facts["network_security_config_known"] and not manifest_facts["network_security_config"]:
            network_issues.append("No network security configuration detected")
            strong_signal = True

        # Check for insecure connections. The first pattern is the cleartext
        # http:// matcher; the remaining patterns are genuine TLS trust-bypass
        # signals (ALLOW_ALL hostname verifier, empty TrustManager, ...). Cleartext
        # URLs pointing at documentation / XML-namespace / placeholder hosts
        # (w3.org, example.com, google.com, ...) are not first-party endpoints and
        # are dropped; genuine first-party cleartext (meme.kik.com, ...) is kept.
        insecure_patterns = self.network_security_checks["insecure_connections"]
        cleartext_pattern = insecure_patterns[0]
        trust_bypass_patterns = insecure_patterns[1:]
        for string in all_strings:
            if not isinstance(string, str):
                continue
            if any(re.search(p, string, re.IGNORECASE) for p in trust_bypass_patterns):
                network_issues.append(f"Insecure network configuration: {string[:80]}...")
                strong_signal = True
                continue
            if re.search(cleartext_pattern, string, re.IGNORECASE):
                host = self._cleartext_url_host(string)
                if host and self._is_non_endpoint_host(host):
                    continue  # documentation / namespace / placeholder host -> drop
                network_issues.append(f"Insecure network configuration: {string[:80]}...")

        # Check for disabled security features
        disabled_patterns = self.network_security_checks["disabled_security_features"]
        for string in all_strings:
            if isinstance(string, str):
                for pattern in disabled_patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        network_issues.append(f"Disabled security feature: {string[:80]}...")
                        strong_signal = True
                        break

        # Check for weak SSL configurations. The first two patterns are inherently
        # SSL/TLS-context signals (deprecated protocol version, weak key size) and
        # remain genuine strong signals. The trailing bare cipher/hash tokens
        # (RC4|DES|3DES, MD5|SHA1) match arbitrary library strings as SUBSTRINGS —
        # `DES` matches "descendant"/"Design"/"NavDestination", `MD5`/`SHA1` match
        # BouncyCastle aliases and log messages — so they are NOT by themselves an
        # SSL misconfiguration. They only count when the string is an actual
        # SSL/TLS/cipher context, preventing bundled crypto-library strings from
        # escalating a cleartext-only finding to HIGH (base_analys.md B3/B6).
        weak_ssl_patterns = self.network_security_checks["weak_ssl_configurations"]
        ssl_context_patterns = weak_ssl_patterns[:2]
        bare_algo_patterns = weak_ssl_patterns[2:]
        for string in all_strings:
            if not isinstance(string, str):
                continue
            matched = any(re.search(p, string, re.IGNORECASE) for p in ssl_context_patterns)
            if not matched and self._has_ssl_tls_context(string):
                matched = any(re.search(p, string, re.IGNORECASE) for p in bare_algo_patterns)
            if matched:
                network_issues.append(f"Weak SSL configuration: {string[:80]}...")
                strong_signal = True

        if network_issues:
            severity = AnalysisSeverity.HIGH if strong_signal else AnalysisSeverity.MEDIUM
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=severity,
                    title="Insecure Network Configuration",
                    description="Application contains insecure network configurations that expose communications to attacks.",
                    evidence=network_issues[:10],
                    recommendations=[
                        "Implement network security configuration with certificate pinning",
                        "Disable cleartext traffic and enforce HTTPS",
                        "Use strong TLS versions (1.2+) and secure cipher suites",
                        "Properly validate SSL certificates and hostnames",
                        "Remove or secure any disabled security features",
                    ],
                )
            )

        return findings

    # Tokens that mark a string as an actual SSL/TLS/cipher-suite context (so a
    # bare weak-cipher/hash token in it is a real config signal, not library noise).
    _SSL_CONTEXT_TOKENS = (
        "ssl",
        "tls",
        "cipher",
        "https",
        "socketfactory",
        "sslcontext",
        "handshake",
        "x509",
        "trustmanager",
        "protocol",
    )

    @classmethod
    def _has_ssl_tls_context(cls, string: str) -> bool:
        """True when ``string`` references an SSL/TLS/cipher configuration context."""
        lowered = string.lower()
        return any(token in lowered for token in cls._SSL_CONTEXT_TOKENS)

    @staticmethod
    def _cleartext_url_host(text: str) -> str | None:
        """Return the lower-cased host of the first ``http://`` URL in ``text``.

        Handles URLs embedded anywhere in a larger string and strips any
        userinfo/port. Returns None when no ``http://`` URL is present.
        """
        match = _HTTP_URL_HOST_RE.search(text)
        if not match:
            return None
        host = match.group(1).split("@")[-1].split(":")[0].strip().lower()
        return host or None

    @staticmethod
    def _is_non_endpoint_host(host: str) -> bool:
        """True for documentation / namespace / connectivity-check / ad-SDK hosts.

        Drops (a) explicit denylist hosts, (b) ``connectivitycheck.*`` captive-portal
        probes, and (c) third-party / ad-SDK hosts recognised by reversing the host
        to a known library package prefix (fyber.com, ogury.com, inmobi.com, ...).
        First-party hosts (kik.com, piranhakik.com, cdn.kik.com, ...) reverse to
        prefixes absent from the allowlist and are never on the denylist, so a
        genuine cleartext endpoint is never suppressed here.
        """
        if host.startswith("connectivitycheck."):
            return True
        if any(host == h or host.endswith("." + h) for h in _NON_ENDPOINT_HOSTS):
            return True
        return SecurityMisconfigurationAssessment._is_ad_or_library_host(host)

    @staticmethod
    def _is_ad_or_library_host(host: str) -> bool:
        """True when ``host`` reverses to a known third-party/ad-SDK package prefix.

        e.g. ``ads-test.st.ogury.com`` -> ``com.ogury.st.ads-test`` which sits under
        the ``com.ogury.`` allowlist prefix. First-party hosts (kik.com,
        piranhakik.com) reverse to prefixes not present in the allowlist and are
        therefore never dropped here.
        """
        labels = [label for label in host.split(".") if label]
        if len(labels) < 2:
            return False
        reversed_domain = ".".join(reversed(labels))
        for prefix in FRAMEWORK_PREFIXES:
            base = prefix.rstrip(".")
            if reversed_domain == base or reversed_domain.startswith(base + "."):
                return True
        return False

    def _assess_storage_configurations(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess file and storage permission configurations."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        # Get behavior analysis for file operations
        behavior_results = analysis_results.get("behaviour_analysis", {})
        file_operations = behavior_results.get("file_operations", {}) if isinstance(behavior_results, dict) else {}

        storage_issues = []

        # Check behavior analysis for world-accessible files
        world_readable = file_operations.get("world_readable_files", [])
        world_writable = file_operations.get("world_writable_files", [])

        if world_readable:
            storage_issues.extend([f"World-readable file: {f}" for f in world_readable[:3]])

        if world_writable:
            storage_issues.extend([f"World-writable file: {f}" for f in world_writable[:3]])

        # Check for world-accessible file patterns in code
        world_patterns = self.storage_permission_checks["world_accessible_files"]
        for string in all_strings:
            if isinstance(string, str):
                for pattern in world_patterns:
                    import re

                    if re.search(pattern, string, re.IGNORECASE):
                        storage_issues.append(f"World-accessible file pattern: {string[:80]}...")
                        break

        # Check for insecure SharedPreferences
        prefs_patterns = self.storage_permission_checks["insecure_shared_preferences"]
        for string in all_strings:
            if isinstance(string, str):
                for pattern in prefs_patterns:
                    import re

                    if re.search(pattern, string, re.IGNORECASE):
                        storage_issues.append(f"Insecure SharedPreferences: {string[:80]}...")
                        break

        # Check for external storage misuse
        storage_issues.extend(self._detect_external_storage_misuse(all_strings))

        if storage_issues:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.MEDIUM,
                    title="Insecure Storage Configuration",
                    description="Application uses insecure file and storage configurations that expose data to unauthorized access.",
                    evidence=storage_issues[:10],
                    recommendations=[
                        "Use MODE_PRIVATE for all internal file operations",
                        "Avoid storing sensitive data on external storage",
                        "Use EncryptedSharedPreferences for sensitive preferences",
                        "Implement proper file permissions and access controls",
                        "Use Android Keystore for sensitive data encryption keys",
                    ],
                )
            )

        return findings

    def _detect_external_storage_misuse(self, all_strings: list) -> list:
        """Detect external storage misuse patterns in strings."""
        issues = []
        external_patterns = self.storage_permission_checks["external_storage_misuse"]
        for string in all_strings:
            if isinstance(string, str):
                for pattern in external_patterns:
                    import re

                    if re.search(pattern, string, re.IGNORECASE):
                        issues.append(f"External storage misuse: {string[:80]}...")
                        break

        return issues

    def _assess_component_configurations(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess component configuration security."""
        findings = []

        manifest_results = analysis_results.get("manifest_analysis", {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, "to_dict") else manifest_results

        component_issues = []

        # Check exported components
        exported_components = manifest_data.get("exported_components", [])
        if len(exported_components) > 5:  # Threshold for too many exports
            component_issues.append(f"Excessive exported components: {len(exported_components)} components exported")

        # Check intent filters for dangerous patterns
        intent_filters = manifest_data.get("intent_filters", [])
        dangerous_patterns = self.component_misconfigurations["dangerous_intent_filters"]

        for intent_filter in intent_filters:
            if isinstance(intent_filter, dict):
                filters = intent_filter.get("filters", [])
                component_name = intent_filter.get("component_name", "unknown")

                for filter_item in filters:
                    if any(dangerous in str(filter_item) for dangerous in dangerous_patterns):
                        component_issues.append(f"Dangerous intent filter in {component_name}: {filter_item}")

        # Check permissions
        permissions = manifest_data.get("permissions", [])
        dangerous_permissions = [
            "WRITE_EXTERNAL_STORAGE",
            "CAMERA",
            "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION",
            "READ_CONTACTS",
            "WRITE_CONTACTS",
            "READ_SMS",
            "SEND_SMS",
            "CALL_PHONE",
        ]

        excessive_permissions = [p for p in permissions if any(dp in p for dp in dangerous_permissions)]
        if len(excessive_permissions) > 3:  # Threshold for permission creep
            component_issues.append(
                f"Excessive dangerous permissions: {len(excessive_permissions)} sensitive permissions"
            )

        # Consume the previously-dead `content_provider_risks` patterns (grantUriPermissions
        # / multiprocess / syncable). We match them against whatever manifest-derived text
        # is available here (component reprs + raw DEX/manifest strings), adding evidence
        # ONLY on a genuine match so this never fabricates a no-op finding. The authoritative
        # androguard-resource-based provider analysis lands in Phase B (provider_paths).
        provider_risk_patterns = self.component_misconfigurations.get("content_provider_risks", [])
        if provider_risk_patterns:
            string_results = analysis_results.get("string_analysis", {})
            string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
            manifest_corpus = [str(c) for c in exported_components]
            manifest_corpus.extend(str(s) for s in string_data.get("all_strings", []) if isinstance(s, str))
            for pattern in provider_risk_patterns:
                # Normalize the attribute pattern to its bare token so it matches decoded
                # manifest text regardless of quoting/namespace (e.g. grantUriPermissions).
                token = pattern.split(":")[-1].split("=")[0]
                if any(token in entry for entry in manifest_corpus):
                    component_issues.append(f"Content provider risk indicator present: {token}")

        if component_issues:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.MEDIUM,
                    title="Component Configuration Issues",
                    description="Application components are configured with excessive privileges or dangerous patterns.",
                    evidence=component_issues,
                    recommendations=[
                        "Minimize exported components and use explicit permissions",
                        "Review and restrict dangerous intent filters",
                        "Follow principle of least privilege for component permissions",
                        "Use signature-level permissions for sensitive inter-app communication",
                        "Regularly audit component configurations and permissions",
                    ],
                )
            )

        return findings

    def _assess_security_policies(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess security policy configurations."""
        findings = []

        policy_issues = []

        # Resolve authoritative manifest facts. Each check below is only emitted
        # when the underlying fact is KNOWN, never on an unknown/default value,
        # so unavailable data (failed apk_overview, split APK) cannot resurface
        # as false positives such as "Target SDK 0" or "Backup is enabled".
        manifest_facts = get_manifest_facts(analysis_results)

        # Missing network security config: only when the manifest attribute is a
        # known absence (present or unknown -> skip).
        if manifest_facts["network_security_config_known"] and not manifest_facts["network_security_config"]:
            policy_issues.append("Missing network security configuration")

        # Backup: only flag when allowBackup is explicitly enabled (False or
        # unknown -> skip).
        if manifest_facts["allow_backup"] is True:
            policy_issues.append("Backup is enabled without proper configuration")

        # Target SDK: only flag when known and actually below the threshold.
        target_sdk = manifest_facts["target_sdk"]
        if target_sdk is not None and target_sdk < 28:  # Android 9 (API 28) stricter policies
            policy_issues.append(f"Target SDK version {target_sdk} does not enforce modern security policies")

        # Minimum SDK: only flag when known and actually below the threshold.
        min_sdk = manifest_facts["min_sdk"]
        if min_sdk is not None and min_sdk < 23:  # Android 6 (API 23) runtime permissions
            policy_issues.append(f"Minimum SDK version {min_sdk} does not support runtime permissions")

        if policy_issues:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.MEDIUM,
                    title="Missing or Weak Security Policies",
                    description="Application lacks essential security policies or uses weak policy configurations.",
                    evidence=policy_issues,
                    recommendations=[
                        "Implement comprehensive network security configuration",
                        "Configure proper backup and data extraction rules",
                        "Target recent Android API levels for security enforcement",
                        "Implement Content Security Policy for web content",
                        "Add certificate pinning and integrity verification policies",
                    ],
                )
            )

        return findings

    def _assess_crypto_configurations(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Assess cryptographic configuration issues."""
        findings = []

        # Get API invocation results for crypto configuration
        api_results = analysis_results.get("api_invocation", {})
        api_data = api_results.to_dict() if hasattr(api_results, "to_dict") else api_results

        crypto_usage = api_data.get("crypto_usage", [])
        crypto_issues = []

        # Check for weak cryptographic configurations
        for crypto_call in crypto_usage:
            if isinstance(crypto_call, dict):
                algorithm = crypto_call.get("algorithm", "").upper()
                context = crypto_call.get("context", "")

                # Flag weak algorithms
                if algorithm in ["MD5", "SHA1", "DES", "RC4"]:
                    crypto_issues.append(f"Weak cryptographic algorithm: {algorithm} used for {context}")

                # Flag inappropriate usage
                if algorithm == "MD5" and "password" in context.lower():
                    crypto_issues.append(f"MD5 used for password hashing at {crypto_call.get('location', 'unknown')}")

        # Get string analysis for hardcoded crypto configurations
        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        # Check for hardcoded cryptographic keys or salts
        crypto_patterns = [
            r'(?:key|salt|iv)\s*=\s*["\'][A-Za-z0-9+/]{16,}["\']',
            r'SecretKeySpec\(["\'][^"\']{8,}["\']',
            r'IvParameterSpec\(["\'][^"\']{8,}["\']',
        ]

        for string in all_strings:
            if isinstance(string, str):
                for pattern in crypto_patterns:
                    import re

                    if re.search(pattern, string, re.IGNORECASE):
                        crypto_issues.append(f"Hardcoded cryptographic material: {string[:60]}...")
                        break

        if crypto_issues:
            findings.append(
                SecurityFinding(
                    category=self.owasp_category,
                    severity=AnalysisSeverity.HIGH,
                    title="Cryptographic Configuration Issues",
                    description="Application uses weak or improperly configured cryptographic implementations.",
                    evidence=crypto_issues[:8],
                    recommendations=[
                        "Use strong cryptographic algorithms (AES-256, SHA-256, etc.)",
                        "Store cryptographic keys securely using Android Keystore",
                        "Use proper key derivation functions for password hashing",
                        "Implement cryptographic best practices and standards",
                        "Regularly review and update cryptographic configurations",
                    ],
                )
            )

        return findings

    # ------------------------------------------------------------------ #
    # WebView JavaScript-bridge exposure (IPC / web attack surface)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _get_api_calls(analysis_results: dict[str, Any]) -> list:
        """Return the ``api_invocation.api_calls`` list defensively."""
        api_results = analysis_results.get("api_invocation", {}) if isinstance(analysis_results, dict) else {}
        api_data = api_results.to_dict() if hasattr(api_results, "to_dict") else api_results
        if not isinstance(api_data, dict):
            return []
        calls = api_data.get("api_calls", [])
        return calls if isinstance(calls, list) else []

    @staticmethod
    def _normalize_api_token(text: Any) -> str:
        """Normalise a smali/dotted class or method token to a slashed-lowercase form.

        Handles ``Landroid/webkit/WebView;`` (smali), ``android.webkit.WebView``
        (dotted), and combined ``...->addJavascriptInterface(...)`` signatures.
        """
        if not isinstance(text, str):
            return ""
        token = text.strip()
        if token.startswith("L") and token.endswith(";"):
            token = token[1:-1]
        token = token.split("->")[-1].split("(")[0]
        return token.replace(".", "/").lower()

    def _assess_webview_js_bridges(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Flag real WebView JavaScript-bridge exposure from API invocations.

        Counts genuine ``addJavascriptInterface`` and ``setJavaScriptEnabled``
        invocations recorded by the api_invocation module (accepting smali and
        dotted forms). When present, emits a single MEDIUM finding summarising the
        counts - not one finding per call.
        """
        findings: list[SecurityFinding] = []

        add_js_interface = 0
        set_js_enabled = 0
        for call in self._get_api_calls(analysis_results):
            if not isinstance(call, dict):
                continue
            called_class = self._normalize_api_token(call.get("called_class", ""))
            method = self._normalize_api_token(call.get("called_method", ""))
            if method == "addjavascriptinterface" or "addjavascriptinterface" in called_class:
                add_js_interface += 1
            elif method == "setjavascriptenabled" or "setjavascriptenabled" in called_class:
                set_js_enabled += 1

        if add_js_interface == 0 and set_js_enabled == 0:
            return findings

        evidence = [
            f"addJavascriptInterface ×{add_js_interface}",
            f"setJavaScriptEnabled ×{set_js_enabled}",
        ]
        description = (
            "The application exposes a JavaScript bridge into WebView content. "
            "addJavascriptInterface makes native methods callable from JavaScript, and enabling "
            "JavaScript widens the WebView attack surface. If any loaded content is attacker-influenced "
            "(cleartext HTTP, third-party pages, deep-link supplied URLs), this can lead to code execution "
            "or data exfiltration through the bridge."
        )
        findings.append(
            SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                confidence=0.6,
                title="WebView JavaScript Bridge Exposure",
                description=description,
                evidence=evidence,
                recommendations=[
                    "Only call addJavascriptInterface for trusted, first-party content loaded over HTTPS",
                    "Restrict @JavascriptInterface methods to the minimum surface and validate all inputs",
                    "Disable JavaScript (setJavaScriptEnabled(false)) in WebViews that do not require it",
                    "Set a strict allowlist of loadable URLs and reject cleartext/untrusted origins",
                ],
            )
        )
        return findings

    def _has_webview_js(self, analysis_results: dict[str, Any]) -> bool:
        """Return True when WebView JS-bridge / setJavaScriptEnabled invocations exist."""
        for call in self._get_api_calls(analysis_results):
            if not isinstance(call, dict):
                continue
            method = self._normalize_api_token(call.get("called_method", ""))
            if method in ("addjavascriptinterface", "setjavascriptenabled"):
                return True
            called_class = self._normalize_api_token(call.get("called_class", ""))
            if "addjavascriptinterface" in called_class or "setjavascriptenabled" in called_class:
                return True
        return False

    # ------------------------------------------------------------------ #
    # Manifest-driven cleartext traffic into first-party endpoints/WebViews
    # ------------------------------------------------------------------ #
    _NON_APP_HOSTS = (
        "schemas.android.com",
        "www.w3.org",
        "w3.org",
        "xmlpull.org",
        "apache.org",
        "java.sun.com",
        "ns.adobe.com",
        "goo.gl",
    )
    _LOCAL_HOSTS = ("localhost", "127.0.0.1", "10.0.2.2", "0.0.0.0")  # noqa: S104  (denylist of local/dev URL hosts, not a bind address)
    _PACKAGE_STOP_TOKENS = frozenset(
        {"com", "org", "net", "io", "co", "android", "app", "apps", "www", "gov", "edu", "mobile", "free", "the"}
    )

    @staticmethod
    def _package_name(analysis_results: dict[str, Any]) -> str | None:
        """Read apk_overview.general_info.package_name defensively."""
        overview = analysis_results.get("apk_overview") if isinstance(analysis_results, dict) else None
        if overview is None:
            return None
        general = getattr(overview, "general_info", None)
        if general is None:
            if isinstance(overview, dict):
                general = overview.get("general_info")
            else:
                to_dict = getattr(overview, "to_dict", None)
                if callable(to_dict):
                    try:
                        general = to_dict().get("general_info")
                    except Exception:
                        general = None
        if general is None:
            return None
        pkg = general.get("package_name") if isinstance(general, dict) else getattr(general, "package_name", None)
        return str(pkg) if pkg else None

    @staticmethod
    def _url_host(url: str) -> str:
        """Extract the lower-cased host from an http:// URL."""
        rest = url[len("http://"):]
        rest = rest.split("/")[0].split("?")[0].split("#")[0]
        rest = rest.split("@")[-1]  # strip userinfo
        rest = rest.split(":")[0]  # strip port
        return rest.strip().lower()

    def _package_tokens(self, package_name: str | None) -> set[str]:
        """Derive meaningful package tokens (drops TLD-like/generic segments)."""
        if not package_name:
            return set()
        return {t for t in package_name.lower().split(".") if t and t not in self._PACKAGE_STOP_TOKENS}

    def _first_party_http_endpoints(self, analysis_results: dict[str, Any]) -> list[str]:
        """Return first-party ``http://`` endpoints from string_analysis URLs.

        A URL is treated as first-party when its host shares a meaningful token
        with the app package name; when no usable package token exists, any
        non-local, non-framework cleartext host is treated as a candidate.
        Localhost/dev and well-known non-app (schema/xml) hosts are excluded.
        """
        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        urls = string_data.get("urls", []) if isinstance(string_data, dict) else []

        tokens = self._package_tokens(self._package_name(analysis_results))

        first_party: list[str] = []
        for url in urls:
            if not isinstance(url, str) or not url.lower().startswith("http://"):
                continue
            host = self._url_host(url)
            if not host or host in self._LOCAL_HOSTS:
                continue
            if any(host == h or host.endswith("." + h) for h in self._NON_APP_HOSTS):
                continue
            if tokens:
                if any(tok in host for tok in tokens):
                    first_party.append(url)
            else:
                first_party.append(url)
        return first_party

    def _assess_cleartext_traffic(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """Flag manifest-permitted cleartext traffic feeding first-party endpoints/WebViews.

        Emits only when ``usesCleartextTraffic`` is a KNOWN True AND first-party
        ``http://`` endpoints exist AND a network security config does not
        restrict cleartext. When the flag is unknown (None) or False, nothing is
        emitted (unknown-sentinel guard). Escalated when a WebView JS bridge /
        setJavaScriptEnabled is also present. This is manifest-attribute-driven
        and complements (does not duplicate) the string-pattern insecure-connection
        check.
        """
        findings: list[SecurityFinding] = []

        facts = get_manifest_facts(analysis_results)
        if facts.get("uses_cleartext_traffic") is not True:
            # Unknown (None) or explicitly False -> do not emit.
            return findings

        # A network security config that restricts cleartext would override the
        # global flag. We only treat cleartext as restricted with positive
        # evidence; absent that, the global usesCleartextTraffic=True stands.
        if self._nsc_restricts_cleartext(analysis_results):
            return findings

        first_party_http = self._first_party_http_endpoints(analysis_results)
        if not first_party_http:
            return findings

        webview_js = self._has_webview_js(analysis_results)

        description = (
            "The manifest permits cleartext (HTTP) traffic (android:usesCleartextTraffic=\"true\") and the "
            "app references first-party http:// endpoints. Cleartext traffic can be intercepted or modified "
            "by a network attacker."
        )
        if webview_js:
            description += (
                " Because the app also loads WebView content with JavaScript enabled, an attacker who tampers "
                "with cleartext content can inject script into the WebView (cleartext content into WebView)."
            )

        evidence = [
            "Manifest: android:usesCleartextTraffic=\"true\"",
        ]
        evidence.extend(f"First-party cleartext endpoint: {url}" for url in first_party_http[:5])
        if webview_js:
            evidence.append("WebView JavaScript bridge / setJavaScriptEnabled present")

        findings.append(
            SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                confidence=0.7,
                title="Cleartext Content Into WebView" if webview_js else "Cleartext Traffic Permitted",
                description=description,
                evidence=evidence,
                recommendations=[
                    "Set android:usesCleartextTraffic=\"false\" and migrate all endpoints to HTTPS",
                    "Add a network security configuration that disallows cleartext for production domains",
                    "Never load cleartext content into a JavaScript-enabled WebView",
                    "Enforce TLS with certificate pinning for first-party endpoints",
                ],
            )
        )
        return findings

    @staticmethod
    def _network_security_dict(analysis_results: dict[str, Any]) -> dict | None:
        """Return the ``apk_overview.network_security`` dict, or None.

        This is the output of the per-domain NSC parser
        (``apk_overview/network_security.py``), which stores its results under
        the keys ``network_findings`` / ``network_summary``.
        """
        overview = analysis_results.get("apk_overview") if isinstance(analysis_results, dict) else None
        network_security = None
        if isinstance(overview, dict):
            network_security = overview.get("network_security")
        elif overview is not None:
            network_security = getattr(overview, "network_security", None)
        return network_security if isinstance(network_security, dict) else None

    def _nsc_restricts_cleartext(self, analysis_results: dict[str, Any]) -> bool:
        """Return True only with positive evidence that an NSC forbids cleartext.

        Consumes the per-domain NSC parser output stored under
        ``apk_overview.network_security.network_findings``. A base-config that
        disallows cleartext to all domains (a SECURE finding scoped to ``*`` with
        a "disallow clear text traffic to all domains" description) is treated as
        a global cleartext restriction. Absent such positive evidence the global
        ``usesCleartextTraffic="true"`` flag stands (deliberately conservative).
        """
        network_security = self._network_security_dict(analysis_results)
        if network_security is None:
            return False
        for finding in network_security.get("network_findings", []) or []:
            if not isinstance(finding, dict):
                continue
            scope = finding.get("scope") or []
            description = str(finding.get("description", "")).lower()
            if "*" in scope and "disallow clear text traffic to all domains" in description:
                return True
        return False

    # ------------------------------------------------------------------ #
    # Network-security-config `user` trust anchor (A05 - misconfiguration)
    # ------------------------------------------------------------------ #
    def _assess_nsc_user_trust_anchors(
        self, analysis_results: dict[str, Any], context: AnalysisContext | None
    ) -> list[SecurityFinding]:
        """Surface a network-security-config ``user`` trust anchor as an A05 finding.

        Trusting user-installed CA certificates (``<certificates src="user"/>``)
        weakens resistance to man-in-the-middle interception. Two independent
        sources are consulted and de-duplicated by (origin, scope):

        (a) the per-domain NSC parser output already stored under
            ``apk_overview.network_security.network_findings`` (apktool-dependent,
            only present when a decode ran), and
        (b) an androguard-based decode of ``res/xml/network_security_config.xml``
            (default-on; needs no apktool run — mirrors provider_paths).

        Findings are CONFIRMED because the anchor is read straight from the decoded
        XML. Base-config anchors (app-wide) are HIGH; domain-config anchors are
        MEDIUM; debug-overrides anchors are MEDIUM (they apply only to debuggable
        builds). Gates gracefully: when no NSC data is available, nothing fires.
        """
        anchors: dict[tuple[str, str], SecurityFinding] = {}
        try:
            for origin, scope_key in self._nsc_user_anchors_from_androguard(context):
                anchors.setdefault((origin, scope_key.lower()), self._build_user_trust_anchor_finding(origin, scope_key))
            for origin, scope_key in self._nsc_user_anchors_from_parser(analysis_results):
                anchors.setdefault((origin, scope_key.lower()), self._build_user_trust_anchor_finding(origin, scope_key))
        except Exception as e:  # never regress the whole assessment on a decode issue
            self.logger.debug(f"NSC user trust-anchor assessment skipped: {e}")
            return []
        return list(anchors.values())

    def _nsc_user_anchors_from_parser(self, analysis_results: dict[str, Any]):
        """Yield (origin, scope_key) user-trust-anchor entries from the NSC parser output."""
        network_security = self._network_security_dict(analysis_results)
        if network_security is None:
            return
        for finding in network_security.get("network_findings", []) or []:
            if not isinstance(finding, dict):
                continue
            description = str(finding.get("description", "")).lower()
            if "user installed certificates" not in description:
                continue
            scope = finding.get("scope") or []
            if "*" in scope:
                yield ("base-config", "*")
            else:
                domains = ", ".join(str(s) for s in scope if s)
                yield ("domain-config", domains or "(unspecified)")

    def _nsc_user_anchors_from_androguard(self, context: AnalysisContext | None):
        """Yield (origin, scope_key) user-trust-anchor entries via an androguard decode.

        Reads and decodes ``res/xml/network_security_config.xml`` directly, so it
        works without an apktool run. Any failure yields nothing.
        """
        if context is None or getattr(context, "androguard_obj", None) is None:
            return
        try:
            apk = context.androguard_obj.get_androguard_apk()
        except Exception:
            return
        if apk is None:
            return
        try:
            data = apk.get_file("res/xml/network_security_config.xml")
        except Exception:
            return
        if not data:
            return
        root = self._decode_nsc_xml(data)
        if root is None:
            return
        yield from self._scan_nsc_root(root)

    @staticmethod
    def _decode_nsc_xml(data: bytes):
        """Decode NSC bytes to an lxml root: compiled AXML via AXMLPrinter, else plain XML."""
        try:
            if data[:4] == _AXML_MAGIC:
                from androguard.core.axml import AXMLPrinter

                return AXMLPrinter(data).get_xml_obj()
            from lxml import etree

            return etree.fromstring(data)
        except Exception:
            return None

    @staticmethod
    def _nsc_localname(tag: Any) -> str:
        """Return the namespace-stripped local name of an lxml element tag."""
        if not isinstance(tag, str):
            return ""
        return tag.rsplit("}", 1)[-1]

    def _config_trusts_user_certs(self, config_element: Any) -> bool:
        """Return True when a config's DIRECT trust-anchors trust user certs.

        Only direct ``<trust-anchors>`` children are inspected so a nested
        ``<domain-config>`` cannot be misattributed to its parent (the nested one
        is scanned independently as its own element).
        """
        for child in config_element:
            if self._nsc_localname(child.tag) != "trust-anchors":
                continue
            for cert in child:
                if self._nsc_localname(cert.tag) == "certificates" and cert.get("src") == "user":
                    return True
        return False

    def _config_domains(self, config_element: Any) -> list[str]:
        """Return the domain names declared directly under a ``<domain-config>``."""
        domains: list[str] = []
        for child in config_element:
            if self._nsc_localname(child.tag) == "domain":
                text = (child.text or "").strip()
                if text:
                    domains.append(text)
        return domains

    def _scan_nsc_root(self, root: Any):
        """Yield (origin, scope_key) for every user trust anchor in an NSC tree."""
        for element in root.iter():
            tag = self._nsc_localname(element.tag)
            if tag == "base-config":
                if self._config_trusts_user_certs(element):
                    yield ("base-config", "*")
            elif tag == "domain-config":
                if self._config_trusts_user_certs(element):
                    domains = self._config_domains(element)
                    yield ("domain-config", ", ".join(domains) if domains else "(unspecified)")
            elif tag == "debug-overrides":
                if self._config_trusts_user_certs(element):
                    yield ("debug-overrides", "*")

    def _build_user_trust_anchor_finding(self, origin: str, scope_key: str) -> SecurityFinding:
        """Build one CONFIRMED A05 finding for a ``user`` trust anchor."""
        if origin == "base-config":
            severity = AnalysisSeverity.HIGH
            scope_desc = "all app traffic (base-config)"
            caveat = ""
        elif origin == "domain-config":
            severity = AnalysisSeverity.MEDIUM
            scope_desc = f"domains: {scope_key}"
            caveat = ""
        else:  # debug-overrides
            severity = AnalysisSeverity.MEDIUM
            scope_desc = "debug-overrides"
            caveat = (
                " This anchor lives under <debug-overrides>, so it is active only when the app is "
                "debuggable; it must never be relied upon in a release build."
            )

        return SecurityFinding(
            category=self.owasp_category,
            severity=severity,
            confidence=0.9,
            verification_status=VerificationStatus.CONFIRMED,
            title="Network Security Config Trusts User-Installed CA Certificates",
            description=(
                "The network security configuration declares a `user` trust anchor "
                "(<certificates src=\"user\"/>), so it trusts user-installed CA certificates for "
                f"{scope_desc}. This weakens resistance to man-in-the-middle interception: a user "
                "(or an attacker with device access) can install a CA and decrypt or modify the "
                "app's TLS traffic." + caveat
            ),
            evidence=[
                f"Trust-anchor scope: {scope_desc}",
                "network_security_config.xml: <trust-anchors><certificates src=\"user\"/></trust-anchors>",
            ],
            recommendations=[
                "Remove the `user` trust anchor and trust only the system CA store",
                "Pin certificates for first-party endpoints",
                "Confine any user-CA trust to debug builds via <debug-overrides>",
            ],
        )
