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

"""
Mobile-Specific Security Assessment.

This module implements OWASP Mobile Top 10 2016 security assessment.
It identifies mobile-specific security vulnerabilities unique to mobile platforms.
"""

import logging
import re
from typing import Any

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import register_assessment
from .evidence import collect_weak_crypto_evidence
from .evidence import list_sink_calls
from .evidence import looks_like_type_descriptor
from .evidence import matches_algorithm_token


@register_assessment("mobile_specific")
class MobileSpecificAssessment(BaseSecurityAssessment):
    """
    OWASP Mobile Top 10 2016 - Mobile-Specific Security Assessment.

    This assessment identifies mobile-specific security vulnerabilities that are
    unique to mobile platforms and not adequately covered by the traditional
    OWASP Top 10 web application security risks.

    Mobile-specific focus areas:
    - M1: Improper Platform Usage - Misuse of platform features or security controls
    - M2: Insecure Data Storage - Unintended data leakage to other apps, malware, or users
    - M3: Insecure Communication - Poor handshaking, incorrect SSL versions, weak negotiation
    - M4: Insecure Authentication - Failing to identify the user at all or inadequately identifying
    - M5: Insufficient Cryptography - Code that applies cryptography to sensitive information asset
    - M6: Insecure Authorization - Failures in authorization (different from authentication)
    - M7: Poor Code Quality - Code-level implementation problems in the mobile client
    - M8: Code Tampering - Binary patching, local resource modification, method hooking
    - M9: Reverse Engineering - Analysis of the final core binary to determine source code
    - M10: Extraneous Functionality - Hidden backdoor functionality or internal development features
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize mobile-specific security assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "OWASP Mobile Top 10"

        self._initialize_platform_and_storage_patterns()
        self._initialize_communication_and_auth_patterns()
        self._initialize_crypto_and_authorization_patterns()
        self._initialize_code_quality_and_tampering_patterns()
        self._initialize_extraneous_functionality_patterns()

    def _initialize_platform_and_storage_patterns(self):
        """Initialize M1 (Improper Platform Usage) and M2 (Insecure Data Storage) patterns."""
        # M1: Improper Platform Usage patterns
        self.platform_misuse_patterns = {
            "permissions": [
                r"android\.permission\.WRITE_EXTERNAL_STORAGE",
                r"android\.permission\.ACCESS_FINE_LOCATION",
                r"android\.permission\.CAMERA",
                r"android\.permission\.RECORD_AUDIO",
                r"android\.permission\.READ_CONTACTS",
                r"android\.permission\.SEND_SMS",
            ],
            "webview_issues": [
                r"setJavaScriptEnabled\(true\)",
                r"setAllowFileAccess\(true\)",
                r"setAllowContentAccess\(true\)",
                r"setAllowUniversalAccessFromFileURLs\(true\)",
                r"addJavaScriptInterface\(",
            ],
            "intent_issues": [r"Intent\.ACTION_SEND", r"startActivityForResult\(", r"setResult\(RESULT_OK"],
        }

        # M2: Insecure Data Storage patterns
        self.insecure_storage_patterns = {
            "shared_preferences": [
                r"SharedPreferences.*putString.*(?:password|token|key|secret)",
                r"PreferenceManager\.getDefaultSharedPreferences",
                r"MODE_WORLD_READABLE",
                r"MODE_WORLD_WRITABLE",
            ],
            "external_storage": [
                r"Environment\.getExternalStorageDirectory\(",
                r"getExternalFilesDir\(",
                r"File\(.*getExternalStorageDirectory\(",
                r"openFileOutput\(.*MODE_WORLD_READABLE",
            ],
            "database_issues": [r"SQLiteDatabase.*execSQL\(", r"rawQuery\(", r"SQLiteOpenHelper", r"ContentProvider"],
        }

    def _initialize_communication_and_auth_patterns(self):
        """Initialize M3 (Insecure Communication) and M4 (Insecure Authentication) patterns."""
        # M3: Insecure Communication patterns
        self.insecure_communication_patterns = {
            "ssl_issues": [
                r"TrustAllCerts",
                r"X509TrustManager.*checkServerTrusted\(\)\s*\{\s*\}",
                r"HostnameVerifier.*verify\(\)\s*\{\s*return\s+true",
                r'SSLContext\.getInstance\("SSL"\)',
                r"setHostnameVerifier\(.*ALLOW_ALL",
            ],
            "cleartext_traffic": [
                r"http://(?!localhost|127\.0\.0\.1)",
                r'android:usesCleartextTraffic="true"',
                r"HttpURLConnection",
                r"DefaultHttpClient",
            ],
            "weak_protocols": [r"SSLv3", r"TLSv1\.0", r"TLSv1\.1", r"SSL_.*_WITH_.*_NULL_"],
        }

        # M4: Insecure Authentication patterns (mobile-specific)
        self.mobile_auth_patterns = {
            "weak_local_auth": [
                r"SharedPreferences.*getString.*password",
                r"if\s*\(.*password.*equals\(",
                r'String.*password.*=.*"[^"]*"',
                r"hardcoded.*(?:password|pin|passcode)",
            ],
            "biometric_issues": [r"FingerprintManager", r"BiometricPrompt", r"KeyguardManager\.isKeyguardSecure\(\)"],
            "session_handling": [r"SessionManager", r"session.*timeout", r"remember.*login"],
        }

    def _initialize_crypto_and_authorization_patterns(self):
        """Initialize M5 (Insufficient Cryptography) and M6 (Insecure Authorization) patterns."""
        # M5: Insufficient Cryptography patterns
        self.crypto_patterns = {
            "weak_algorithms": [
                r'Cipher\.getInstance\("DES',
                r'Cipher\.getInstance\("RC4',
                r'Cipher\.getInstance\("MD5',
                r'MessageDigest\.getInstance\("MD5"',
                r'MessageDigest\.getInstance\("SHA1"',
                r'KeyGenerator\.getInstance\("DES"',
            ],
            "weak_key_generation": [
                r"SecureRandom\(\)\.setSeed\(",
                r"Random\(\)\.nextInt\(",
                r"Math\.random\(",
                r"System\.currentTimeMillis\(\).*seed",
            ],
            "hardcoded_keys": [
                r"byte\[\]\s+key\s*=\s*\{[^}]*\}",
                r'String\s+.*(?:key|secret|password)\s*=\s*"[A-Za-z0-9+/=]{16,}"',
                r'private\s+static\s+final\s+String.*KEY.*=.*"[^"]*"',
            ],
        }

        # M6: Insecure Authorization patterns
        self.authorization_patterns = {
            "permission_bypass": [
                r"checkCallingPermission\(",
                r"checkSelfPermission\(",
                r"PermissionChecker\.checkSelfPermission",
            ],
            "privilege_escalation": [
                r"su\s+",
                r"Runtime\.getRuntime\(\)\.exec\(",
                r"ProcessBuilder",
                r"android\.intent\.action\.CALL",
            ],
        }

    def _initialize_code_quality_and_tampering_patterns(self):
        """Initialize M7 (Poor Code Quality), M8 (Code Tampering), and M9 (Reverse Engineering) patterns."""
        # M7: Poor Code Quality patterns
        self.code_quality_patterns = {
            "buffer_overflows": [r"strcpy\(", r"strcat\(", r"sprintf\(", r"gets\("],
            "memory_corruption": [r"malloc\(", r"free\(", r"memcpy\(", r"strcpy\("],
            "format_string_bugs": [r"printf\([^,)]*\)", r"sprintf\([^,)]*\)", r"fprintf\([^,)]*\)"],
        }

        # M8: Code Tampering protection patterns
        self.anti_tampering_patterns = [
            "checksum",
            "signature.*verification",
            "integrity.*check",
            "tamper.*detection",
            "root.*detection",
            "frida.*detection",
            "xposed.*detection",
        ]

        # M9: Reverse Engineering protection patterns
        self.anti_reverse_patterns = [
            "obfuscat",
            "proguard",
            "dexguard",
            "string.*encrypt",
            "native.*protection",
            "anti.*debug",
            "ptrace",
        ]

    def _initialize_extraneous_functionality_patterns(self):
        """Initialize M10 (Extraneous Functionality) patterns."""
        # M10: Extraneous Functionality patterns
        self.extraneous_functionality_patterns = {
            "debug_features": [
                r"Log\.d\(",
                r"Log\.v\(",
                r"System\.out\.println\(",
                r"printStackTrace\(\)",
                r"BuildConfig\.DEBUG",
                r'android:debuggable="true"',
            ],
            "test_features": [r"test.*endpoint", r"debug.*mode", r"admin.*panel", r"backdoor", r"internal.*api"],
            "development_features": [r"developer.*options", r"staging.*environment", r"test.*user", r"mock.*data"],
        }

    def assess(self, analysis_results: dict[str, Any], context: AnalysisContext | None = None) -> list[SecurityFinding]:
        """
        Assess for mobile-specific security vulnerabilities.

        Args:
            analysis_results: Combined results from all analysis modules

        Returns:
            List of security findings related to mobile-specific vulnerabilities
        """
        findings = []

        try:
            # M1: Improper Platform Usage
            platform_findings = self._assess_improper_platform_usage(analysis_results)
            findings.extend(platform_findings)

            # M2: Insecure Data Storage
            storage_findings = self._assess_insecure_data_storage(analysis_results)
            findings.extend(storage_findings)

            # M3: Insecure Communication
            communication_findings = self._assess_insecure_communication(analysis_results)
            findings.extend(communication_findings)

            # M4: Insecure Authentication (Mobile-specific)
            auth_findings = self._assess_mobile_authentication(analysis_results)
            findings.extend(auth_findings)

            # M5: Insufficient Cryptography
            crypto_findings = self._assess_insufficient_cryptography(analysis_results)
            findings.extend(crypto_findings)

            # M6: Insecure Authorization
            authz_findings = self._assess_insecure_authorization(analysis_results)
            findings.extend(authz_findings)

            # M7: Poor Code Quality
            quality_findings = self._assess_code_quality(analysis_results)
            findings.extend(quality_findings)

            # M8: Code Tampering
            tampering_findings = self._assess_code_tampering_protection(analysis_results)
            findings.extend(tampering_findings)

            # M9: Reverse Engineering
            reverse_findings = self._assess_reverse_engineering_protection(analysis_results)
            findings.extend(reverse_findings)

            # M10: Extraneous Functionality
            extraneous_findings = self._assess_extraneous_functionality(analysis_results)
            findings.extend(extraneous_findings)

        except Exception as e:
            self.logger.error(f"Mobile-specific assessment failed: {str(e)}")

        return findings

    def _assess_improper_platform_usage(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """M1: Assess improper platform usage."""
        findings = []

        # Check manifest for permission issues
        manifest_results = analysis_results.get("manifest_analysis", {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, "to_dict") else manifest_results
        permissions = manifest_data.get("permissions", [])
        exported_components = manifest_data.get("exported_components", [])

        platform_issues = []

        # Check for dangerous permissions without proper justification
        dangerous_permissions = [
            p for p in permissions if any(pattern in p for pattern in self.platform_misuse_patterns["permissions"])
        ]
        if dangerous_permissions:
            platform_issues.extend([f"Dangerous permission: {perm}" for perm in dangerous_permissions[:5]])

        # Check for exported components that might be vulnerable
        if exported_components:
            platform_issues.extend([f"Exported component: {comp}" for comp in exported_components[:3]])

        # Check string analysis for WebView misuse
        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        webview_issues = []
        for string in all_strings:
            if isinstance(string, str):
                for pattern in self.platform_misuse_patterns["webview_issues"]:
                    if re.search(pattern, string):
                        webview_issues.append(f"WebView security issue: {string[:60]}...")
                        break

        if webview_issues:
            platform_issues.extend(webview_issues[:3])

        if platform_issues:
            findings.append(
                SecurityFinding(
                    category=f"{self.owasp_category} - M1",
                    severity=AnalysisSeverity.HIGH,
                    title="Improper Platform Usage",
                    description="Application misuses platform features or fails to use platform security controls properly.",
                    evidence=platform_issues,
                    recommendations=[
                        "Request only necessary permissions and justify dangerous permissions",
                        "Secure WebView configurations by disabling unnecessary features",
                        "Validate input and output for exported components",
                        "Use platform security controls appropriately",
                        "Follow Android security best practices for component exposure",
                    ],
                )
            )

        return findings

    def _assess_insecure_data_storage(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """M2: Assess insecure data storage."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])
        if not isinstance(all_strings, list):
            all_strings = []

        storage_issues = []

        # World-readable/writable file modes are the genuinely dangerous storage
        # signals - match them as whole-word tokens, not bare substrings, and skip
        # type descriptors (e.g. Compose/media class names) entirely.
        world_mode_tokens = ("MODE_WORLD_READABLE", "MODE_WORLD_WRITABLE")
        for string in all_strings:
            if not isinstance(string, str) or looks_like_type_descriptor(string):
                continue
            for token in world_mode_tokens:
                if matches_algorithm_token(string, token):
                    storage_issues.append(f"World-accessible storage mode: {string[:70]}")
                    break
            # SharedPreferences persisting a secret needs both the API and a secret
            # keyword in the same string - a real, specific pattern.
            if matches_algorithm_token(string, "putString") and any(
                matches_algorithm_token(string, kw) for kw in ("password", "token", "secret", "apikey")
            ):
                storage_issues.append(f"Secret stored in preferences: {string[:70]}")

        # A real SQLite write/query API sink is stronger evidence than a substring.
        for call in list_sink_calls(analysis_results, "sql"):
            storage_issues.append(
                f"SQLite data access: {call.get('called_class', '')}.{call.get('called_method', '')}"
            )

        if storage_issues:
            findings.append(
                SecurityFinding(
                    category=f"{self.owasp_category} - M2",
                    severity=AnalysisSeverity.HIGH,
                    title="Insecure Data Storage",
                    description="Application stores sensitive data insecurely, making it accessible to other applications or unauthorized users.",
                    evidence=storage_issues[:8],
                    confidence=0.7,
                    recommendations=[
                        "Use Android Keystore for sensitive data storage",
                        "Avoid storing sensitive data in SharedPreferences without encryption",
                        "Use internal storage instead of external storage for sensitive files",
                        "Implement proper file permissions and access controls",
                        "Encrypt sensitive data before storage using strong encryption",
                    ],
                )
            )

        return findings

    def _assess_insecure_communication(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """M3: Assess insecure communication."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])
        urls = string_data.get("urls", [])

        if not isinstance(all_strings, list):
            all_strings = []
        if not isinstance(urls, list):
            urls = []

        communication_issues = []

        # Check for cleartext HTTP URLs (real evidence from extracted URLs).
        cleartext_urls = [
            url
            for url in urls
            if isinstance(url, str)
            and url.startswith("http://")
            and not any(local in url for local in ["localhost", "127.0.0.1", "10.0.2.2"])
        ]
        if cleartext_urls:
            communication_issues.extend([f"Cleartext URL: {url}" for url in cleartext_urls[:3]])

        # Only genuinely dangerous TLS patterns count. Bare "HttpURLConnection" /
        # "DefaultHttpClient" substrings are present in most apps and are dropped;
        # weak-protocol names are matched as whole-word tokens, not substrings.
        trust_bypass_patterns = self.insecure_communication_patterns["ssl_issues"]
        weak_protocol_tokens = ("SSLv3", "TLSv1.0", "TLSv1.1")
        for string in all_strings:
            if not isinstance(string, str) or looks_like_type_descriptor(string):
                continue
            for pattern in trust_bypass_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    communication_issues.append(f"SSL/TLS trust bypass: {string[:60]}")
                    break
            for token in weak_protocol_tokens:
                if matches_algorithm_token(string, token):
                    communication_issues.append(f"Weak TLS protocol reference: {string[:60]}")
                    break

        if communication_issues:
            findings.append(
                SecurityFinding(
                    category=f"{self.owasp_category} - M3",
                    severity=AnalysisSeverity.HIGH,
                    title="Insecure Communication",
                    description="Application uses insecure communication channels or improperly implements SSL/TLS security.",
                    evidence=communication_issues[:8],
                    confidence=0.7,
                    recommendations=[
                        "Use HTTPS for all network communications",
                        "Implement certificate pinning for critical connections",
                        "Use strong SSL/TLS configurations and avoid weak protocols",
                        "Validate SSL certificates properly without bypassing checks",
                        "Set network security config to block cleartext traffic",
                    ],
                )
            )

        return findings

    def _assess_mobile_authentication(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """M4: Assess mobile-specific authentication issues."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        auth_issues = []

        # Check for weak local authentication
        for string in all_strings:
            if isinstance(string, str):
                for category, patterns in self.mobile_auth_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, string, re.IGNORECASE):
                            auth_issues.append(f"Authentication issue ({category}): {string[:60]}...")
                            break

        # Check manifest for biometric permissions
        manifest_results = analysis_results.get("manifest_analysis", {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, "to_dict") else manifest_results
        permissions = manifest_data.get("permissions", [])

        has_biometric = any("FINGERPRINT" in p or "BIOMETRIC" in p for p in permissions)
        if has_biometric:
            auth_issues.append("Biometric authentication implemented - verify secure usage")

        if auth_issues:
            findings.append(
                SecurityFinding(
                    category=f"{self.owasp_category} - M4",
                    severity=AnalysisSeverity.MEDIUM,
                    title="Insecure Mobile Authentication",
                    description="Application implements authentication mechanisms that are insufficient for mobile security requirements.",
                    evidence=auth_issues[:6],
                    recommendations=[
                        "Implement strong local authentication using Android Keystore",
                        "Use biometric authentication for sensitive operations",
                        "Avoid hardcoded credentials and weak password policies",
                        "Implement proper session management with timeout",
                        "Use multi-factor authentication where appropriate",
                    ],
                )
            )

        return findings

    def _assess_insufficient_cryptography(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """M5: Assess insufficient cryptography."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])
        if not isinstance(all_strings, list):
            all_strings = []

        crypto_issues = collect_weak_crypto_evidence(analysis_results, all_strings)

        if crypto_issues:
            findings.append(
                SecurityFinding(
                    category=f"{self.owasp_category} - M5",
                    severity=AnalysisSeverity.HIGH,
                    title="Insufficient Cryptography",
                    description="Application uses weak cryptographic algorithms, implementations, or key management practices.",
                    evidence=crypto_issues[:8],
                    confidence=0.7,
                    recommendations=[
                        "Use strong cryptographic algorithms (AES-256, RSA-2048+, SHA-256+)",
                        "Implement proper key management using Android Keystore",
                        "Use cryptographically secure random number generation",
                        "Avoid hardcoded cryptographic keys and secrets",
                        "Follow cryptographic best practices and standards",
                    ],
                )
            )

        return findings

    def _assess_insecure_authorization(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """M6: Assess insecure authorization."""
        """M6: Assess insecure authorization"""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        authz_issues = []

        # Check for authorization bypass patterns
        for string in all_strings:
            if isinstance(string, str):
                for category, patterns in self.authorization_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, string):
                            authz_issues.append(f"Authorization issue ({category}): {string[:60]}...")
                            break

        if authz_issues:
            findings.append(
                SecurityFinding(
                    category=f"{self.owasp_category} - M6",
                    severity=AnalysisSeverity.MEDIUM,
                    title="Insecure Authorization",
                    description="Application fails to properly verify user authorization for accessing sensitive functionality or data.",
                    evidence=authz_issues[:6],
                    recommendations=[
                        "Implement proper permission checking before sensitive operations",
                        "Use role-based access control where appropriate",
                        "Validate user authorization on both client and server side",
                        "Avoid privilege escalation vulnerabilities",
                        "Follow principle of least privilege",
                    ],
                )
            )

        return findings

    def _assess_code_quality(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """M7: Assess poor code quality."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        quality_issues = []

        # Check for code quality issues that could lead to security vulnerabilities
        for string in all_strings:
            if isinstance(string, str):
                for category, patterns in self.code_quality_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, string):
                            quality_issues.append(f"Code quality issue ({category}): {string[:60]}...")
                            break

        if quality_issues:
            findings.append(
                SecurityFinding(
                    category=f"{self.owasp_category} - M7",
                    severity=AnalysisSeverity.MEDIUM,
                    title="Poor Code Quality",
                    description="Application contains code quality issues that could lead to security vulnerabilities.",
                    evidence=quality_issues[:6],
                    recommendations=[
                        "Use secure coding practices and avoid dangerous functions",
                        "Implement proper input validation and sanitization",
                        "Use static analysis tools to identify code quality issues",
                        "Follow secure development lifecycle practices",
                        "Regular code reviews focusing on security aspects",
                    ],
                )
            )

        return findings

    def _assess_code_tampering_protection(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """M8 + M9: Report tampering / reverse-engineering hardening posture.

        Previously M8 and M9 each emitted their own LOW finding asserting the app
        had "no protection" whenever the literal marker strings were absent. That
        is backwards for obfuscated apps (which strip the literal ``proguard`` /
        ``obfuscat`` strings precisely because they ARE obfuscated). Both checks
        are now folded into a single low-confidence posture note that reports the
        *absence of explicit markers* rather than asserting the app is unprotected.
        M9 (:meth:`_assess_reverse_engineering_protection`) is retained but folded
        in here to avoid emitting a second, contradictory finding.
        """
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])
        if not isinstance(all_strings, list):
            all_strings = []

        has_anti_tampering = any(
            any(pattern.lower() in s.lower() for pattern in self.anti_tampering_patterns)
            for s in all_strings
            if isinstance(s, str)
        )
        has_reverse_markers = any(
            any(pattern.lower() in s.lower() for pattern in self.anti_reverse_patterns)
            for s in all_strings
            if isinstance(s, str)
        )

        posture_notes = []
        if not has_anti_tampering:
            posture_notes.append("No explicit anti-tampering markers found (checksum/root/tamper detection)")
        if not has_reverse_markers:
            posture_notes.append(
                "No explicit anti-reverse-engineering markers found. Note: absence of these markers does "
                "not prove the app is unobfuscated - obfuscated apps typically strip such literals."
            )

        if posture_notes:
            findings.append(
                SecurityFinding(
                    category=f"{self.owasp_category} - M8/M9",
                    severity=AnalysisSeverity.LOW,
                    title="Tampering & Reverse-Engineering Hardening Posture",
                    description=(
                        "Informational: no explicit anti-tampering or anti-reverse-engineering markers were "
                        "detected. This is a posture note, not a confirmed weakness - marker absence is not "
                        "proof that the protections are missing."
                    ),
                    evidence=posture_notes,
                    confidence=0.2,
                    recommendations=[
                        "Implement runtime application self-protection (RASP)",
                        "Add checksum verification for critical application components",
                        "Implement root/jailbreak detection where appropriate",
                        "Use code obfuscation (ProGuard/DexGuard) and string encryption",
                        "Consider anti-debugging and anti-hooking measures for sensitive applications",
                    ],
                )
            )

        return findings

    def _assess_reverse_engineering_protection(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """M9: Reverse-engineering posture.

        Folded into :meth:`_assess_code_tampering_protection` (M8/M9 combined
        posture) to avoid emitting a second, contradictory absence-based finding.
        Retained as a no-op so the assessment surface is not removed.
        """
        return []

    def _assess_extraneous_functionality(self, analysis_results: dict[str, Any]) -> list[SecurityFinding]:
        """M10: Assess extraneous functionality."""
        findings = []

        string_results = analysis_results.get("string_analysis", {})
        string_data = string_results.to_dict() if hasattr(string_results, "to_dict") else string_results
        all_strings = string_data.get("all_strings", [])

        # Check manifest for debug flags
        manifest_results = analysis_results.get("manifest_analysis", {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, "to_dict") else manifest_results

        extraneous_issues = []

        # Check for debug features in production
        debug_enabled = manifest_data.get("debuggable", False)
        if debug_enabled:
            extraneous_issues.append("Application has android:debuggable=true")

        # Check for development and test functionality
        for string in all_strings:
            if isinstance(string, str):
                for category, patterns in self.extraneous_functionality_patterns.items():
                    for pattern in patterns:
                        try:
                            if re.search(pattern, string, re.IGNORECASE):
                                extraneous_issues.append(f"Extraneous functionality ({category}): {string[:60]}...")
                                break
                        except Exception as e:
                            self.logger.debug(f"Regex pattern error for pattern '{pattern}': {e}")
                            continue

        if extraneous_issues:
            findings.append(
                SecurityFinding(
                    category=f"{self.owasp_category} - M10",
                    severity=AnalysisSeverity.MEDIUM,
                    title="Extraneous Functionality",
                    description="Application contains hidden backdoor functionality or internal development features that could be exploited.",
                    evidence=extraneous_issues[:8],
                    recommendations=[
                        "Remove debug and development code from production builds",
                        "Disable debug flags and testing features in release builds",
                        "Implement proper build configurations for different environments",
                        "Use build-time feature flags to exclude development functionality",
                        "Regular security testing to identify hidden functionality",
                    ],
                )
            )

        return findings
