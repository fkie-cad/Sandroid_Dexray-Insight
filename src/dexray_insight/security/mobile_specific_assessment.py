#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import List, Dict, Any
import re

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment


@register_assessment('mobile_specific')
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
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "OWASP Mobile Top 10"
        
        # M1: Improper Platform Usage patterns
        self.platform_misuse_patterns = {
            'permissions': [
                r'android\.permission\.WRITE_EXTERNAL_STORAGE',
                r'android\.permission\.ACCESS_FINE_LOCATION',
                r'android\.permission\.CAMERA',
                r'android\.permission\.RECORD_AUDIO',
                r'android\.permission\.READ_CONTACTS',
                r'android\.permission\.SEND_SMS'
            ],
            'webview_issues': [
                r'setJavaScriptEnabled\(true\)',
                r'setAllowFileAccess\(true\)',
                r'setAllowContentAccess\(true\)',
                r'setAllowUniversalAccessFromFileURLs\(true\)',
                r'addJavaScriptInterface\('
            ],
            'intent_issues': [
                r'Intent\.ACTION_SEND',
                r'startActivityForResult\(',
                r'setResult\(RESULT_OK'
            ]
        }
        
        # M2: Insecure Data Storage patterns
        self.insecure_storage_patterns = {
            'shared_preferences': [
                r'SharedPreferences.*putString.*(?:password|token|key|secret)',
                r'PreferenceManager\.getDefaultSharedPreferences',
                r'MODE_WORLD_READABLE',
                r'MODE_WORLD_WRITABLE'
            ],
            'external_storage': [
                r'Environment\.getExternalStorageDirectory\(',
                r'getExternalFilesDir\(',
                r'File\(.*getExternalStorageDirectory\(',
                r'openFileOutput\(.*MODE_WORLD_READABLE'
            ],
            'database_issues': [
                r'SQLiteDatabase.*execSQL\(',
                r'rawQuery\(',
                r'SQLiteOpenHelper',
                r'ContentProvider'
            ]
        }
        
        # M3: Insecure Communication patterns
        self.insecure_communication_patterns = {
            'ssl_issues': [
                r'TrustAllCerts',
                r'X509TrustManager.*checkServerTrusted\(\)\s*\{\s*\}',
                r'HostnameVerifier.*verify\(\)\s*\{\s*return\s+true',
                r'SSLContext\.getInstance\("SSL"\)',
                r'setHostnameVerifier\(.*ALLOW_ALL'
            ],
            'cleartext_traffic': [
                r'http://(?!localhost|127\.0\.0\.1)',
                r'android:usesCleartextTraffic="true"',
                r'HttpURLConnection',
                r'DefaultHttpClient'
            ],
            'weak_protocols': [
                r'SSLv3',
                r'TLSv1\.0',
                r'TLSv1\.1',
                r'SSL_.*_WITH_.*_NULL_'
            ]
        }
        
        # M4: Insecure Authentication patterns (mobile-specific)
        self.mobile_auth_patterns = {
            'weak_local_auth': [
                r'SharedPreferences.*getString.*password',
                r'if\s*\(.*password.*equals\(',
                r'String.*password.*=.*"[^"]*"',
                r'hardcoded.*(?:password|pin|passcode)'
            ],
            'biometric_issues': [
                r'FingerprintManager',
                r'BiometricPrompt',
                r'KeyguardManager\.isKeyguardSecure\(\)'
            ],
            'session_handling': [
                r'SessionManager',
                r'session.*timeout',
                r'remember.*login'
            ]
        }
        
        # M5: Insufficient Cryptography patterns
        self.crypto_patterns = {
            'weak_algorithms': [
                r'Cipher\.getInstance\("DES',
                r'Cipher\.getInstance\("RC4',
                r'Cipher\.getInstance\("MD5',
                r'MessageDigest\.getInstance\("MD5"',
                r'MessageDigest\.getInstance\("SHA1"',
                r'KeyGenerator\.getInstance\("DES"'
            ],
            'weak_key_generation': [
                r'SecureRandom\(\)\.setSeed\(',
                r'Random\(\)\.nextInt\(',
                r'Math\.random\(',
                r'System\.currentTimeMillis\(\).*seed'
            ],
            'hardcoded_keys': [
                r'byte\[\]\s+key\s*=\s*\{[^}]*\}',
                r'String\s+.*(?:key|secret|password)\s*=\s*"[A-Za-z0-9+/=]{16,}"',
                r'private\s+static\s+final\s+String.*KEY.*=.*"[^"]*"'
            ]
        }
        
        # M6: Insecure Authorization patterns
        self.authorization_patterns = {
            'permission_bypass': [
                r'checkCallingPermission\(',
                r'checkSelfPermission\(',
                r'PermissionChecker\.checkSelfPermission'
            ],
            'privilege_escalation': [
                r'su\s+',
                r'Runtime\.getRuntime\(\)\.exec\(',
                r'ProcessBuilder',
                r'android\.intent\.action\.CALL'
            ]
        }
        
        # M7: Poor Code Quality patterns
        self.code_quality_patterns = {
            'buffer_overflows': [
                r'strcpy\(',
                r'strcat\(',
                r'sprintf\(',
                r'gets\('
            ],
            'memory_corruption': [
                r'malloc\(',
                r'free\(',
                r'memcpy\(',
                r'strcpy\('
            ],
            'format_string_bugs': [
                r'printf\([^,)]*\)',
                r'sprintf\([^,)]*\)',
                r'fprintf\([^,)]*\)'
            ]
        }
        
        # M8: Code Tampering protection patterns
        self.anti_tampering_patterns = [
            'checksum',
            'signature.*verification',
            'integrity.*check',
            'tamper.*detection',
            'root.*detection',
            'frida.*detection',
            'xposed.*detection'
        ]
        
        # M9: Reverse Engineering protection patterns
        self.anti_reverse_patterns = [
            'obfuscat',
            'proguard',
            'dexguard',
            'string.*encrypt',
            'native.*protection',
            'anti.*debug',
            'ptrace'
        ]
        
        # M10: Extraneous Functionality patterns
        self.extraneous_functionality_patterns = {
            'debug_features': [
                r'Log\.d\(',
                r'Log\.v\(',
                r'System\.out\.println\(',
                r'printStackTrace\(\)',
                r'BuildConfig\.DEBUG',
                r'android:debuggable="true"'
            ],
            'test_features': [
                r'test.*endpoint',
                r'debug.*mode',
                r'admin.*panel',
                r'backdoor',
                r'internal.*api'
            ],
            'development_features': [
                r'developer.*options',
                r'staging.*environment',
                r'test.*user',
                r'mock.*data'
            ]
        }
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
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
    
    def _assess_improper_platform_usage(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """M1: Assess improper platform usage"""
        findings = []
        
        # Check manifest for permission issues
        manifest_results = analysis_results.get('manifest_analysis', {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, 'to_dict') else manifest_results
        permissions = manifest_data.get('permissions', [])
        exported_components = manifest_data.get('exported_components', [])
        
        platform_issues = []
        
        # Check for dangerous permissions without proper justification
        dangerous_permissions = [p for p in permissions if any(pattern in p for pattern in self.platform_misuse_patterns['permissions'])]
        if dangerous_permissions:
            platform_issues.extend([f"Dangerous permission: {perm}" for perm in dangerous_permissions[:5]])
        
        # Check for exported components that might be vulnerable
        if exported_components:
            platform_issues.extend([f"Exported component: {comp}" for comp in exported_components[:3]])
        
        # Check string analysis for WebView misuse
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        webview_issues = []
        for string in all_strings:
            if isinstance(string, str):
                for pattern in self.platform_misuse_patterns['webview_issues']:
                    if re.search(pattern, string):
                        webview_issues.append(f"WebView security issue: {string[:60]}...")
                        break
        
        if webview_issues:
            platform_issues.extend(webview_issues[:3])
        
        if platform_issues:
            findings.append(SecurityFinding(
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
                    "Follow Android security best practices for component exposure"
                ]
            ))
        
        return findings
    
    def _assess_insecure_data_storage(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """M2: Assess insecure data storage"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        storage_issues = []
        
        # Check for insecure SharedPreferences usage
        for string in all_strings:
            if isinstance(string, str):
                for category, patterns in self.insecure_storage_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, string, re.IGNORECASE):
                            storage_issues.append(f"Insecure {category}: {string[:70]}...")
                            break
        
        if storage_issues:
            findings.append(SecurityFinding(
                category=f"{self.owasp_category} - M2",
                severity=AnalysisSeverity.HIGH,
                title="Insecure Data Storage",
                description="Application stores sensitive data insecurely, making it accessible to other applications or unauthorized users.",
                evidence=storage_issues[:8],
                recommendations=[
                    "Use Android Keystore for sensitive data storage",
                    "Avoid storing sensitive data in SharedPreferences without encryption",
                    "Use internal storage instead of external storage for sensitive files",
                    "Implement proper file permissions and access controls",
                    "Encrypt sensitive data before storage using strong encryption"
                ]
            ))
        
        return findings
    
    def _assess_insecure_communication(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """M3: Assess insecure communication"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        urls = string_data.get('urls', [])
        
        communication_issues = []
        
        # Check for cleartext HTTP URLs
        cleartext_urls = [url for url in urls if url.startswith('http://') and not any(local in url for local in ['localhost', '127.0.0.1', '10.0.2.2'])]
        if cleartext_urls:
            communication_issues.extend([f"Cleartext URL: {url}" for url in cleartext_urls[:3]])
        
        # Check for SSL/TLS issues in code
        for string in all_strings:
            if isinstance(string, str):
                for category, patterns in self.insecure_communication_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, string, re.IGNORECASE):
                            communication_issues.append(f"SSL/TLS issue ({category}): {string[:60]}...")
                            break
        
        if communication_issues:
            findings.append(SecurityFinding(
                category=f"{self.owasp_category} - M3",
                severity=AnalysisSeverity.HIGH,
                title="Insecure Communication",
                description="Application uses insecure communication channels or improperly implements SSL/TLS security.",
                evidence=communication_issues[:8],
                recommendations=[
                    "Use HTTPS for all network communications",
                    "Implement certificate pinning for critical connections",
                    "Use strong SSL/TLS configurations and avoid weak protocols",
                    "Validate SSL certificates properly without bypassing checks",
                    "Set network security config to block cleartext traffic"
                ]
            ))
        
        return findings
    
    def _assess_mobile_authentication(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """M4: Assess mobile-specific authentication issues"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
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
        manifest_results = analysis_results.get('manifest_analysis', {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, 'to_dict') else manifest_results
        permissions = manifest_data.get('permissions', [])
        
        has_biometric = any('FINGERPRINT' in p or 'BIOMETRIC' in p for p in permissions)
        if has_biometric:
            auth_issues.append("Biometric authentication implemented - verify secure usage")
        
        if auth_issues:
            findings.append(SecurityFinding(
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
                    "Use multi-factor authentication where appropriate"
                ]
            ))
        
        return findings
    
    def _assess_insufficient_cryptography(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """M5: Assess insufficient cryptography"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        crypto_issues = []
        
        # Check for weak cryptographic implementations
        for string in all_strings:
            if isinstance(string, str):
                for category, patterns in self.crypto_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, string):
                            crypto_issues.append(f"Cryptography issue ({category}): {string[:70]}...")
                            break
        
        if crypto_issues:
            findings.append(SecurityFinding(
                category=f"{self.owasp_category} - M5",
                severity=AnalysisSeverity.HIGH,
                title="Insufficient Cryptography",
                description="Application uses weak cryptographic algorithms, implementations, or key management practices.",
                evidence=crypto_issues[:8],
                recommendations=[
                    "Use strong cryptographic algorithms (AES-256, RSA-2048+, SHA-256+)",
                    "Implement proper key management using Android Keystore",
                    "Use cryptographically secure random number generation",
                    "Avoid hardcoded cryptographic keys and secrets",
                    "Follow cryptographic best practices and standards"
                ]
            ))
        
        return findings
    
    def _assess_insecure_authorization(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """M6: Assess insecure authorization"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
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
            findings.append(SecurityFinding(
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
                    "Follow principle of least privilege"
                ]
            ))
        
        return findings
    
    def _assess_code_quality(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """M7: Assess poor code quality"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
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
            findings.append(SecurityFinding(
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
                    "Regular code reviews focusing on security aspects"
                ]
            ))
        
        return findings
    
    def _assess_code_tampering_protection(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """M8: Assess code tampering protection"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        # Check for anti-tampering measures
        has_anti_tampering = any(
            any(pattern.lower() in s.lower() for pattern in self.anti_tampering_patterns)
            for s in all_strings if isinstance(s, str)
        )
        
        if not has_anti_tampering:
            findings.append(SecurityFinding(
                category=f"{self.owasp_category} - M8",
                severity=AnalysisSeverity.LOW,
                title="Insufficient Code Tampering Protection",
                description="Application lacks adequate protection against code tampering and runtime manipulation.",
                evidence=["No anti-tampering mechanisms detected"],
                recommendations=[
                    "Implement runtime application self-protection (RASP)",
                    "Add checksum verification for critical application components",
                    "Implement root/jailbreak detection where appropriate",
                    "Use signature verification to detect unauthorized modifications",
                    "Consider anti-debugging and anti-hooking measures for sensitive applications"
                ]
            ))
        
        return findings
    
    def _assess_reverse_engineering_protection(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """M9: Assess reverse engineering protection"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        # Check for obfuscation and anti-reverse engineering measures
        has_protection = any(
            any(pattern.lower() in s.lower() for pattern in self.anti_reverse_patterns)
            for s in all_strings if isinstance(s, str)
        )
        
        if not has_protection:
            findings.append(SecurityFinding(
                category=f"{self.owasp_category} - M9",
                severity=AnalysisSeverity.LOW,
                title="Insufficient Reverse Engineering Protection",
                description="Application lacks adequate protection against reverse engineering and code analysis.",
                evidence=["No code obfuscation or anti-reverse engineering measures detected"],
                recommendations=[
                    "Implement code obfuscation using tools like ProGuard or DexGuard",
                    "Use string encryption for sensitive strings and constants",
                    "Consider native code implementation for critical algorithms",
                    "Implement anti-debugging measures where appropriate",
                    "Use control flow obfuscation for sensitive code paths"
                ]
            ))
        
        return findings
    
    def _assess_extraneous_functionality(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """M10: Assess extraneous functionality"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        # Check manifest for debug flags
        manifest_results = analysis_results.get('manifest_analysis', {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, 'to_dict') else manifest_results
        
        extraneous_issues = []
        
        # Check for debug features in production
        debug_enabled = manifest_data.get('debuggable', False)
        if debug_enabled:
            extraneous_issues.append("Application has android:debuggable=true")
        
        # Check for development and test functionality
        for string in all_strings:
            if isinstance(string, str):
                for category, patterns in self.extraneous_functionality_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, string, re.IGNORECASE):
                            extraneous_issues.append(f"Extraneous functionality ({category}): {string[:60]}...")
                            break
        
        if extraneous_issues:
            findings.append(SecurityFinding(
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
                    "Regular security testing to identify hidden functionality"
                ]
            ))
        
        return findings