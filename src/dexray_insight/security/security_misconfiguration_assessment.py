#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import List, Dict, Any

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment


@register_assessment('security_misconfiguration')
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
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A05:2021-Security Misconfiguration"
        
        # Debug and development configuration checks
        self.debug_checks = {
            'manifest_debug_flags': [
                'android:debuggable="true"',
                'android:allowBackup="true"',
                'android:testOnly="true"',
                'android:exported="true"'  # when inappropriate
            ],
            'debug_code_patterns': [
                r'Log\.[dwiev]\(',
                r'System\.out\.println\(',
                r'printStackTrace\(\)',
                r'BuildConfig\.DEBUG',
                r'__DEV__',
                r'Log\.isLoggable\(',
                r'android\.util\.Log'
            ],
            'development_endpoints': [
                r'http://(?:localhost|127\.0\.0\.1|10\.0\.2\.2|debug|dev|staging)',
                r'://.*\.(?:dev|debug|test|staging|local)\.',
                r'debug\..*\.com',
                r'api-dev\.',
                r'staging-api\.'
            ]
        }
        
        # Network security configuration checks
        self.network_security_checks = {
            'insecure_connections': [
                r'http://(?!localhost|127\.0\.0\.1)',  # Non-localhost HTTP
                r'setHostnameVerifier\(.*ALLOW_ALL',
                r'setDefaultHostnameVerifier\(',
                r'TrustManager.*checkServerTrusted.*\{\s*\}',  # Empty trust manager
                r'X509TrustManager.*\{\s*\}',
                r'SSLContext.*TLS.*null',
                r'HttpsURLConnection.*setDefaultSSLSocketFactory'
            ],
            'disabled_security_features': [
                r'setAllowFileAccess\(true\)',
                r'setAllowContentAccess\(true\)',
                r'setAllowUniversalAccessFromFileURLs\(true\)',
                r'setJavaScriptEnabled\(true\)',
                r'setDomStorageEnabled\(true\)',
                r'setDatabaseEnabled\(true\)'
            ],
            'weak_ssl_configurations': [
                r'SSL_?(?:v2|v3|TLS_?(?:v1|1\.0|1\.1))',
                r'DH.*512|RSA.*1024',  # Weak key sizes
                r'RC4|DES|3DES',  # Weak ciphers
                r'MD5|SHA1'  # Weak hash functions
            ]
        }
        
        # File and storage permission checks
        self.storage_permission_checks = {
            'world_accessible_files': [
                r'MODE_WORLD_READABLE',
                r'MODE_WORLD_WRITEABLE',
                r'openFileOutput\([^,]+,\s*[12]\)',  # MODE_WORLD_READABLE=1, MODE_WORLD_WRITEABLE=2
                r'File\([^)]*"/sdcard/',
                r'Environment\.getExternalStorageDirectory\(\)',
                r'Context\.MODE_WORLD_READABLE'
            ],
            'insecure_shared_preferences': [
                r'getSharedPreferences\([^,]+,\s*MODE_WORLD_READABLE\)',
                r'getSharedPreferences\([^,]+,\s*MODE_WORLD_WRITEABLE\)',
                r'getSharedPreferences.*MODE_WORLD'
            ],
            'external_storage_misuse': [
                r'getExternalFilesDir\([^)]*\).*password',
                r'getExternalStorageDirectory\(\).*token',
                r'/sdcard/.*(?:password|token|key|secret)',
                r'Environment\.getExternalStoragePublicDirectory'
            ]
        }
        
        # Component and permission misconfigurations
        self.component_misconfigurations = {
            'overprivileged_exports': [
                'android:exported="true"',
                'android:permission=""',  # Empty permission
                'android:protectionLevel="normal"'  # For sensitive operations
            ],
            'dangerous_intent_filters': [
                'android.intent.action.BOOT_COMPLETED',
                'android.intent.action.PACKAGE_INSTALL',
                'android.intent.action.PACKAGE_REMOVED',
                'android.provider.Telephony.SMS_RECEIVED',
                'android.intent.action.PHONE_STATE'
            ],
            'content_provider_risks': [
                'android:grantUriPermissions="true"',
                'android:multiprocess="true"',
                'android:syncable="true"'
            ]
        }
        
        # Security policy misconfigurations
        self.security_policy_checks = {
            'missing_policies': [
                'network-security-config',
                'content-security-policy',
                'certificate-pinning',
                'backup-rules',
                'data-extraction-rules'
            ],
            'weak_policies': [
                'cleartextTrafficPermitted="true"',
                'usesCleartextTraffic="true"',
                'android:allowBackup="true"',
                'android:fullBackupContent=""'  # Empty backup rules
            ]
        }
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
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
            
        except Exception as e:
            self.logger.error(f"Security misconfiguration assessment failed: {str(e)}")
        
        return findings
    
    def _assess_debug_configurations(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess debug and development configurations"""
        findings = []
        
        # Get manifest analysis for debug flags
        manifest_results = analysis_results.get('manifest_analysis', {})
        if hasattr(manifest_results, 'to_dict'):
            manifest_data = manifest_results.to_dict()
        else:
            manifest_data = manifest_results
        
        debug_flags = manifest_data.get('debug_flags', {})
        debug_issues = []
        
        # Check manifest debug flags
        if debug_flags.get('debuggable'):
            debug_issues.append("Application is marked as debuggable in production manifest")
        
        if debug_flags.get('allow_backup'):
            debug_issues.append("Application allows full backup without restrictions")
        
        if debug_flags.get('test_only'):
            debug_issues.append("Application is marked as test-only but may be in production")
        
        # Get string analysis for debug code patterns
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        # Check for debug code patterns
        debug_code_count = 0
        debug_patterns = self.debug_checks['debug_code_patterns']
        
        for string in all_strings:
            if isinstance(string, str):
                for pattern in debug_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        debug_code_count += 1
                        break
        
        if debug_code_count > 10:  # Threshold for excessive debug code
            debug_issues.append(f"Excessive debug/logging code detected: {debug_code_count} instances")
        
        # Check for development endpoints
        dev_endpoints = []
        dev_patterns = self.debug_checks['development_endpoints']
        
        urls = string_data.get('urls', [])
        domains = string_data.get('domains', [])
        all_network_strings = urls + domains + all_strings
        
        for string in all_network_strings:
            if isinstance(string, str):
                for pattern in dev_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        dev_endpoints.append(string)
                        break
        
        if dev_endpoints:
            debug_issues.extend([f"Development endpoint: {endpoint}" for endpoint in dev_endpoints[:5]])
        
        if debug_issues:
            severity = AnalysisSeverity.HIGH if debug_flags.get('debuggable') else AnalysisSeverity.MEDIUM
            
            findings.append(SecurityFinding(
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
                    "Implement proper build pipeline to strip debug artifacts"
                ]
            ))
        
        return findings
    
    def _assess_network_security_config(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess network security configurations"""
        findings = []
        
        # Get manifest data for network security policy
        manifest_results = analysis_results.get('manifest_analysis', {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, 'to_dict') else manifest_results
        
        # Get string analysis for network patterns
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        network_issues = []
        
        # Check for missing network security config
        network_config = manifest_data.get('network_security_config')
        if not network_config:
            network_issues.append("No network security configuration detected")
        
        # Check for insecure connections
        insecure_patterns = self.network_security_checks['insecure_connections']
        for string in all_strings:
            if isinstance(string, str):
                for pattern in insecure_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        network_issues.append(f"Insecure network configuration: {string[:80]}...")
                        break
        
        # Check for disabled security features
        disabled_patterns = self.network_security_checks['disabled_security_features']
        for string in all_strings:
            if isinstance(string, str):
                for pattern in disabled_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        network_issues.append(f"Disabled security feature: {string[:80]}...")
                        break
        
        # Check for weak SSL configurations
        weak_ssl_patterns = self.network_security_checks['weak_ssl_configurations']
        for string in all_strings:
            if isinstance(string, str):
                for pattern in weak_ssl_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        network_issues.append(f"Weak SSL configuration: {string[:80]}...")
                        break
        
        if network_issues:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Insecure Network Configuration",
                description="Application contains insecure network configurations that expose communications to attacks.",
                evidence=network_issues[:10],
                recommendations=[
                    "Implement network security configuration with certificate pinning",
                    "Disable cleartext traffic and enforce HTTPS",
                    "Use strong TLS versions (1.2+) and secure cipher suites",
                    "Properly validate SSL certificates and hostnames",
                    "Remove or secure any disabled security features"
                ]
            ))
        
        return findings
    
    def _assess_storage_configurations(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess file and storage permission configurations"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        # Get behavior analysis for file operations
        behavior_results = analysis_results.get('behaviour_analysis', {})
        file_operations = behavior_results.get('file_operations', {}) if isinstance(behavior_results, dict) else {}
        
        storage_issues = []
        
        # Check behavior analysis for world-accessible files
        world_readable = file_operations.get('world_readable_files', [])
        world_writable = file_operations.get('world_writable_files', [])
        
        if world_readable:
            storage_issues.extend([f"World-readable file: {f}" for f in world_readable[:3]])
        
        if world_writable:
            storage_issues.extend([f"World-writable file: {f}" for f in world_writable[:3]])
        
        # Check for world-accessible file patterns in code
        world_patterns = self.storage_permission_checks['world_accessible_files']
        for string in all_strings:
            if isinstance(string, str):
                for pattern in world_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        storage_issues.append(f"World-accessible file pattern: {string[:80]}...")
                        break
        
        # Check for insecure SharedPreferences
        prefs_patterns = self.storage_permission_checks['insecure_shared_preferences']
        for string in all_strings:
            if isinstance(string, str):
                for pattern in prefs_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        storage_issues.append(f"Insecure SharedPreferences: {string[:80]}...")
                        break
        
        # Check for external storage misuse
        external_patterns = self.storage_permission_checks['external_storage_misuse']
        for string in all_strings:
            if isinstance(string, str):
                for pattern in external_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        storage_issues.append(f"External storage misuse: {string[:80]}...")
                        break
        
        if storage_issues:
            findings.append(SecurityFinding(
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
                    "Use Android Keystore for sensitive data encryption keys"
                ]
            ))
        
        return findings
    
    def _assess_component_configurations(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess component configuration security"""
        findings = []
        
        manifest_results = analysis_results.get('manifest_analysis', {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, 'to_dict') else manifest_results
        
        component_issues = []
        
        # Check exported components
        exported_components = manifest_data.get('exported_components', [])
        if len(exported_components) > 5:  # Threshold for too many exports
            component_issues.append(f"Excessive exported components: {len(exported_components)} components exported")
        
        # Check intent filters for dangerous patterns
        intent_filters = manifest_data.get('intent_filters', [])
        dangerous_patterns = self.component_misconfigurations['dangerous_intent_filters']
        
        for intent_filter in intent_filters:
            if isinstance(intent_filter, dict):
                filters = intent_filter.get('filters', [])
                component_name = intent_filter.get('component_name', 'unknown')
                
                for filter_item in filters:
                    if any(dangerous in str(filter_item) for dangerous in dangerous_patterns):
                        component_issues.append(f"Dangerous intent filter in {component_name}: {filter_item}")
        
        # Check permissions
        permissions = manifest_data.get('permissions', [])
        dangerous_permissions = [
            'WRITE_EXTERNAL_STORAGE', 'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION',
            'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_SMS', 'SEND_SMS', 'CALL_PHONE'
        ]
        
        excessive_permissions = [p for p in permissions if any(dp in p for dp in dangerous_permissions)]
        if len(excessive_permissions) > 3:  # Threshold for permission creep
            component_issues.append(f"Excessive dangerous permissions: {len(excessive_permissions)} sensitive permissions")
        
        if component_issues:
            findings.append(SecurityFinding(
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
                    "Regularly audit component configurations and permissions"
                ]
            ))
        
        return findings
    
    def _assess_security_policies(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess security policy configurations"""
        findings = []
        
        manifest_results = analysis_results.get('manifest_analysis', {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, 'to_dict') else manifest_results
        
        policy_issues = []
        
        # Check for missing security policies
        network_config = manifest_data.get('network_security_config')
        if not network_config:
            policy_issues.append("Missing network security configuration")
        
        debug_flags = manifest_data.get('debug_flags', {})
        if debug_flags.get('allow_backup', True):  # Default is true, which is often insecure
            policy_issues.append("Backup is enabled without proper configuration")
        
        # Check target SDK version for security policy enforcement
        target_sdk = manifest_data.get('target_sdk_version', 0)
        if target_sdk < 28:  # Android 9 (API 28) introduced stricter security policies
            policy_issues.append(f"Target SDK version {target_sdk} does not enforce modern security policies")
        
        min_sdk = manifest_data.get('min_sdk_version', 0)
        if min_sdk < 23:  # Android 6 (API 23) introduced runtime permissions
            policy_issues.append(f"Minimum SDK version {min_sdk} does not support runtime permissions")
        
        if policy_issues:
            findings.append(SecurityFinding(
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
                    "Add certificate pinning and integrity verification policies"
                ]
            ))
        
        return findings
    
    def _assess_crypto_configurations(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess cryptographic configuration issues"""
        findings = []
        
        # Get API invocation results for crypto configuration
        api_results = analysis_results.get('api_invocation', {})
        api_data = api_results.to_dict() if hasattr(api_results, 'to_dict') else api_results
        
        crypto_usage = api_data.get('crypto_usage', [])
        crypto_issues = []
        
        # Check for weak cryptographic configurations
        for crypto_call in crypto_usage:
            if isinstance(crypto_call, dict):
                algorithm = crypto_call.get('algorithm', '').upper()
                context = crypto_call.get('context', '')
                
                # Flag weak algorithms
                if algorithm in ['MD5', 'SHA1', 'DES', 'RC4']:
                    crypto_issues.append(f"Weak cryptographic algorithm: {algorithm} used for {context}")
                
                # Flag inappropriate usage
                if algorithm == 'MD5' and 'password' in context.lower():
                    crypto_issues.append(f"MD5 used for password hashing at {crypto_call.get('location', 'unknown')}")
        
        # Get string analysis for hardcoded crypto configurations
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        # Check for hardcoded cryptographic keys or salts
        crypto_patterns = [
            r'(?:key|salt|iv)\s*=\s*["\'][A-Za-z0-9+/]{16,}["\']',
            r'SecretKeySpec\(["\'][^"\']{8,}["\']',
            r'IvParameterSpec\(["\'][^"\']{8,}["\']'
        ]
        
        for string in all_strings:
            if isinstance(string, str):
                for pattern in crypto_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        crypto_issues.append(f"Hardcoded cryptographic material: {string[:60]}...")
                        break
        
        if crypto_issues:
            findings.append(SecurityFinding(
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
                    "Regularly review and update cryptographic configurations"
                ]
            ))
        
        return findings