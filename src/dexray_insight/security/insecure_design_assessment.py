#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import List, Dict, Any

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment


@register_assessment('insecure_design')
class InsecureDesignAssessment(BaseSecurityAssessment):
    """
    OWASP A04:2021 - Insecure Design vulnerability assessment.
    
    This assessment identifies design-level security flaws that represent
    missing or ineffective security controls in the application's architecture.
    
    Mobile-specific focus areas:
    - Insecure data flows and trust boundaries
    - Missing security controls and defense-in-depth
    - Weak cryptographic design patterns
    - Unsafe inter-component communication
    - Insecure API design patterns
    - Missing threat modeling considerations
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A04:2021-Insecure Design"
        
        # Design pattern checks for mobile applications
        self.design_patterns = {
            'insecure_data_flows': {
                'patterns': [
                    r'Intent\.putExtra\([^,]+,\s*[^)]*(?:password|token|secret|key)[^)]*\)',
                    r'SharedPreferences.*\.putString\([^,]+,\s*[^)]*(?:password|token|auth)[^)]*\)',
                    r'Log\.[dwiev]\([^,]+,.*(?:password|token|secret|credential)',
                    r'System\.out\.println.*(?:password|token|secret|auth)',
                    r'Uri\.parse\([^)]*(?:file://|content://)[^)]*\)'
                ],
                'description': 'Insecure data flows expose sensitive information through unsafe channels'
            },
            'missing_input_validation': {
                'patterns': [
                    r'Intent\.getStringExtra\([^)]+\)(?!\s*(?:!=\s*null|\.(?:trim|isEmpty|matches)))',
                    r'getIntent\(\)\.getData\(\)(?!\s*(?:!=\s*null|\.getScheme))',
                    r'Uri\.parse\([^)]+\)(?!\s*(?:\.getScheme|validation))',
                    r'URLConnection\.setRequestProperty\([^,]+,\s*[^)]*user[^)]*\)',
                ],
                'description': 'Missing input validation allows untrusted data to flow through the system'
            },
            'weak_crypto_design': {
                'patterns': [
                    r'Cipher\.getInstance\(["\'](?:DES|RC4|MD5)["\']',
                    r'MessageDigest\.getInstance\(["\']MD5["\']',
                    r'KeyGenerator\.getInstance\(["\']DES["\']',
                    r'new\s+Random\(\)',  # Non-cryptographic random
                    r'Math\.random\(\)',
                    r'SecretKeySpec\([^,]+,\s*["\']DES["\']'
                ],
                'description': 'Weak cryptographic design uses deprecated or insecure algorithms'
            },
            'insecure_ipc_design': {
                'patterns': [
                    r'sendBroadcast\([^)]+\)(?!\s*[^)]*permission)',
                    r'ContentProvider.*openFile.*MODE_WORLD_READABLE',
                    r'openFileOutput\([^,]+,\s*MODE_WORLD_READABLE\)',
                    r'Intent\s*intent[^;]*\.setComponent\([^)]*user[^)]*\)',
                    r'PendingIntent\.get(?:Activity|Service|Broadcast)\([^,]*,\s*0,'
                ],
                'description': 'Insecure inter-process communication design exposes app functionality'
            },
            'unsafe_external_interfaces': {
                'patterns': [
                    r'WebView.*setJavaScriptEnabled\(true\)',
                    r'WebView.*addJavaScriptInterface\(',
                    r'setAllowFileAccess\(true\)',
                    r'setAllowUniversalAccessFromFileURLs\(true\)',
                    r'WebSettings.*setMixedContentMode\(.*MIXED_CONTENT_ALWAYS_ALLOW'
                ],
                'description': 'Unsafe external interfaces create attack vectors through web content'
            }
        }
        
        # Security control checks
        self.security_control_checks = {
            'missing_authentication': [
                'no biometric authentication detected',
                'no multi-factor authentication',
                'missing session timeout controls'
            ],
            'missing_authorization': [
                'no role-based access controls',
                'missing permission checks',
                'insufficient access restrictions'
            ],
            'missing_integrity_controls': [
                'no certificate pinning',
                'missing signature verification', 
                'no tampering detection'
            ],
            'missing_confidentiality_controls': [
                'no data encryption at rest',
                'missing secure key storage',
                'no secure communication channels'
            ]
        }
        
        # Threat modeling gaps - common mobile threat scenarios
        self.threat_scenarios = {
            'device_compromise': [
                'missing root/jailbreak detection',
                'no secure enclave usage',
                'insufficient local data protection'
            ],
            'network_attacks': [
                'missing certificate pinning',
                'no network security policy',
                'insufficient TLS configuration'
            ],
            'reverse_engineering': [
                'no code obfuscation',
                'missing anti-debugging',
                'no tamper detection'
            ],
            'privilege_escalation': [
                'overprivileged components',
                'unsafe permission combinations',
                'missing privilege checks'
            ]
        }
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Assess for insecure design vulnerabilities.
        
        Args:
            analysis_results: Combined results from all analysis modules
            
        Returns:
            List of security findings related to insecure design
        """
        findings = []
        
        try:
            # 1. Analyze insecure data flow patterns
            data_flow_findings = self._assess_insecure_data_flows(analysis_results)
            if isinstance(data_flow_findings, list):
                findings.extend(data_flow_findings)
            
            # 2. Check for missing security controls
            control_findings = self._assess_missing_security_controls(analysis_results)
            if isinstance(control_findings, list):
                findings.extend(control_findings)
            
            # 3. Evaluate cryptographic design patterns
            crypto_findings = self._assess_cryptographic_design(analysis_results)
            if isinstance(crypto_findings, list):
                findings.extend(crypto_findings)
            
            # 4. Analyze inter-component communication design
            ipc_findings = self._assess_ipc_design(analysis_results)
            if isinstance(ipc_findings, list):
                findings.extend(ipc_findings)
            
            # 5. Check external interface security
            interface_findings = self._assess_external_interfaces(analysis_results)
            if isinstance(interface_findings, list):
                findings.extend(interface_findings)
            
            # 6. Evaluate against common threat scenarios
            threat_findings = self._assess_threat_scenario_coverage(analysis_results)
            if isinstance(threat_findings, list):
                findings.extend(threat_findings)
            
        except Exception as e:
            self.logger.error(f"Insecure design assessment failed: {str(e)}")
        
        return findings
    
    def _assess_insecure_data_flows(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for insecure data flow patterns"""
        findings = []
        
        # Get string analysis results
        string_results = analysis_results.get('string_analysis', {})
        if hasattr(string_results, 'to_dict'):
            string_data = string_results.to_dict()
        else:
            string_data = string_results
        
        all_strings = string_data.get('all_strings', [])
        if not isinstance(all_strings, list):
            all_strings = []
        
        # Check for insecure data flow patterns
        flow_evidence = []
        
        for pattern_category, pattern_info in self.design_patterns.items():
            if pattern_category in ['insecure_data_flows', 'missing_input_validation']:
                patterns = pattern_info['patterns']
                
                for string in all_strings:
                    if isinstance(string, str):
                        for pattern in patterns:
                            import re
                            if re.search(pattern, string, re.IGNORECASE):
                                flow_evidence.append(f"Insecure data flow: {string[:100]}...")
                                break
        
        if flow_evidence:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Insecure Data Flow Design",
                description="Application contains insecure data flow patterns that expose sensitive information through unsafe channels or lack proper input validation.",
                evidence=flow_evidence[:10],  # Limit evidence
                recommendations=[
                    "Implement secure data flow design with clear trust boundaries",
                    "Add comprehensive input validation for all external data sources",
                    "Use secure storage mechanisms for sensitive data transmission",
                    "Implement data classification and handling policies",
                    "Add data leak prevention controls for sensitive information"
                ]
            ))
        
        return findings
    
    def _assess_missing_security_controls(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for missing essential security controls"""
        findings = []
        
        # Get manifest analysis to check for security controls
        manifest_results = analysis_results.get('manifest_analysis', {})
        if hasattr(manifest_results, 'to_dict'):
            manifest_data = manifest_results.to_dict()
        else:
            manifest_data = manifest_results
        
        # Get behavior analysis for security features
        behavior_results = analysis_results.get('behaviour_analysis', {})
        
        missing_controls = []
        
        # Check for authentication controls
        permissions = manifest_data.get('permissions', [])
        if not isinstance(permissions, list):
            permissions = []
        if not any('FINGERPRINT' in perm or 'BIOMETRIC' in perm for perm in permissions):
            missing_controls.append("No biometric authentication permissions detected")
        
        # Check for secure storage controls
        if not any('KEYSTORE' in str(behavior_results).upper() or 'ENCRYPTED' in str(behavior_results).upper()):
            missing_controls.append("No secure key storage implementation detected")
        
        # Check for network security controls
        network_config = manifest_data.get('network_security_config')
        if not network_config:
            missing_controls.append("No network security configuration detected")
        
        # Check for integrity controls
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        if not isinstance(all_strings, list):
            all_strings = []
        
        has_cert_pinning = any('pin' in str(s).lower() and 'cert' in str(s).lower() for s in all_strings)
        if not has_cert_pinning:
            missing_controls.append("No certificate pinning implementation detected")
        
        if missing_controls:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Missing Security Controls",
                description="Application lacks essential security controls that should be present in a defense-in-depth security design.",
                evidence=missing_controls,
                recommendations=[
                    "Implement biometric authentication for sensitive operations",
                    "Use Android Keystore for secure key and credential storage",
                    "Configure network security policy with certificate pinning",
                    "Add integrity verification and tamper detection controls",
                    "Implement comprehensive session management and timeout controls"
                ]
            ))
        
        return findings
    
    def _assess_cryptographic_design(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess cryptographic design patterns"""
        findings = []
        
        # Get API invocation results for crypto usage
        api_results = analysis_results.get('api_invocation', {})
        if hasattr(api_results, 'to_dict'):
            api_data = api_results.to_dict()
        else:
            api_data = api_results
        
        crypto_usage = api_data.get('crypto_usage', [])
        if not isinstance(crypto_usage, list):
            crypto_usage = []
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        if not isinstance(all_strings, list):
            all_strings = []
        
        weak_crypto_evidence = []
        
        # Check for weak algorithms in API usage
        for crypto_call in crypto_usage:
            if isinstance(crypto_call, dict):
                algorithm = crypto_call.get('algorithm', '').upper()
                if algorithm in ['MD5', 'SHA1', 'DES', 'RC4']:
                    weak_crypto_evidence.append(f"Weak algorithm detected: {algorithm} at {crypto_call.get('location', 'unknown')}")
        
        # Check for weak crypto patterns in strings
        weak_patterns = self.design_patterns['weak_crypto_design']['patterns']
        for string in all_strings:
            if isinstance(string, str):
                for pattern in weak_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        weak_crypto_evidence.append(f"Weak crypto pattern: {string[:80]}...")
                        break
        
        if weak_crypto_evidence:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Weak Cryptographic Design",
                description="Application uses weak or deprecated cryptographic algorithms and patterns that compromise data security.",
                evidence=weak_crypto_evidence[:8],
                recommendations=[
                    "Replace weak algorithms with strong alternatives (AES-256, SHA-256, etc.)",
                    "Use cryptographically secure random number generators",
                    "Implement proper key derivation functions (PBKDF2, scrypt, Argon2)",
                    "Use authenticated encryption modes (GCM, CCM)",
                    "Follow current cryptographic best practices and standards"
                ]
            ))
        
        return findings
    
    def _assess_ipc_design(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess inter-process communication design"""
        findings = []
        
        # Get manifest data for component analysis
        manifest_results = analysis_results.get('manifest_analysis', {})
        if hasattr(manifest_results, 'to_dict'):
            manifest_data = manifest_results.to_dict()
        else:
            manifest_data = manifest_results
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        if not isinstance(all_strings, list):
            all_strings = []
        
        ipc_issues = []
        
        # Check for insecure IPC patterns in code
        ipc_patterns = self.design_patterns['insecure_ipc_design']['patterns']
        for string in all_strings:
            if isinstance(string, str):
                for pattern in ipc_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        ipc_issues.append(f"Insecure IPC pattern: {string[:80]}...")
                        break
        
        # Check for exported components without proper protection
        exported_components = manifest_data.get('exported_components', [])
        if not isinstance(exported_components, list):
            exported_components = []
        if exported_components:
            ipc_issues.append(f"Exported components detected: {len(exported_components)} components may lack proper access controls")
        
        # Check intent filters for overly broad patterns
        intent_filters = manifest_data.get('intent_filters', [])
        if not isinstance(intent_filters, list):
            intent_filters = []
        for intent_filter in intent_filters:
            if isinstance(intent_filter, dict):
                filters = intent_filter.get('filters', [])
                if not isinstance(filters, list):
                    filters = []
                if any('*' in str(filter_item) or 'ANY' in str(filter_item).upper() for filter_item in filters):
                    ipc_issues.append(f"Overly broad intent filter in {intent_filter.get('component_name', 'unknown component')}")
        
        if ipc_issues:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Insecure Inter-Process Communication Design",
                description="Application's IPC design exposes functionality through insecure channels or lacks proper access controls.",
                evidence=ipc_issues[:10],
                recommendations=[
                    "Implement proper access controls for exported components",
                    "Use signature-level permissions for sensitive IPC",
                    "Validate all data received through IPC channels",
                    "Minimize the attack surface by reducing exported components",
                    "Use explicit intents instead of implicit ones where possible"
                ]
            ))
        
        return findings
    
    def _assess_external_interfaces(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess external interface security design"""
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        if not isinstance(all_strings, list):
            all_strings = []
        
        interface_issues = []
        
        # Check for unsafe WebView configurations
        webview_patterns = self.design_patterns['unsafe_external_interfaces']['patterns']
        for string in all_strings:
            if isinstance(string, str):
                for pattern in webview_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        interface_issues.append(f"Unsafe WebView configuration: {string[:80]}...")
                        break
        
        if interface_issues:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Unsafe External Interface Design",
                description="Application's external interfaces (WebView, etc.) are configured insecurely, creating attack vectors.",
                evidence=interface_issues[:8],
                recommendations=[
                    "Disable JavaScript in WebView unless absolutely necessary",
                    "Remove JavaScript interfaces or secure them properly",
                    "Disable file access and universal access from file URLs",
                    "Implement Content Security Policy for web content",
                    "Validate and sanitize all data from external sources"
                ]
            ))
        
        return findings
    
    def _assess_threat_scenario_coverage(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess coverage of common mobile threat scenarios"""
        findings = []
        
        # This is a high-level assessment of whether the app design addresses common threats
        threat_gaps = []
        
        # Check for device compromise protections
        behavior_results = analysis_results.get('behaviour_analysis', {})
        if not any('root' in str(behavior_results).lower() or 'jailbreak' in str(behavior_results).lower()):
            threat_gaps.append("No root/jailbreak detection mechanisms detected")
        
        # Check for reverse engineering protections
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        if not isinstance(all_strings, list):
            all_strings = []
        
        has_obfuscation = any('obfuscat' in str(s).lower() or 'proguard' in str(s).lower() for s in all_strings)
        if not has_obfuscation:
            threat_gaps.append("No code obfuscation or anti-reverse engineering protections detected")
        
        # Check for network attack protections
        manifest_results = analysis_results.get('manifest_analysis', {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, 'to_dict') else manifest_results
        
        if not manifest_data.get('network_security_config'):
            threat_gaps.append("No network security configuration for protecting against network attacks")
        
        if threat_gaps:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Insufficient Threat Scenario Coverage",
                description="Application design does not adequately address common mobile threat scenarios and attack vectors.",
                evidence=threat_gaps,
                recommendations=[
                    "Implement comprehensive threat modeling for mobile-specific risks",
                    "Add device integrity checks (root/jailbreak detection)",
                    "Implement code obfuscation and anti-tampering controls",
                    "Configure network security policies for threat protection",
                    "Design with assumption of device compromise and plan accordingly"
                ]
            ))
        
        return findings