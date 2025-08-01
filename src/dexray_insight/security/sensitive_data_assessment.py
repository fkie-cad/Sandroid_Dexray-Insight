#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import logging
from typing import List, Dict, Any

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment

@register_assessment('sensitive_data')
class SensitiveDataAssessment(BaseSecurityAssessment):
    """OWASP A02:2021 - Cryptographic Failures / Sensitive Data Exposure assessment"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A02:2021-Cryptographic Failures"
        
        self.pii_patterns = config.get('pii_patterns', ['email', 'phone', 'ssn', 'credit_card'])
        self.crypto_keys_check = config.get('crypto_keys_check', True)
        
        # PII detection patterns
        self.pii_regex_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        }
        
        # Crypto-related patterns
        self.crypto_patterns = [
            # Weak encryption algorithms
            'DES', 'RC4', 'MD5', 'SHA1',
            
            # Common key/password patterns
            'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api_key',
            'private_key', 'public_key', 'certificate', 'keystore',
            
            # Base64 encoded patterns (potential keys/secrets)
            r'[A-Za-z0-9+/]{20,}={0,2}',
            
            # Hex encoded patterns
            r'[a-fA-F0-9]{32,}'
        ]
        
        # Permissions that may indicate sensitive data access
        self.sensitive_permissions = [
            'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
            'READ_SMS', 'RECEIVE_SMS', 'READ_PHONE_STATE', 'READ_PHONE_NUMBERS',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION',
            'CAMERA', 'RECORD_AUDIO', 'BODY_SENSORS', 'READ_CALENDAR', 'WRITE_CALENDAR'
        ]
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Assess for sensitive data exposure vulnerabilities
        
        Args:
            analysis_results: Combined results from all analysis modules
            
        Returns:
            List of security findings related to sensitive data exposure
        """
        findings = []
        
        try:
            # Check for PII in strings
            pii_findings = self._assess_pii_exposure(analysis_results)
            findings.extend(pii_findings)
            
            # Check for crypto keys and secrets
            if self.crypto_keys_check:
                crypto_findings = self._assess_crypto_keys_exposure(analysis_results)
                findings.extend(crypto_findings)
            
            # Check weak cryptographic algorithms
            weak_crypto_findings = self._assess_weak_cryptography(analysis_results)
            findings.extend(weak_crypto_findings)
            
            # Check sensitive permissions
            permission_findings = self._assess_sensitive_permissions(analysis_results)
            findings.extend(permission_findings)
            
        except Exception as e:
            self.logger.error(f"Sensitive data assessment failed: {str(e)}")
        
        return findings
    
    def _assess_pii_exposure(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for PII exposure in strings"""
        findings = []
        
        # Get string analysis results
        string_results = analysis_results.get('string_analysis', {})
        if hasattr(string_results, 'to_dict'):
            string_data = string_results.to_dict()
        else:
            string_data = string_results
        
        if not isinstance(string_data, dict):
            return findings
        
        # Collect all strings for analysis
        all_strings = []
        for key in ['emails', 'urls', 'domains']:
            strings = string_data.get(key, [])
            if isinstance(strings, list):
                all_strings.extend(strings)
        
        pii_found = {}
        
        # Check for PII patterns
        for pii_type in self.pii_patterns:
            if pii_type in self.pii_regex_patterns:
                pattern = self.pii_regex_patterns[pii_type]
                matches = []
                
                for string in all_strings:
                    if isinstance(string, str):
                        if re.search(pattern, string):
                            matches.append(string[:50] + "..." if len(string) > 50 else string)
                
                if matches:
                    pii_found[pii_type] = matches
        
        # Also check emails from string analysis results
        emails = string_data.get('emails', [])
        if emails:
            pii_found['emails_detected'] = [email[:30] + "..." for email in emails[:5]]
        
        if pii_found:
            evidence = []
            for pii_type, matches in pii_found.items():
                evidence.append(f"{pii_type.upper()}: {len(matches)} instances found")
                evidence.extend([f"  - {match}" for match in matches[:3]])  # Show first 3
            
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Potential PII Exposure in Application Strings",
                description="Personal Identifiable Information (PII) patterns detected in application strings, which may indicate hardcoded sensitive data.",
                evidence=evidence,
                recommendations=[
                    "Remove all hardcoded PII from the application",
                    "Use secure storage mechanisms for sensitive data",
                    "Implement proper data encryption for stored PII",
                    "Follow data minimization principles",
                    "Ensure compliance with privacy regulations (GDPR, CCPA, etc.)"
                ]
            ))
        
        return findings
    
    def _assess_crypto_keys_exposure(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for exposed cryptographic keys and secrets"""
        findings = []
        
        # Get string analysis results
        string_results = analysis_results.get('string_analysis', {})
        if hasattr(string_results, 'to_dict'):
            string_data = string_results.to_dict()
        else:
            string_data = string_results
        
        if not isinstance(string_data, dict):
            return findings
        
        # Collect all strings
        all_strings = []
        for key in ['emails', 'urls', 'domains']:
            strings = string_data.get(key, [])
            if isinstance(strings, list):
                all_strings.extend(strings)
        
        # Check Android properties for keys
        android_props = string_data.get('android_properties', {})
        if isinstance(android_props, dict):
            all_strings.extend(android_props.keys())
        
        crypto_evidence = []
        
        for string in all_strings:
            if isinstance(string, str):
                string_lower = string.lower()
                
                # Check for key/secret keywords
                for pattern in ['password', 'passwd', 'secret', 'key', 'token', 'api_key']:
                    if pattern in string_lower and len(string) > 10:
                        crypto_evidence.append(f"Potential secret: {string[:40]}...")
                        break
                
                # Check for Base64 patterns (potential encoded keys)
                if re.match(r'^[A-Za-z0-9+/]{40,}={0,2}$', string):
                    crypto_evidence.append(f"Potential Base64 encoded key: {string[:30]}...")
                
                # Check for hex patterns (potential keys)
                if re.match(r'^[a-fA-F0-9]{32,}$', string):
                    crypto_evidence.append(f"Potential hex encoded key: {string[:30]}...")
        
        if crypto_evidence:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.CRITICAL,
                title="Potential Hardcoded Cryptographic Keys or Secrets",
                description="Patterns resembling cryptographic keys or secrets found in application strings, indicating potential hardcoded sensitive credentials.",
                evidence=crypto_evidence[:10],  # Limit to first 10
                recommendations=[
                    "Remove all hardcoded keys and secrets from the application",
                    "Use Android Keystore for cryptographic key storage",
                    "Implement secure key management practices",
                    "Use environment variables or secure configuration for API keys",
                    "Rotate any exposed keys immediately",
                    "Implement key derivation functions instead of hardcoded keys"
                ]
            ))
        
        return findings
    
    def _assess_weak_cryptography(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for weak cryptographic algorithms"""
        findings = []
        
        # Check API calls for weak crypto usage
        api_results = analysis_results.get('api_invocation', {})
        if hasattr(api_results, 'to_dict'):
            api_data = api_results.to_dict()
        else:
            api_data = api_results
        
        if not isinstance(api_data, dict):
            return findings
        
        weak_crypto_evidence = []
        api_calls = api_data.get('api_calls', [])
        
        for call in api_calls:
            if isinstance(call, dict):
                api_name = call.get('called_class', '') + '.' + call.get('called_method', '')
                
                # Check for weak algorithms
                weak_algorithms = ['DES', 'RC4', 'MD5', 'SHA1']
                for weak_algo in weak_algorithms:
                    if weak_algo.lower() in api_name.lower():
                        weak_crypto_evidence.append(f"Weak algorithm usage: {api_name}")
                        break
        
        # Also check strings for algorithm names
        string_results = analysis_results.get('string_analysis', {})
        if hasattr(string_results, 'to_dict'):
            string_data = string_results.to_dict()
            all_strings = []
            for key in ['emails', 'urls', 'domains']:
                strings = string_data.get(key, [])
                if isinstance(strings, list):
                    all_strings.extend(strings)
            
            for string in all_strings:
                if isinstance(string, str):
                    for weak_algo in ['DES', 'RC4', 'MD5', 'SHA1']:
                        if weak_algo in string.upper():
                            weak_crypto_evidence.append(f"Weak algorithm reference: {string[:50]}...")
                            break
        
        if weak_crypto_evidence:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Weak Cryptographic Algorithms Detected",
                description="Usage of weak or deprecated cryptographic algorithms that may be vulnerable to attacks.",
                evidence=weak_crypto_evidence,
                recommendations=[
                    "Replace weak algorithms with stronger alternatives (AES, SHA-256, etc.)",
                    "Use Android's recommended cryptographic libraries",
                    "Implement proper key management",
                    "Follow current cryptographic best practices",
                    "Regularly update cryptographic implementations"
                ]
            ))
        
        return findings
    
    def _assess_sensitive_permissions(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess permissions that may lead to sensitive data access"""
        findings = []
        
        # Get permission analysis results
        permission_results = analysis_results.get('permission_analysis', {})
        if hasattr(permission_results, 'to_dict'):
            permission_data = permission_results.to_dict()
        else:
            permission_data = permission_results
        
        if not isinstance(permission_data, dict):
            return findings
        
        all_permissions = permission_data.get('all_permissions', [])
        sensitive_found = []
        
        for permission in all_permissions:
            if isinstance(permission, str):
                for sensitive_perm in self.sensitive_permissions:
                    if sensitive_perm in permission:
                        sensitive_found.append(permission)
                        break
        
        if sensitive_found:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Sensitive Data Access Permissions",
                description="Application requests permissions that provide access to sensitive user data.",
                evidence=[f"Permission: {perm}" for perm in sensitive_found],
                recommendations=[
                    "Ensure sensitive data is encrypted before storage",
                    "Implement proper data retention policies",
                    "Use runtime permissions and explain data usage to users",
                    "Minimize data collection to what's necessary for functionality",
                    "Implement secure data transmission (HTTPS, certificate pinning)",
                    "Follow platform guidelines for handling sensitive data"
                ]
            ))
        
        return findings