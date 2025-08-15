#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import List, Dict, Any

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment


@register_assessment('integrity_failures')
class IntegrityFailuresAssessment(BaseSecurityAssessment):
    """OWASP A08:2021 - Software and Data Integrity Failures assessment"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A08:2021-Software and Data Integrity Failures"
        
        self.deserialization_patterns = [
            r'ObjectInputStream.*readObject\(',
            r'Gson.*fromJson\(',
            r'Jackson.*readValue\(',
            r'Serializable',
            r'Externalizable'
        ]
        
        self.integrity_checks = [
            'certificate pinning',
            'signature verification',
            'checksum validation'
        ]
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        
        try:
            # Check for unsafe deserialization
            deserialization_findings = self._assess_unsafe_deserialization(analysis_results)
            findings.extend(deserialization_findings)
            
            # Check for missing integrity controls
            integrity_findings = self._assess_missing_integrity_controls(analysis_results)
            findings.extend(integrity_findings)
            
        except Exception as e:
            self.logger.error(f"Integrity failures assessment failed: {str(e)}")
        
        return findings
    
    def _assess_unsafe_deserialization(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        
        # Check API invocation for deserialization usage
        api_results = analysis_results.get('api_invocation', {})
        api_data = api_results.to_dict() if hasattr(api_results, 'to_dict') else api_results
        api_calls = api_data.get('api_calls', [])
        
        deserialization_usage = []
        
        for api_call in api_calls:
            if isinstance(api_call, dict):
                called_method = api_call.get('called_method', '')
                called_class = api_call.get('called_class', '')
                
                if 'readObject' in called_method and 'ObjectInputStream' in called_class:
                    deserialization_usage.append(f"Unsafe deserialization: {called_class}.{called_method}")
        
        # Check strings for deserialization patterns
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        for string in all_strings:
            if isinstance(string, str):
                for pattern in self.deserialization_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        deserialization_usage.append(f"Deserialization pattern: {string[:80]}...")
                        break
        
        if deserialization_usage:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Unsafe Deserialization Detected",
                description="Application uses deserialization mechanisms that could allow remote code execution if untrusted data is processed.",
                evidence=deserialization_usage[:8],
                recommendations=[
                    "Avoid deserializing untrusted data",
                    "Use safe serialization formats like JSON with schema validation",
                    "Implement input validation before deserialization",
                    "Use allowlists for deserializable classes",
                    "Consider alternative data exchange formats"
                ]
            ))
        
        return findings
    
    def _assess_missing_integrity_controls(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        integrity_issues = []
        
        # Check for certificate pinning
        has_cert_pinning = any('pin' in s.lower() and 'cert' in s.lower() for s in all_strings if isinstance(s, str))
        if not has_cert_pinning:
            integrity_issues.append("No certificate pinning implementation detected")
        
        # Check for signature verification
        has_signature_check = any('signature' in s.lower() and 'verify' in s.lower() for s in all_strings if isinstance(s, str))
        if not has_signature_check:
            integrity_issues.append("No signature verification implementation detected")
        
        if integrity_issues:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Missing Integrity Controls",
                description="Application lacks essential integrity verification mechanisms.",
                evidence=integrity_issues,
                recommendations=[
                    "Implement certificate pinning for network communications",
                    "Add signature verification for critical operations",
                    "Use checksums for data integrity validation",
                    "Implement tamper detection mechanisms",
                    "Verify the integrity of downloaded content"
                ]
            ))
        
        return findings