#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import List, Dict, Any

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment


@register_assessment('ssrf')
class SSRFAssessment(BaseSecurityAssessment):
    """OWASP A10:2021 - Server-Side Request Forgery (SSRF) assessment"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A10:2021-Server-Side Request Forgery (SSRF)"
        
        self.url_validation_patterns = [
            r'Uri\.parse\([^)]*user[^)]*\)',
            r'URL\([^)]*user[^)]*\)',
            r'HttpURLConnection.*setRequestProperty.*user',
            r'Intent\.setData\(Uri\.parse\([^)]*user[^)]*\)\)'
        ]
        
        self.internal_service_patterns = [
            r'https?://(?:localhost|127\.0\.0\.1|10\.0\.2\.2)',
            r'https?://.*\.internal\.',
            r'https?://192\.168\.',
            r'https?://10\.',
            r'file://',
            r'content://'
        ]
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        
        try:
            # Check for unsafe URL validation
            url_findings = self._assess_url_validation(analysis_results)
            findings.extend(url_findings)
            
            # Check for internal service exposure
            internal_findings = self._assess_internal_service_exposure(analysis_results)
            findings.extend(internal_findings)
            
        except Exception as e:
            self.logger.error(f"SSRF assessment failed: {str(e)}")
        
        return findings
    
    def _assess_url_validation(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        unsafe_url_handling = []
        
        for string in all_strings:
            if isinstance(string, str):
                for pattern in self.url_validation_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        unsafe_url_handling.append(f"Unsafe URL handling: {string[:80]}...")
                        break
        
        if unsafe_url_handling:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Server-Side Request Forgery (SSRF) Risk",
                description="Application handles user-controlled URLs without proper validation, potentially enabling SSRF attacks.",
                evidence=unsafe_url_handling[:8],
                recommendations=[
                    "Implement strict URL validation and allowlists",
                    "Validate URL schemes and restrict to allowed protocols",
                    "Use DNS resolution blocking for internal networks",
                    "Implement proper input sanitization for URL parameters",
                    "Consider using a proxy service for external requests"
                ]
            ))
        
        return findings
    
    def _assess_internal_service_exposure(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        urls = string_data.get('urls', [])
        
        internal_services = []
        all_network_strings = urls + all_strings
        
        for string in all_network_strings:
            if isinstance(string, str):
                for pattern in self.internal_service_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        internal_services.append(f"Internal service reference: {string}")
                        break
        
        if internal_services:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Internal Service Exposure Risk",
                description="Application contains references to internal services that could be exploited in SSRF attacks.",
                evidence=internal_services[:8],
                recommendations=[
                    "Remove hardcoded internal service URLs from client code",
                    "Implement network-level protections against internal access",
                    "Use service discovery mechanisms instead of hardcoded URLs",
                    "Validate and restrict network access from mobile clients",
                    "Implement proper API gateway patterns for internal services"
                ]
            ))
        
        return findings