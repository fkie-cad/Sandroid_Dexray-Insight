#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import List, Dict, Any

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment


@register_assessment('logging_monitoring_failures')
class LoggingMonitoringFailuresAssessment(BaseSecurityAssessment):
    """OWASP A09:2021 - Security Logging and Monitoring Failures assessment"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A09:2021-Security Logging and Monitoring Failures"
        
        self.logging_patterns = [
            r'Log\.[dwiev]\([^,]+,.*(?:password|token|secret|credential|key)',
            r'System\.out\.println.*(?:password|token|secret|auth)',
            r'printStackTrace\(\)',
            r'Log\.d\([^,]+,.*(?:user|email|phone|address)',
            r'android\.util\.Log'
        ]
        
        self.sensitive_data_patterns = [
            'password', 'token', 'secret', 'credential', 'key',
            'email', 'phone', 'address', 'ssn', 'credit'
        ]
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        
        try:
            # Check for excessive logging of sensitive data
            logging_findings = self._assess_excessive_logging(analysis_results)
            findings.extend(logging_findings)
            
            # Check for missing security monitoring
            monitoring_findings = self._assess_missing_monitoring(analysis_results)
            findings.extend(monitoring_findings)
            
        except Exception as e:
            self.logger.error(f"Logging monitoring failures assessment failed: {str(e)}")
        
        return findings
    
    def _assess_excessive_logging(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        sensitive_logging = []
        
        for string in all_strings:
            if isinstance(string, str):
                for pattern in self.logging_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        sensitive_logging.append(f"Sensitive data logging: {string[:100]}...")
                        break
        
        if sensitive_logging:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Excessive Logging of Sensitive Data",
                description="Application logs sensitive information that could be exposed through log files or debugging.",
                evidence=sensitive_logging[:10],
                recommendations=[
                    "Remove sensitive data from log messages",
                    "Use log levels appropriately (avoid debug logs in production)",
                    "Implement log sanitization for sensitive fields",
                    "Use structured logging with field filtering",
                    "Review and audit all logging statements"
                ]
            ))
        
        return findings
    
    def _assess_missing_monitoring(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        findings = []
        
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        # Check for security event monitoring
        has_security_monitoring = any(
            'security' in s.lower() and ('log' in s.lower() or 'monitor' in s.lower() or 'audit' in s.lower())
            for s in all_strings if isinstance(s, str)
        )
        
        monitoring_issues = []
        
        if not has_security_monitoring:
            monitoring_issues.append("No security event monitoring implementation detected")
        
        # Check for crash reporting that might expose sensitive data
        crash_reporting = []
        crash_patterns = [
            r'Crashlytics', r'Bugsnag', r'Sentry', r'ACRA',
            r'printStackTrace\(\)', r'Log\.getStackTraceString'
        ]
        
        for string in all_strings:
            if isinstance(string, str):
                for pattern in crash_patterns:
                    import re
                    if re.search(pattern, string, re.IGNORECASE):
                        crash_reporting.append(f"Crash reporting: {string[:80]}...")
                        break
        
        if crash_reporting:
            monitoring_issues.extend(crash_reporting[:3])
            monitoring_issues.append("Crash reporting may expose sensitive information in stack traces")
        
        if monitoring_issues:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.LOW,
                title="Insufficient Security Monitoring",
                description="Application lacks adequate security event logging and monitoring capabilities.",
                evidence=monitoring_issues,
                recommendations=[
                    "Implement security event logging for authentication attempts",
                    "Monitor and log suspicious activities",
                    "Sanitize crash reports before transmission",
                    "Implement proper log retention and analysis",
                    "Add alerting for security-relevant events"
                ]
            ))
        
        return findings