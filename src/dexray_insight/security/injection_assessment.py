#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import List, Dict, Any

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment

@register_assessment('injection')
class InjectionAssessment(BaseSecurityAssessment):
    """OWASP A03:2021 - Injection vulnerability assessment"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A03:2021-Injection"
        
        # SQL injection patterns
        self.sql_patterns = config.get('sql_patterns', [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
            'ALTER', 'EXEC', 'UNION', 'TRUNCATE', 'MERGE'
        ])
        
        # Command injection patterns  
        self.command_patterns = config.get('command_patterns', [
            'exec', 'system', 'runtime', 'sh', 'bash', 'cmd', 'powershell'
        ])
        
        # LDAP injection patterns
        self.ldap_patterns = ['ldap://', 'ldaps://', 'ldapQuery', 'DirectorySearcher']
        
        # NoSQL injection patterns
        self.nosql_patterns = ['$where', '$ne', '$gt', '$lt', '$regex', 'find(', 'aggregate(']
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Assess for injection vulnerabilities
        
        Args:
            analysis_results: Combined results from all analysis modules
            
        Returns:
            List of security findings related to injection vulnerabilities
        """
        findings = []
        
        try:
            # Check for SQL injection patterns
            sql_findings = self._assess_sql_injection(analysis_results)
            findings.extend(sql_findings)
            
            # Check for command injection patterns
            command_findings = self._assess_command_injection(analysis_results)
            findings.extend(command_findings)
            
            # Check for LDAP injection patterns
            ldap_findings = self._assess_ldap_injection(analysis_results)
            findings.extend(ldap_findings)
            
            # Check for NoSQL injection patterns
            nosql_findings = self._assess_nosql_injection(analysis_results)
            findings.extend(nosql_findings)
            
            # Check API calls for injection risks
            api_findings = self._assess_api_injection_risks(analysis_results)
            findings.extend(api_findings)
            
        except Exception as e:
            self.logger.error(f"Injection assessment failed: {str(e)}")
        
        return findings
    
    def _assess_sql_injection(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for SQL injection vulnerabilities"""
        findings = []
        
        # Check strings for SQL patterns
        string_results = analysis_results.get('string_analysis', {})
        if hasattr(string_results, 'to_dict'):
            string_data = string_results.to_dict()
        else:
            string_data = string_results
        
        all_strings = []
        if isinstance(string_data, dict):
            # Collect all string types
            for key in ['emails', 'urls', 'domains']:
                strings = string_data.get(key, [])
                if isinstance(strings, list):
                    all_strings.extend(strings)
        
        # Look for SQL injection patterns in strings
        sql_evidence = []
        for string in all_strings:
            if isinstance(string, str):
                for pattern in self.sql_patterns:
                    if pattern.lower() in string.lower():
                        sql_evidence.append(f"Found SQL pattern '{pattern}' in string: {string[:100]}...")
                        break
        
        if sql_evidence:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Potential SQL Injection Vulnerability",
                description="SQL query patterns found in strings that may indicate SQL injection vulnerabilities if user input is not properly sanitized.",
                evidence=sql_evidence,
                recommendations=[
                    "Use parameterized queries or prepared statements",
                    "Implement input validation and sanitization",
                    "Use ORM frameworks that provide built-in protection",
                    "Apply the principle of least privilege for database access",
                    "Implement proper error handling to prevent information disclosure"
                ]
            ))
        
        return findings
    
    def _assess_command_injection(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for command injection vulnerabilities"""
        findings = []
        
        # Check API calls for command execution
        api_results = analysis_results.get('api_invocation', {})
        if hasattr(api_results, 'to_dict'):
            api_data = api_results.to_dict()
        else:
            api_data = api_results
        
        command_evidence = []
        
        # Check suspicious API calls
        suspicious_calls = api_data.get('suspicious_api_calls', [])
        for call in suspicious_calls:
            if isinstance(call, dict):
                api_name = call.get('called_class', '') + '.' + call.get('called_method', '')
                for pattern in self.command_patterns:
                    if pattern.lower() in api_name.lower():
                        command_evidence.append(f"Command execution API detected: {api_name}")
                        break
        
        # Check regular API calls
        api_calls = api_data.get('api_calls', [])
        for call in api_calls:
            if isinstance(call, dict):
                api_name = call.get('called_class', '') + '.' + call.get('called_method', '')
                if 'java.lang.Runtime.exec' in api_name or 'java.lang.ProcessBuilder' in api_name:
                    command_evidence.append(f"System command execution detected: {api_name}")
        
        if command_evidence:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.CRITICAL,
                title="Potential Command Injection Vulnerability",
                description="System command execution APIs detected that may be vulnerable to command injection if user input is not properly validated.",
                evidence=command_evidence,
                recommendations=[
                    "Avoid system command execution when possible",
                    "Use safe APIs instead of system commands",
                    "Implement strict input validation and sanitization",
                    "Use allowlists for acceptable input values",
                    "Run processes with minimal privileges"
                ]
            ))
        
        return findings
    
    def _assess_ldap_injection(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for LDAP injection vulnerabilities"""
        findings = []
        
        # Check strings for LDAP patterns
        string_results = analysis_results.get('string_analysis', {})
        if hasattr(string_results, 'to_dict'):
            string_data = string_results.to_dict()
        else:
            string_data = string_results
        
        ldap_evidence = []
        all_strings = []
        
        if isinstance(string_data, dict):
            for key in ['urls', 'domains']:
                strings = string_data.get(key, [])
                if isinstance(strings, list):
                    all_strings.extend(strings)
        
        for string in all_strings:
            if isinstance(string, str):
                for pattern in self.ldap_patterns:
                    if pattern.lower() in string.lower():
                        ldap_evidence.append(f"LDAP pattern found: {string}")
                        break
        
        if ldap_evidence:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Potential LDAP Injection Vulnerability",
                description="LDAP-related patterns found that may indicate LDAP injection vulnerabilities if user input is not properly escaped.",
                evidence=ldap_evidence,
                recommendations=[
                    "Use parameterized LDAP queries",
                    "Implement proper input escaping for LDAP special characters",
                    "Validate and sanitize all user inputs",
                    "Use LDAP APIs that provide built-in protection"
                ]
            ))
        
        return findings
    
    def _assess_nosql_injection(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for NoSQL injection vulnerabilities"""
        findings = []
        
        # Check strings for NoSQL patterns
        string_results = analysis_results.get('string_analysis', {})
        if hasattr(string_results, 'to_dict'):
            string_data = string_results.to_dict()
        else:
            string_data = string_results
        
        nosql_evidence = []
        all_strings = []
        
        if isinstance(string_data, dict):
            for key in ['emails', 'urls', 'domains']:
                strings = string_data.get(key, [])
                if isinstance(strings, list):
                    all_strings.extend(strings)
        
        for string in all_strings:
            if isinstance(string, str):
                for pattern in self.nosql_patterns:
                    if pattern in string:
                        nosql_evidence.append(f"NoSQL pattern found: {pattern} in {string[:50]}...")
                        break
        
        if nosql_evidence:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Potential NoSQL Injection Vulnerability",
                description="NoSQL query patterns found that may indicate NoSQL injection vulnerabilities.",
                evidence=nosql_evidence,
                recommendations=[
                    "Implement proper input validation for NoSQL queries",
                    "Use parameterized queries where available",
                    "Sanitize user input before including in queries",
                    "Apply schema validation for NoSQL documents"
                ]
            ))
        
        return findings
    
    def _assess_api_injection_risks(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess API calls for injection risks"""
        findings = []
        
        # Check for reflection usage which can lead to injection
        api_results = analysis_results.get('api_invocation', {})
        if hasattr(api_results, 'to_dict'):
            api_data = api_results.to_dict()
        else:
            api_data = api_results
        
        reflection_usage = api_data.get('reflection_usage', [])
        
        if reflection_usage:
            evidence = [f"Reflection API usage: {usage}" for usage in reflection_usage[:5]]  # Limit to first 5
            
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Reflection Usage May Enable Injection Attacks",
                description="Application uses reflection APIs which may be exploited for injection attacks if user input is not properly validated.",
                evidence=evidence,
                recommendations=[
                    "Avoid reflection with user-controlled input",
                    "Implement strict validation for reflection parameters",
                    "Use allowlists for acceptable class and method names",
                    "Consider alternative approaches that don't require reflection"
                ]
            ))
        
        return findings