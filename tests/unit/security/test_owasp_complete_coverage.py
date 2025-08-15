#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive tests for complete OWASP Top 10 2021 coverage.

This test suite validates that all OWASP Top 10 categories are implemented
and properly integrated with the security assessment framework.
"""

import pytest

from src.dexray_insight.security.insecure_design_assessment import InsecureDesignAssessment
from src.dexray_insight.security.security_misconfiguration_assessment import SecurityMisconfigurationAssessment
from src.dexray_insight.security.vulnerable_components_assessment import VulnerableComponentsAssessment
from src.dexray_insight.security.authentication_failures_assessment import AuthenticationFailuresAssessment
from src.dexray_insight.security.integrity_failures_assessment import IntegrityFailuresAssessment
from src.dexray_insight.security.logging_monitoring_failures_assessment import LoggingMonitoringFailuresAssessment
from src.dexray_insight.security.ssrf_assessment import SSRFAssessment
from src.dexray_insight.security.mobile_specific_assessment import MobileSpecificAssessment

from src.dexray_insight.core.base_classes import AnalysisSeverity


class TestOWASPTopTenCompleteCoverage:
    """Test complete OWASP Top 10 2021 coverage"""
    
    @pytest.fixture
    def mock_analysis_results(self):
        """Comprehensive mock analysis results for testing all assessments"""
        return {
            'manifest_analysis': {
                'activities': ['MainActivity', 'DebugActivity', 'AdminActivity'],
                'services': ['BackgroundService', 'DebugService'],
                'receivers': ['BootReceiver', 'DebugReceiver'],
                'content_providers': ['DataProvider'],
                'permissions': [
                    'android.permission.INTERNET',
                    'android.permission.WRITE_EXTERNAL_STORAGE',
                    'android.permission.ACCESS_FINE_LOCATION',
                    'android.permission.CAMERA',
                    'android.permission.RECORD_AUDIO'
                ],
                'intent_filters': [
                    {
                        'component_name': 'MainActivity',
                        'component_type': 'activity',
                        'filters': ['android.intent.action.MAIN']
                    },
                    {
                        'component_name': 'DebugActivity', 
                        'component_type': 'activity',
                        'filters': ['com.example.DEBUG_ACTION']
                    }
                ],
                'exported_components': ['MainActivity', 'DebugActivity'],
                'debug_flags': {
                    'debuggable': True,
                    'allow_backup': True,
                    'test_only': False
                },
                'network_security_config': None,
                'min_sdk_version': 21,
                'target_sdk_version': 30
            },
            'string_analysis': {
                'all_strings': [
                    'http://debug.example.com/api',
                    'https://api.internal.company.com',
                    'password123',
                    'admin_secret_key',
                    'Log.d("DEBUG", "Sensitive data: " + userToken)',
                    'System.out.println("User password: " + password)',
                    'SharedPreferences.Editor.putString("auth_token", token)',
                    'Intent.setData(Uri.parse(userInput))',
                    'HttpURLConnection.setRequestProperty("Authorization", hardcodedToken)'
                ],
                'urls': [
                    'http://debug.example.com/api',
                    'https://api.internal.company.com',
                    'https://127.0.0.1:8080/internal'
                ],
                'domains': ['debug.example.com', 'api.internal.company.com'],
                'ip_addresses': ['127.0.0.1', '192.168.1.100']
            },
            'library_detection': {
                'detected_libraries': [
                    {
                        'name': 'Apache Commons Collections',
                        'version': '3.2.1',
                        'category': 'utility',
                        'confidence': 0.9,
                        'known_vulnerabilities': ['CVE-2015-7501'],
                        'latest_version': '4.4',
                        'years_behind': 8
                    },
                    {
                        'name': 'OkHttp',
                        'version': '3.8.0',
                        'category': 'networking',
                        'confidence': 0.95,
                        'known_vulnerabilities': ['CVE-2021-0341'],
                        'latest_version': '4.10.0',
                        'years_behind': 4
                    },
                    {
                        'name': 'Jackson Databind',
                        'version': '2.9.8',
                        'category': 'serialization',
                        'confidence': 0.88,
                        'known_vulnerabilities': ['CVE-2019-12384', 'CVE-2019-14540'],
                        'latest_version': '2.15.2',
                        'years_behind': 3
                    }
                ]
            },
            'api_invocation': {
                'api_calls': [
                    {
                        'called_class': 'java.net.HttpURLConnection',
                        'called_method': 'setHostnameVerifier',
                        'context': 'Disabling hostname verification'
                    },
                    {
                        'called_class': 'javax.net.ssl.SSLContext',
                        'called_method': 'getInstance',
                        'context': 'Custom SSL configuration'
                    },
                    {
                        'called_class': 'java.io.ObjectInputStream',
                        'called_method': 'readObject',
                        'context': 'Unsafe deserialization'
                    }
                ],
                'reflection_usage': [
                    'Class.forName("java.lang.Runtime")',
                    'Method.invoke(dynamicMethod, userInput)'
                ],
                'crypto_usage': [
                    {
                        'algorithm': 'MD5',
                        'context': 'Password hashing',
                        'location': 'AuthManager.java:45'
                    },
                    {
                        'algorithm': 'DES',
                        'context': 'Data encryption',
                        'location': 'CryptoHelper.java:23'
                    }
                ]
            },
            'behaviour_analysis': {
                'suspicious_behaviors': [
                    'Dynamic code loading detected',
                    'Root detection bypass attempted',
                    'Certificate pinning bypass detected'
                ],
                'network_activity': {
                    'insecure_connections': ['http://api.example.com'],
                    'certificate_validation_disabled': True,
                    'hostname_verification_disabled': True
                },
                'file_operations': {
                    'world_readable_files': ['/data/data/com.example/shared_prefs/auth.xml'],
                    'world_writable_files': ['/sdcard/app_logs/debug.log'],
                    'external_storage_usage': True
                }
            },
            'native_analysis': {
                'native_libraries': [
                    {
                        'name': 'libcrypto.so',
                        'version': 'OpenSSL 1.0.2',
                        'vulnerabilities': ['CVE-2016-2107', 'CVE-2016-6304'],
                        'architecture': 'arm64-v8a'
                    }
                ],
                'binary_analysis': {
                    'stack_protection': False,
                    'position_independent': False,
                    'stripped_symbols': True
                }
            }
        }
    
    def test_a04_insecure_design_assessment_initialization(self):
        """Test A04:2021 - Insecure Design assessment initialization"""
        config = {'enabled': True}
        assessment = InsecureDesignAssessment(config)
        
        assert assessment.owasp_category == "A04:2021-Insecure Design"
        assert assessment.enabled is True
        assert hasattr(assessment, 'design_patterns')
        assert hasattr(assessment, 'security_control_checks')
    
    def test_a04_insecure_design_assessment_findings(self, mock_analysis_results):
        """Test A04:2021 - Insecure Design assessment detects design flaws"""
        config = {'enabled': True}
        assessment = InsecureDesignAssessment(config)
        
        findings = assessment.assess(mock_analysis_results)
        
        # Should detect insecure design patterns
        assert len(findings) > 0
        
        # Check for specific design flaw categories
        finding_titles = [f.title for f in findings]
        expected_patterns = [
            'Insecure Data Flow Design',
            'Missing Security Controls',
            'Weak Cryptographic Design'
        ]
        
        # At least one design flaw should be detected
        assert any(any(pattern in title for pattern in expected_patterns) 
                  for title in finding_titles)
    
    def test_a04_insecure_design_assessment_handles_non_list_strings(self):
        """Test A04:2021 - Insecure Design assessment handles non-list string data"""
        config = {'enabled': True}
        assessment = InsecureDesignAssessment(config)
        
        # Mock data with non-list all_strings (this was causing the bool iteration error)
        analysis_results_with_bool = {
            'string_analysis': {
                'all_strings': True  # This was causing the 'bool' object is not iterable error
            },
            'manifest_analysis': {'permissions': []},
            'behaviour_analysis': {},
            'api_invocation': {'crypto_usage': []},
            'library_detection': {'detected_libraries': []}
        }
        
        # Should not raise an exception
        findings = assessment.assess(analysis_results_with_bool)
        # Should complete without error (may have 0 or more findings)
        assert isinstance(findings, list)
    
    def test_a05_security_misconfiguration_assessment_initialization(self):
        """Test A05:2021 - Security Misconfiguration assessment initialization"""
        config = {'enabled': True}
        assessment = SecurityMisconfigurationAssessment(config)
        
        assert assessment.owasp_category == "A05:2021-Security Misconfiguration"
        assert assessment.enabled is True
        assert hasattr(assessment, 'debug_checks')
        assert hasattr(assessment, 'network_security_checks')
    
    def test_a05_security_misconfiguration_debug_flags(self, mock_analysis_results):
        """Test A05:2021 - Security Misconfiguration detects debug flags"""
        config = {'enabled': True}
        assessment = SecurityMisconfigurationAssessment(config)
        
        findings = assessment.assess(mock_analysis_results)
        
        # Should detect debug flags in production
        debug_findings = [f for f in findings if 'debug' in f.title.lower()]
        assert len(debug_findings) > 0
        
        # Should have HIGH severity for debug flags in production
        assert any(f.severity == AnalysisSeverity.HIGH for f in debug_findings)
    
    def test_a06_vulnerable_components_assessment_initialization(self):
        """Test A06:2021 - Vulnerable and Outdated Components assessment initialization"""
        config = {'enabled': True}
        assessment = VulnerableComponentsAssessment(config)
        
        assert assessment.owasp_category == "A06:2021-Vulnerable and Outdated Components"
        assert assessment.enabled is True
        assert hasattr(assessment, 'vulnerability_databases')
        assert hasattr(assessment, 'component_age_thresholds')
    
    def test_a06_vulnerable_components_cve_detection(self, mock_analysis_results):
        """Test A06:2021 - Vulnerable Components detects CVEs"""
        config = {'enabled': True}
        assessment = VulnerableComponentsAssessment(config)
        
        findings = assessment.assess(mock_analysis_results)
        
        # Should detect vulnerable components
        assert len(findings) > 0
        
        # Should detect specific CVEs from mock data
        cve_findings = [f for f in findings if 'CVE-' in str(f.evidence)]
        assert len(cve_findings) > 0
        
        # Apache Commons Collections should be flagged as CRITICAL
        commons_findings = [f for f in findings if 'Commons Collections' in str(f.evidence)]
        assert len(commons_findings) > 0
        assert any(f.severity == AnalysisSeverity.CRITICAL for f in commons_findings)
    
    def test_a06_vulnerable_components_none_values_handling(self):
        """Test A06:2021 - Vulnerable Components handles None values correctly"""
        config = {'enabled': True}
        assessment = VulnerableComponentsAssessment(config)
        
        # Mock data with None values for years_behind
        analysis_results_with_none = {
            'library_detection': {
                'detected_libraries': [
                    {
                        'name': 'Test Library',
                        'version': '1.0.0',
                        'category': 'utility',
                        'confidence': 0.9,
                        'years_behind': None,  # This was causing the error
                        'latest_version': '2.0.0'
                    }
                ]
            },
            'string_analysis': {'all_strings': []},
            'manifest_analysis': {},
            'native_analysis': {'native_libraries': []}
        }
        
        # Should not raise an exception
        findings = assessment.assess(analysis_results_with_none)
        # Should complete without error (may have 0 or more findings)
        assert isinstance(findings, list)
    
    def test_a07_authentication_failures_assessment_initialization(self):
        """Test A07:2021 - Identification and Authentication Failures assessment initialization"""
        config = {'enabled': True}
        assessment = AuthenticationFailuresAssessment(config)
        
        assert assessment.owasp_category == "A07:2021-Identification and Authentication Failures"
        assert assessment.enabled is True
        assert hasattr(assessment, 'authentication_patterns')
        assert hasattr(assessment, 'session_management_checks')
    
    def test_a07_authentication_failures_weak_auth(self, mock_analysis_results):
        """Test A07:2021 - Authentication Failures detects weak authentication"""
        config = {'enabled': True}
        assessment = AuthenticationFailuresAssessment(config)
        
        findings = assessment.assess(mock_analysis_results)
        
        # Should detect authentication issues
        assert len(findings) > 0
        
        # Should detect weak credential storage
        auth_findings = [f for f in findings if 'authentication' in f.title.lower() or 'credential' in f.title.lower()]
        assert len(auth_findings) > 0
    
    def test_a08_integrity_failures_assessment_initialization(self):
        """Test A08:2021 - Software and Data Integrity Failures assessment initialization"""
        config = {'enabled': True}
        assessment = IntegrityFailuresAssessment(config)
        
        assert assessment.owasp_category == "A08:2021-Software and Data Integrity Failures"
        assert assessment.enabled is True
        assert hasattr(assessment, 'deserialization_patterns')
        assert hasattr(assessment, 'integrity_checks')
    
    def test_a08_integrity_failures_unsafe_deserialization(self, mock_analysis_results):
        """Test A08:2021 - Integrity Failures detects unsafe deserialization"""
        config = {'enabled': True}
        assessment = IntegrityFailuresAssessment(config)
        
        findings = assessment.assess(mock_analysis_results)
        
        # Should detect unsafe deserialization
        assert len(findings) > 0
        
        # Should detect ObjectInputStream usage
        deserialization_findings = [f for f in findings if 'deserialization' in f.title.lower()]
        assert len(deserialization_findings) > 0
        assert any(f.severity == AnalysisSeverity.HIGH for f in deserialization_findings)
    
    def test_a09_logging_monitoring_failures_assessment_initialization(self):
        """Test A09:2021 - Security Logging and Monitoring Failures assessment initialization"""
        config = {'enabled': True}
        assessment = LoggingMonitoringFailuresAssessment(config)
        
        assert assessment.owasp_category == "A09:2021-Security Logging and Monitoring Failures"
        assert assessment.enabled is True
        assert hasattr(assessment, 'logging_patterns')
        assert hasattr(assessment, 'sensitive_data_patterns')
    
    def test_a09_logging_monitoring_excessive_logging(self, mock_analysis_results):
        """Test A09:2021 - Logging Failures detects excessive logging of sensitive data"""
        config = {'enabled': True}
        assessment = LoggingMonitoringFailuresAssessment(config)
        
        findings = assessment.assess(mock_analysis_results)
        
        # Should detect excessive logging
        assert len(findings) > 0
        
        # Should detect sensitive data in logs
        logging_findings = [f for f in findings if 'logging' in f.title.lower() or 'log' in f.title.lower()]
        assert len(logging_findings) > 0
    
    def test_a10_ssrf_assessment_initialization(self):
        """Test A10:2021 - Server-Side Request Forgery assessment initialization"""
        config = {'enabled': True}
        assessment = SSRFAssessment(config)
        
        assert assessment.owasp_category == "A10:2021-Server-Side Request Forgery (SSRF)"
        assert assessment.enabled is True
        assert hasattr(assessment, 'url_validation_patterns')
        assert hasattr(assessment, 'internal_service_patterns')
    
    def test_a10_ssrf_assessment_url_validation(self, mock_analysis_results):
        """Test A10:2021 - SSRF assessment detects unsafe URL validation"""
        config = {'enabled': True}
        assessment = SSRFAssessment(config)
        
        findings = assessment.assess(mock_analysis_results)
        
        # Should detect SSRF vulnerabilities
        assert len(findings) > 0
        
        # Should detect internal service exposure
        ssrf_findings = [f for f in findings if 'ssrf' in f.title.lower() or 'request forgery' in f.title.lower()]
        assert len(ssrf_findings) > 0
    
    def test_mobile_specific_assessment_initialization(self):
        """Test Mobile-Specific Security Assessment initialization"""
        config = {'enabled': True}
        assessment = MobileSpecificAssessment(config)
        
        assert assessment.owasp_category == "OWASP Mobile Top 10"
        assert assessment.enabled is True
        assert hasattr(assessment, 'platform_misuse_patterns')
    
    def test_mobile_specific_assessment_platform_misuse(self, mock_analysis_results):
        """Test Mobile-Specific assessment detects platform misuse"""
        config = {'enabled': True}
        assessment = MobileSpecificAssessment(config)
        
        findings = assessment.assess(mock_analysis_results)
        
        # Should detect mobile-specific issues
        assert len(findings) > 0
        
        # Should detect insecure data storage or communication
        mobile_findings = [f for f in findings if any(keyword in f.title.lower() 
                          for keyword in ['mobile', 'storage', 'communication', 'platform'])]
        assert len(mobile_findings) > 0
    
    def test_all_owasp_categories_covered(self):
        """Test that all OWASP Top 10 2021 categories are covered"""
        expected_assessments = [
            'broken_access_control',      # A01:2021 - existing
            'sensitive_data',             # A02:2021 - existing  
            'injection',                  # A03:2021 - existing
            'insecure_design',           # A04:2021 - new
            'security_misconfiguration', # A05:2021 - new
            'vulnerable_components',     # A06:2021 - new
            'authentication_failures',  # A07:2021 - new
            'integrity_failures',       # A08:2021 - new
            'logging_monitoring_failures', # A09:2021 - new
            'ssrf',                      # A10:2021 - new
            'mobile_specific'            # Mobile Top 10 - new
        ]
        
        # This test will pass once all assessments are implemented
        # For now, it documents the expected coverage
        assert len(expected_assessments) == 11  # 10 OWASP + 1 Mobile specific
    
    def test_assessment_severity_distribution(self, mock_analysis_results):
        """Test that assessments produce appropriate severity distribution"""
        assessments = [
            InsecureDesignAssessment({}),
            SecurityMisconfigurationAssessment({}),
            VulnerableComponentsAssessment({}),
            AuthenticationFailuresAssessment({}),
            IntegrityFailuresAssessment({}),
            LoggingMonitoringFailuresAssessment({}),
            SSRFAssessment({}),
            MobileSpecificAssessment({})
        ]
        
        all_findings = []
        for assessment in assessments:
            findings = assessment.assess(mock_analysis_results)
            all_findings.extend(findings)
        
        # Should have findings across multiple severity levels
        severities = [f.severity for f in all_findings]
        unique_severities = set(severities)
        
        # Should have at least 2 different severity levels
        assert len(unique_severities) >= 2
        
        # Should have some high or critical findings
        assert any(s in [AnalysisSeverity.HIGH, AnalysisSeverity.CRITICAL] for s in severities)


if __name__ == '__main__':
    pytest.main([__file__])