#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for CVE Assessment module

Tests the CVE vulnerability scanning functionality including:
- CVE assessment initialization and configuration
- Library extraction and filtering
- Vulnerability scanning and deduplication
- Security finding generation
- Error handling and edge cases
"""

import pytest
import unittest.mock as mock

from src.dexray_insight.security.cve_assessment import CVEAssessment
from src.dexray_insight.security.cve.models.vulnerability import CVEVulnerability, CVESeverity
from src.dexray_insight.core.base_classes import AnalysisSeverity


class TestCVEAssessment:
    """Test suite for CVE Assessment functionality"""
    
    @pytest.fixture
    def base_config(self):
        """Base configuration for CVE assessment tests"""
        return {
            'security': {
                'cve_scanning': {
                    'enabled': True,
                    'sources': {
                        'osv': {'enabled': True, 'api_key': None},
                        'nvd': {'enabled': True, 'api_key': 'test_key'},
                        'github': {'enabled': True, 'api_key': 'test_token'}
                    },
                    'max_workers': 2,
                    'timeout_seconds': 10,
                    'min_confidence': 0.7,
                    'cache_duration_hours': 1,
                    'max_libraries_per_source': 5
                }
            }
        }
    
    @pytest.fixture
    def disabled_config(self):
        """Configuration with CVE scanning disabled"""
        return {
            'security': {
                'cve_scanning': {
                    'enabled': False
                }
            }
        }
    
    @pytest.fixture
    def sample_library_results(self):
        """Sample library detection results for testing"""
        return {
            'library_detection': {
                'detected_libraries': [
                    {
                        'name': 'com.squareup.okhttp3:okhttp',
                        'version': '3.8.0',
                        'confidence': 0.9,
                        'category': 'networking',
                        'detection_method': 'heuristic'
                    },
                    {
                        'name': 'com.google.firebase:firebase-core',
                        'version': '16.0.0',
                        'confidence': 0.85,
                        'category': 'analytics',
                        'detection_method': 'similarity'
                    },
                    {
                        'name': 'androidx.core:core',
                        'version': '1.0.0',
                        'confidence': 0.6,  # Below threshold
                        'category': 'framework',
                        'detection_method': 'pattern'
                    }
                ]
            }
        }
    
    @pytest.fixture
    def sample_vulnerabilities(self):
        """Sample CVE vulnerabilities for testing"""
        return [
            CVEVulnerability(
                cve_id='CVE-2021-0001',
                summary='Critical vulnerability in OkHttp',
                description='Remote code execution vulnerability',
                severity=CVESeverity.CRITICAL,
                cvss_score=9.8,
                source='osv'
            ),
            CVEVulnerability(
                cve_id='CVE-2021-0002',
                summary='High severity Firebase vulnerability',
                description='Data exposure vulnerability',
                severity=CVESeverity.HIGH,
                cvss_score=7.5,
                source='nvd'
            ),
            CVEVulnerability(
                cve_id='CVE-2021-0001',  # Duplicate for deduplication testing
                summary='Critical vulnerability in OkHttp (duplicate)',
                description='Remote code execution vulnerability',
                severity=CVESeverity.CRITICAL,
                cvss_score=9.8,
                source='github'
            )
        ]
    
    def test_cve_assessment_initialization_enabled(self, base_config):
        """Test CVE assessment initialization when enabled"""
        assessment = CVEAssessment(base_config)
        
        assert hasattr(assessment, 'clients')
        assert hasattr(assessment, 'cache_manager')
        assert hasattr(assessment, 'scan_config')
        assert assessment.scan_config['max_workers'] == 2
        assert assessment.scan_config['timeout_seconds'] == 10
        assert assessment.scan_config['min_confidence'] == 0.7
    
    def test_cve_assessment_initialization_disabled(self, disabled_config):
        """Test CVE assessment initialization when disabled"""
        assessment = CVEAssessment(disabled_config)
        
        assert assessment.sources_config == {}
        assert assessment.scan_config == {}
        assert assessment.cache_manager is None
        assert assessment.clients == {}
    
    @mock.patch('src.dexray_insight.security.cve_assessment.OSVClient')
    @mock.patch('src.dexray_insight.security.cve_assessment.NVDClient')
    @mock.patch('src.dexray_insight.security.cve_assessment.GitHubAdvisoryClient')
    def test_client_initialization(self, mock_github, mock_nvd, mock_osv, base_config):
        """Test CVE client initialization"""
        # Mock health checks to return True
        mock_osv.return_value.health_check.return_value = True
        mock_nvd.return_value.health_check.return_value = True
        mock_github.return_value.health_check.return_value = True
        
        assessment = CVEAssessment(base_config)
        
        # Verify clients were initialized
        assert 'osv' in assessment.clients
        assert 'nvd' in assessment.clients
        assert 'github' in assessment.clients
        
        # Verify constructor calls
        mock_osv.assert_called_once()
        mock_nvd.assert_called_once()
        mock_github.assert_called_once()
    
    def test_extract_scannable_libraries(self, base_config, sample_library_results):
        """Test library extraction and filtering for CVE scanning"""
        assessment = CVEAssessment(base_config)
        
        scannable = assessment._extract_scannable_libraries(sample_library_results)
        
        # Should extract 2 libraries (1 filtered out due to low confidence)
        assert len(scannable) == 2
        
        # Check first library
        assert scannable[0]['name'] == 'com.squareup.okhttp3:okhttp'
        assert scannable[0]['version'] == '3.8.0'
        assert scannable[0]['confidence'] == 0.9
        
        # Check second library
        assert scannable[1]['name'] == 'com.google.firebase:firebase-core'
        assert scannable[1]['version'] == '16.0.0'
        assert scannable[1]['confidence'] == 0.85
    
    def test_extract_scannable_libraries_max_limit(self, base_config, sample_library_results):
        """Test library extraction respects max libraries limit"""
        # Set very low max limit
        base_config['security']['cve_scanning']['max_libraries_per_source'] = 1
        assessment = CVEAssessment(base_config)
        
        scannable = assessment._extract_scannable_libraries(sample_library_results)
        
        # Should only return 1 library (highest confidence)
        assert len(scannable) == 1
        assert scannable[0]['name'] == 'com.squareup.okhttp3:okhttp'
        assert scannable[0]['confidence'] == 0.9
    
    def test_extract_scannable_libraries_empty_results(self, base_config):
        """Test library extraction with empty results"""
        assessment = CVEAssessment(base_config)
        
        empty_results = {'library_detection': {'detected_libraries': []}}
        scannable = assessment._extract_scannable_libraries(empty_results)
        
        assert len(scannable) == 0
    
    def test_deduplicate_vulnerabilities(self, base_config, sample_vulnerabilities):
        """Test vulnerability deduplication logic"""
        assessment = CVEAssessment(base_config)
        
        unique_vulns = assessment._deduplicate_vulnerabilities(sample_vulnerabilities)
        
        # Should have 2 unique vulnerabilities (duplicate CVE-2021-0001 removed)
        assert len(unique_vulns) == 2
        
        cve_ids = [vuln.cve_id for vuln in unique_vulns]
        assert 'CVE-2021-0001' in cve_ids
        assert 'CVE-2021-0002' in cve_ids
        assert cve_ids.count('CVE-2021-0001') == 1  # Only one instance
    
    def test_create_security_findings(self, base_config, sample_vulnerabilities, sample_library_results):
        """Test security finding generation from vulnerabilities"""
        assessment = CVEAssessment(base_config)
        libraries = assessment._extract_scannable_libraries(sample_library_results)
        
        findings = assessment._create_security_findings(sample_vulnerabilities, libraries)
        
        # Should have findings for critical and high severity + summary
        assert len(findings) >= 3
        
        # Check for critical finding
        critical_findings = [f for f in findings if f.severity == AnalysisSeverity.CRITICAL]
        assert len(critical_findings) >= 1
        assert 'CVE-2021-0001' in critical_findings[0].evidence[0]
        
        # Check for high finding
        high_findings = [f for f in findings if f.severity == AnalysisSeverity.HIGH]
        assert len(high_findings) >= 1
        assert 'CVE-2021-0002' in high_findings[0].evidence[0]
        
        # Check for summary finding
        summary_findings = [f for f in findings if f.severity == AnalysisSeverity.INFO and 'Summary' in f.title]
        assert len(summary_findings) >= 1
    
    def test_create_severity_finding(self, base_config, sample_vulnerabilities):
        """Test creation of severity-specific security findings"""
        assessment = CVEAssessment(base_config)
        
        critical_vulns = [v for v in sample_vulnerabilities if v.severity == CVESeverity.CRITICAL]
        
        finding = assessment._create_severity_finding(
            critical_vulns,
            AnalysisSeverity.CRITICAL,
            "Test Critical Finding",
            "Test description"
        )
        
        assert finding.severity == AnalysisSeverity.CRITICAL
        assert finding.title == "Test Critical Finding"
        assert finding.description == "Test description"
        assert len(finding.evidence) >= 1
        assert 'CVE-2021-0001' in finding.evidence[0]
        assert len(finding.recommendations) >= 3
    
    @mock.patch.object(CVEAssessment, '_scan_libraries_for_cves')
    @mock.patch.object(CVEAssessment, '_extract_scannable_libraries')
    def test_assess_disabled_scanning(self, mock_extract, mock_scan, disabled_config, sample_library_results):
        """Test assessment when CVE scanning is disabled"""
        assessment = CVEAssessment(disabled_config)
        
        findings = assessment.assess(sample_library_results)
        
        # Should return empty findings and not call scanning methods
        assert len(findings) == 0
        mock_extract.assert_not_called()
        mock_scan.assert_not_called()
    
    @mock.patch.object(CVEAssessment, '_scan_libraries_for_cves')
    def test_assess_no_scannable_libraries(self, mock_scan, base_config):
        """Test assessment when no libraries are scannable"""
        assessment = CVEAssessment(base_config)
        
        # Empty library results
        empty_results = {'library_detection': {'detected_libraries': []}}
        findings = assessment.assess(empty_results)
        
        # Should return empty findings and not call scanning
        assert len(findings) == 0
        mock_scan.assert_not_called()
    
    @mock.patch.object(CVEAssessment, '_scan_libraries_for_cves')
    def test_assess_with_vulnerabilities(self, mock_scan, base_config, sample_library_results, sample_vulnerabilities):
        """Test assessment when vulnerabilities are found"""
        assessment = CVEAssessment(base_config)
        mock_scan.return_value = sample_vulnerabilities
        
        findings = assessment.assess(sample_library_results)
        
        # Should return multiple findings
        assert len(findings) >= 3
        mock_scan.assert_called_once()
        
        # Check that various severity levels are represented
        severities = [f.severity for f in findings]
        assert AnalysisSeverity.CRITICAL in severities
        assert AnalysisSeverity.HIGH in severities
        assert AnalysisSeverity.INFO in severities
    
    @mock.patch.object(CVEAssessment, '_scan_libraries_for_cves')
    def test_assess_no_vulnerabilities_found(self, mock_scan, base_config, sample_library_results):
        """Test assessment when no vulnerabilities are found"""
        assessment = CVEAssessment(base_config)
        mock_scan.return_value = []  # No vulnerabilities found
        
        findings = assessment.assess(sample_library_results)
        
        # Should return info finding about successful scan
        assert len(findings) == 1
        assert findings[0].severity == AnalysisSeverity.INFO
        assert "CVE Vulnerability Scan Completed" in findings[0].title
        assert "No known vulnerabilities found" in findings[0].description
    
    @mock.patch.object(CVEAssessment, '_extract_scannable_libraries')
    def test_assess_exception_handling(self, mock_extract, base_config, sample_library_results):
        """Test assessment exception handling"""
        assessment = CVEAssessment(base_config)
        mock_extract.side_effect = Exception("Test error")
        
        findings = assessment.assess(sample_library_results)
        
        # Should return error finding
        assert len(findings) == 1
        assert findings[0].severity == AnalysisSeverity.LOW
        assert "CVE Scanning Error" in findings[0].title
        assert "Test error" in findings[0].description
    
    def test_get_scan_statistics(self, base_config):
        """Test CVE scan statistics gathering"""
        assessment = CVEAssessment(base_config)
        
        stats = assessment.get_scan_statistics()
        
        assert 'clients_initialized' in stats
        assert 'cache_stats' in stats
        assert 'sources_enabled' in stats
        assert isinstance(stats['sources_enabled'], list)
    
    def test_configuration_precedence(self, base_config):
        """Test configuration value precedence and defaults"""
        # Test with partial configuration
        partial_config = {
            'security': {
                'cve_scanning': {
                    'enabled': True,
                    'max_workers': 5  # Only set max_workers
                }
            }
        }
        
        assessment = CVEAssessment(partial_config)
        
        # Should use provided value
        assert assessment.scan_config['max_workers'] == 5
        
        # Should use defaults for missing values
        assert assessment.scan_config['timeout_seconds'] == 30
        assert assessment.scan_config['min_confidence'] == 0.7
        assert assessment.scan_config['cache_duration_hours'] == 24
    
    @pytest.mark.parametrize("confidence,expected_count", [
        (0.5, 3),  # All libraries included
        (0.7, 2),  # Default threshold, 2 libraries
        (0.9, 1),  # High threshold, 1 library
        (1.0, 0),  # Impossible threshold, 0 libraries
    ])
    def test_confidence_filtering(self, base_config, sample_library_results, confidence, expected_count):
        """Test library filtering by confidence threshold"""
        base_config['security']['cve_scanning']['min_confidence'] = confidence
        assessment = CVEAssessment(base_config)
        
        scannable = assessment._extract_scannable_libraries(sample_library_results)
        
        assert len(scannable) == expected_count


@pytest.mark.integration
class TestCVEAssessmentIntegration:
    """Integration tests for CVE Assessment with real components"""
    
    @pytest.fixture
    def real_config(self):
        """Configuration for integration testing"""
        return {
            'security': {
                'cve_scanning': {
                    'enabled': True,
                    'sources': {
                        'osv': {'enabled': True, 'api_key': None},
                        'nvd': {'enabled': False, 'api_key': None},  # Disable to avoid rate limits
                        'github': {'enabled': False, 'api_key': None}  # Disable to avoid rate limits
                    },
                    'max_workers': 1,
                    'timeout_seconds': 5,
                    'min_confidence': 0.8,
                    'cache_duration_hours': 1,
                    'max_libraries_per_source': 2
                }
            }
        }
    
    @pytest.fixture
    def vulnerable_library_results(self):
        """Library results with known vulnerable libraries"""
        return {
            'library_detection': {
                'detected_libraries': [
                    {
                        'name': 'com.squareup.okhttp3:okhttp',
                        'version': '3.8.0',  # Known vulnerable version
                        'confidence': 0.95,
                        'category': 'networking',
                        'detection_method': 'heuristic'
                    }
                ]
            }
        }
    
    @pytest.mark.slow
    def test_real_cve_scanning(self, real_config, vulnerable_library_results):
        """Test CVE scanning with real API calls (slow test)"""
        assessment = CVEAssessment(real_config)
        
        # Skip if no clients were initialized (e.g., network issues)
        if not assessment.clients:
            pytest.skip("No CVE clients available for integration test")
        
        findings = assessment.assess(vulnerable_library_results)
        
        # Should return some findings (at least the scan completion)
        assert len(findings) >= 1
        
        # If vulnerabilities were found, check structure
        vuln_findings = [f for f in findings if 'CVE' in f.title and f.severity != AnalysisSeverity.INFO]
        if vuln_findings:
            finding = vuln_findings[0]
            assert hasattr(finding, 'evidence')
            assert hasattr(finding, 'recommendations')
            assert len(finding.evidence) > 0
            assert len(finding.recommendations) > 0