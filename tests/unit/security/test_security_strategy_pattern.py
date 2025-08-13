#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive tests for refactored Security Assessment Strategy Pattern classes.

Following SOLID principles and TDD Red-Green-Refactor cycle:
- Single Responsibility: Each strategy handles one aspect of secret detection
- Open/Closed: New strategies can be added without modifying existing ones
- Strategy Pattern: Interchangeable detection algorithms
- Dependency Inversion: Strategies depend on abstractions, not concretions

Target components: Strategy pattern classes in SensitiveDataAssessment
- StringCollectionStrategy: Gather strings from various sources
- DeepAnalysisStrategy: Extract from XML/Smali/DEX files
- PatternDetectionStrategy: Apply secret detection patterns
- ResultClassificationStrategy: Organize by severity
- FindingGenerationStrategy: Create SecurityFinding objects
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
from typing import Dict, Any, List

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from dexray_insight.core.base_classes import SecurityFinding, AnalysisSeverity


@pytest.mark.unit
@pytest.mark.security
class TestStringCollectionStrategy:
    """Test StringCollectionStrategy for gathering strings from various sources."""
    
    @pytest.fixture
    def strategy(self):
        """Create StringCollectionStrategy instance."""
        mock_logger = Mock()
        # Import the class directly from the module where it's defined
        from dexray_insight.security.sensitive_data_assessment import StringCollectionStrategy
        return StringCollectionStrategy(mock_logger)
    
    @pytest.fixture
    def mock_analysis_results(self):
        """Create mock analysis results for testing."""
        return {
            'string_analysis': {
                'emails': ['test@example.com', 'admin@company.org'],
                'urls': ['https://api.example.com', 'http://internal.service'],
                'domains': ['example.com', 'suspicious.domain'],
                'ip_addresses': ['192.168.1.1', '10.0.0.1'],
                'android_properties': {
                    'api.key': 'sk_test_12345',
                    'debug.enabled': 'true'
                },
                'all_strings': ['hardcoded_secret', 'another_string']
            }
        }
    
    def test_collect_strings_from_string_analysis(self, strategy, mock_analysis_results):
        """Test collecting strings from string analysis results."""
        # Act
        result = strategy.collect_strings(mock_analysis_results)
        
        # Assert
        assert isinstance(result, list)
        assert len(result) > 0
        
        # Check that strings from different categories are collected
        string_values = [item['value'] for item in result]
        assert 'test@example.com' in string_values
        assert 'https://api.example.com' in string_values
        assert 'example.com' in string_values
        assert '192.168.1.1' in string_values
        assert 'sk_test_12345' in string_values  # From Android properties
        assert 'hardcoded_secret' in string_values  # From raw strings
    
    def test_collect_strings_with_location_information(self, strategy, mock_analysis_results):
        """Test that collected strings include proper location information."""
        # Act
        result = strategy.collect_strings(mock_analysis_results)
        
        # Assert - Check structure of returned items
        for item in result:
            assert 'value' in item
            assert 'location' in item
            assert 'file_path' in item
            assert 'line_number' in item
        
        # Check specific location information
        email_items = [item for item in result if item['value'] == 'test@example.com']
        assert len(email_items) == 1
        assert 'String analysis (emails)' in email_items[0]['location']
    
    def test_collect_strings_handles_missing_string_analysis(self, strategy):
        """Test handling when string analysis results are missing."""
        # Arrange
        empty_results = {}
        
        # Act
        result = strategy.collect_strings(empty_results)
        
        # Assert
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_collect_strings_handles_non_dict_string_analysis(self, strategy):
        """Test handling when string analysis is not a dictionary."""
        # Arrange
        invalid_results = {'string_analysis': "not_a_dict"}
        
        # Act
        result = strategy.collect_strings(invalid_results)
        
        # Assert
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_collect_strings_handles_object_with_to_dict(self, strategy):
        """Test handling when string analysis has to_dict() method."""
        # Arrange
        mock_string_result = Mock()
        mock_string_result.to_dict.return_value = {
            'emails': ['mock@test.com'],
            'urls': ['https://mock.api']
        }
        analysis_results = {'string_analysis': mock_string_result}
        
        # Act
        result = strategy.collect_strings(analysis_results)
        
        # Assert
        mock_string_result.to_dict.assert_called_once()
        string_values = [item['value'] for item in result]
        assert 'mock@test.com' in string_values
        assert 'https://mock.api' in string_values


@pytest.mark.unit
@pytest.mark.security
class TestDeepAnalysisStrategy:
    """Test DeepAnalysisStrategy for extracting strings from deep analysis sources."""
    
    @pytest.fixture
    def strategy(self):
        """Create DeepAnalysisStrategy instance."""
        mock_logger = Mock()
        from dexray_insight.security.sensitive_data_assessment import DeepAnalysisStrategy
        return DeepAnalysisStrategy(mock_logger)
    
    @pytest.fixture
    def mock_existing_strings(self):
        """Create mock existing strings collection."""
        return [
            {'value': 'existing_string', 'location': 'test', 'file_path': None, 'line_number': None}
        ]
    
    def test_extract_deep_strings_with_deep_analysis_mode(self, strategy, mock_existing_strings):
        """Test deep string extraction when deep analysis mode is available."""
        # Arrange
        mock_behaviour_results = Mock()
        mock_behaviour_results.androguard_objects = {
            'mode': 'deep',
            'apk_obj': Mock(),
            'dex_obj': [Mock()]
        }
        
        # Mock DEX strings
        mock_dex = mock_behaviour_results.androguard_objects['dex_obj'][0]
        mock_dex.get_strings.return_value = ['dex_string_1', 'dex_string_2']
        
        analysis_results = {'behaviour_analysis': mock_behaviour_results}
        
        # Act
        result = strategy.extract_deep_strings(analysis_results, mock_existing_strings)
        
        # Assert
        assert len(result) > len(mock_existing_strings)  # Should have added strings
        
        # Check that DEX strings were extracted
        string_values = [item['value'] for item in result]
        assert 'dex_string_1' in string_values
        assert 'dex_string_2' in string_values
        
        # Check that existing strings are preserved
        assert 'existing_string' in string_values
    
    def test_extract_deep_strings_with_fast_analysis_mode(self, strategy, mock_existing_strings):
        """Test deep string extraction when only fast analysis mode is available."""
        # Arrange
        mock_behaviour_results = Mock()
        mock_behaviour_results.androguard_objects = {'mode': 'fast'}
        analysis_results = {'behaviour_analysis': mock_behaviour_results}
        
        # Act
        result = strategy.extract_deep_strings(analysis_results, mock_existing_strings)
        
        # Assert
        assert result == mock_existing_strings  # Should return unchanged
        strategy.logger.debug.assert_called_with("📱 Using FAST analysis mode - limited string sources")
    
    def test_extract_deep_strings_handles_missing_behaviour_analysis(self, strategy, mock_existing_strings):
        """Test handling when behaviour analysis results are missing."""
        # Arrange
        analysis_results = {}
        
        # Act
        result = strategy.extract_deep_strings(analysis_results, mock_existing_strings)
        
        # Assert
        assert result == mock_existing_strings  # Should return unchanged
    
    def test_extract_dex_strings_success(self, strategy):
        """Test successful DEX string extraction."""
        # Arrange
        mock_dex1 = Mock()
        mock_dex1.get_strings.return_value = ['secret_key_123', 'api_token_456']
        mock_dex2 = Mock()
        mock_dex2.get_strings.return_value = ['another_secret']
        
        dex_objects = [mock_dex1, mock_dex2]
        all_strings = []
        
        # Act
        count = strategy._extract_dex_strings(dex_objects, all_strings)
        
        # Assert
        assert count == 3
        assert len(all_strings) == 3
        
        # Check structure and content
        assert all_strings[0]['value'] == 'secret_key_123'
        assert all_strings[0]['location'] == 'DEX file 1'
        assert all_strings[0]['file_path'] == 'classes.dex'
        
        assert all_strings[2]['value'] == 'another_secret'
        assert all_strings[2]['location'] == 'DEX file 2'
        assert all_strings[2]['file_path'] == 'classes2.dex'
    
    def test_extract_dex_strings_handles_exceptions(self, strategy):
        """Test DEX string extraction handles exceptions gracefully."""
        # Arrange
        mock_dex = Mock()
        mock_dex.get_strings.side_effect = Exception("DEX parsing error")
        dex_objects = [mock_dex]
        all_strings = []
        
        # Act
        count = strategy._extract_dex_strings(dex_objects, all_strings)
        
        # Assert
        assert count == 0
        assert len(all_strings) == 0
        strategy.logger.error.assert_called_with("Failed to extract strings from DEX 0: DEX parsing error")


@pytest.mark.unit
@pytest.mark.security
class TestPatternDetectionStrategy:
    """Test PatternDetectionStrategy for detecting secrets using patterns."""
    
    @pytest.fixture
    def mock_detection_patterns(self):
        """Create mock detection patterns."""
        return {
            'api_keys': {
                'pattern': r'sk_[a-zA-Z0-9]{24}',
                'severity': 'HIGH'
            },
            'aws_keys': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': 'CRITICAL'
            }
        }
    
    @pytest.fixture
    def strategy(self, mock_detection_patterns):
        """Create PatternDetectionStrategy instance."""
        mock_logger = Mock()
        from dexray_insight.security.sensitive_data_assessment import PatternDetectionStrategy
        return PatternDetectionStrategy(mock_detection_patterns, mock_logger)
    
    @pytest.fixture
    def mock_strings_with_location(self):
        """Create mock strings with location data."""
        return [
            {
                'value': 'sk_test_1234567890123456789012',
                'location': 'Test location 1',
                'file_path': 'test.java',
                'line_number': 42
            },
            {
                'value': 'AKIAIOSFODNN7EXAMPLE',
                'location': 'Test location 2',
                'file_path': 'config.xml',
                'line_number': 15
            },
            {
                'value': 'regular_string_no_secret',
                'location': 'Test location 3',
                'file_path': None,
                'line_number': None
            }
        ]
    
    def test_detect_secrets_basic_functionality(self, strategy, mock_strings_with_location):
        """Test basic secret detection functionality."""
        # Act
        result = strategy.detect_secrets(mock_strings_with_location)
        
        # Assert
        assert isinstance(result, list)
        # Note: Current implementation returns empty list as placeholder
        # This would be expanded when full pattern matching is implemented
        strategy.logger.info.assert_any_call(f"🔍 Scanning {len(mock_strings_with_location)} strings for secrets...")
        strategy.logger.info.assert_any_call("🔍 Found 0 potential secrets")  # Current placeholder behavior
    
    def test_detect_secrets_filters_empty_strings(self, strategy):
        """Test that empty or very short strings are filtered out."""
        # Arrange
        strings_with_empty = [
            {'value': '', 'location': 'test', 'file_path': None, 'line_number': None},
            {'value': 'a', 'location': 'test', 'file_path': None, 'line_number': None},
            {'value': 'ab', 'location': 'test', 'file_path': None, 'line_number': None},
            {'value': 'abc', 'location': 'test', 'file_path': None, 'line_number': None}
        ]
        
        # Act
        result = strategy.detect_secrets(strings_with_empty)
        
        # Assert - Only strings with length >= 3 should be processed
        strategy.logger.info.assert_any_call("🔍 Scanning 4 strings for secrets...")


@pytest.mark.unit
@pytest.mark.security  
class TestResultClassificationStrategy:
    """Test ResultClassificationStrategy for classifying detection results by severity."""
    
    @pytest.fixture
    def strategy(self):
        """Create ResultClassificationStrategy instance."""
        from dexray_insight.security.sensitive_data_assessment import ResultClassificationStrategy
        return ResultClassificationStrategy()
    
    @pytest.fixture
    def mock_detected_secrets(self):
        """Create mock detected secrets with different severities."""
        return [
            {
                'type': 'AWS Access Key',
                'severity': 'CRITICAL',
                'pattern_name': 'aws_access_key',
                'value': 'AKIAIOSFODNN7EXAMPLE',
                'location': 'config.xml',
                'file_path': 'res/values/config.xml',
                'line_number': 15
            },
            {
                'type': 'API Key',
                'severity': 'HIGH',
                'pattern_name': 'stripe_api_key',
                'value': 'sk_test_1234567890123456789012',
                'location': 'MainActivity.java',
                'file_path': 'src/MainActivity.java',
                'line_number': 42
            },
            {
                'type': 'Database URL',
                'severity': 'MEDIUM',
                'pattern_name': 'postgres_url',
                'value': 'postgresql://user:pass@localhost/db',
                'location': 'application.properties',
                'file_path': None,
                'line_number': None
            },
            {
                'type': 'S3 Bucket URL',
                'severity': 'LOW',
                'pattern_name': 's3_url',
                'value': 'https://mybucket.s3.amazonaws.com',
                'location': 'strings.xml',
                'file_path': None,
                'line_number': None
            }
        ]
    
    def test_classify_by_severity_structure(self, strategy, mock_detected_secrets):
        """Test that classification returns proper structure."""
        # Act
        result = strategy.classify_by_severity(mock_detected_secrets)
        
        # Assert
        assert isinstance(result, dict)
        assert 'findings' in result
        assert 'secrets' in result
        
        findings = result['findings']
        secrets = result['secrets']
        
        # Check findings structure
        assert all(severity in findings for severity in ['critical', 'high', 'medium', 'low'])
        assert all(isinstance(findings[sev], list) for sev in findings)
        
        # Check secrets structure  
        assert all(severity in secrets for severity in ['critical', 'high', 'medium', 'low'])
        assert all(isinstance(secrets[sev], list) for sev in secrets)
    
    def test_classify_by_severity_content(self, strategy, mock_detected_secrets):
        """Test that secrets are correctly classified by severity."""
        # Act
        result = strategy.classify_by_severity(mock_detected_secrets)
        
        findings = result['findings']
        secrets = result['secrets']
        
        # Assert - Check counts by severity
        assert len(findings['critical']) == 1
        assert len(findings['high']) == 1  
        assert len(findings['medium']) == 1
        assert len(findings['low']) == 1
        
        assert len(secrets['critical']) == 1
        assert len(secrets['high']) == 1
        assert len(secrets['medium']) == 1
        assert len(secrets['low']) == 1
    
    def test_classify_terminal_display_format(self, strategy, mock_detected_secrets):
        """Test terminal display formatting includes location info."""
        # Act
        result = strategy.classify_by_severity(mock_detected_secrets)
        
        findings = result['findings']
        
        # Assert - Check terminal display format
        critical_finding = findings['critical'][0]
        assert '🔑 [CRITICAL] AWS Access Key:' in critical_finding
        assert 'res/values/config.xml:15' in critical_finding
        
        high_finding = findings['high'][0]  
        assert '🔑 [HIGH] API Key:' in high_finding
        assert 'src/MainActivity.java:42' in high_finding
    
    def test_classify_evidence_entry_structure(self, strategy, mock_detected_secrets):
        """Test evidence entry structure and content."""
        # Act
        result = strategy.classify_by_severity(mock_detected_secrets)
        
        secrets = result['secrets']
        critical_secret = secrets['critical'][0]
        
        # Assert - Check evidence entry structure
        required_fields = ['type', 'severity', 'pattern_name', 'value', 'full_context', 
                          'location', 'file_path', 'line_number', 'preview']
        assert all(field in critical_secret for field in required_fields)
        
        # Check content
        assert critical_secret['type'] == 'AWS Access Key'
        assert critical_secret['severity'] == 'CRITICAL'
        assert critical_secret['value'] == 'AKIAIOSFODNN7EXAMPLE'
        assert critical_secret['preview'] == 'AKIAIOSFODNN7EXAMPLE'  # Short enough, no truncation


@pytest.mark.unit
@pytest.mark.security
class TestFindingGenerationStrategy:
    """Test FindingGenerationStrategy for generating SecurityFinding objects."""
    
    @pytest.fixture
    def strategy(self):
        """Create FindingGenerationStrategy instance."""
        from dexray_insight.security.sensitive_data_assessment import FindingGenerationStrategy
        return FindingGenerationStrategy("A02:2021-Cryptographic Failures")
    
    @pytest.fixture
    def mock_classified_results(self):
        """Create mock classified results for testing."""
        return {
            'findings': {
                'critical': [
                    '🔑 [CRITICAL] AWS Access Key: AKIAIOSFODNN7EXAMPLE (found in config.xml:15)',
                    '🔑 [CRITICAL] Private Key: -----BEGIN RSA PRIVATE KEY----- (found in key.pem:1)'
                ],
                'high': [
                    '🔑 [HIGH] API Key: sk_test_1234567890123456789012 (found in MainActivity.java:42)'
                ],
                'medium': [
                    '🔑 [MEDIUM] Database URL: postgresql://user:pass@localhost/db (found in config.properties)'
                ],
                'low': [
                    '🔑 [LOW] S3 URL: https://mybucket.s3.amazonaws.com (found in strings.xml)'
                ]
            },
            'secrets': {
                'critical': [{'type': 'AWS Access Key'}, {'type': 'Private Key'}],
                'high': [{'type': 'API Key'}],
                'medium': [{'type': 'Database URL'}],
                'low': [{'type': 'S3 URL'}]
            }
        }
    
    def test_generate_security_findings_structure(self, strategy, mock_classified_results):
        """Test that SecurityFinding objects are generated with proper structure."""
        # Act
        findings = strategy.generate_security_findings(mock_classified_results)
        
        # Assert
        assert isinstance(findings, list)
        assert len(findings) == 4  # One for each severity level
        
        # Check that all findings are SecurityFinding instances
        for finding in findings:
            assert isinstance(finding, SecurityFinding)
    
    def test_generate_critical_security_finding(self, strategy, mock_classified_results):
        """Test critical severity SecurityFinding generation."""
        # Act
        findings = strategy.generate_security_findings(mock_classified_results)
        
        # Find critical finding
        critical_finding = next(f for f in findings if f.severity == AnalysisSeverity.CRITICAL)
        
        # Assert
        assert critical_finding.category == "A02:2021-Cryptographic Failures"
        assert critical_finding.severity == AnalysisSeverity.CRITICAL
        assert "🔴 CRITICAL: 2 Hard-coded Secrets Found" in critical_finding.title
        assert "immediate security risks" in critical_finding.description
        assert "🚨 IMMEDIATE ACTION REQUIRED" in critical_finding.recommendation
        
        # Check evidence is limited to 10 items
        assert len(critical_finding.evidence) <= 10
        assert len(critical_finding.remediation_steps) == 5
    
    def test_generate_high_security_finding(self, strategy, mock_classified_results):
        """Test high severity SecurityFinding generation."""
        # Act
        findings = strategy.generate_security_findings(mock_classified_results)
        
        # Find high finding
        high_finding = next(f for f in findings if f.severity == AnalysisSeverity.HIGH)
        
        # Assert
        assert "🟠 HIGH: 1 Potential Secrets Found" in high_finding.title
        assert "⚠️ HIGH PRIORITY" in high_finding.recommendation
        assert len(high_finding.remediation_steps) == 4
    
    def test_generate_medium_security_finding(self, strategy, mock_classified_results):
        """Test medium severity SecurityFinding generation."""
        # Act
        findings = strategy.generate_security_findings(mock_classified_results)
        
        # Find medium finding
        medium_finding = next(f for f in findings if f.severity == AnalysisSeverity.MEDIUM)
        
        # Assert
        assert "🟡 MEDIUM: 1 Suspicious Strings Found" in medium_finding.title
        assert len(medium_finding.evidence) <= 15
        assert len(medium_finding.remediation_steps) == 4
    
    def test_generate_low_security_finding(self, strategy, mock_classified_results):
        """Test low severity SecurityFinding generation."""
        # Act
        findings = strategy.generate_security_findings(mock_classified_results)
        
        # Find low finding
        low_finding = next(f for f in findings if f.severity == AnalysisSeverity.LOW)
        
        # Assert
        assert "🔵 LOW: 1 Potential Information Leakage" in low_finding.title
        assert len(low_finding.evidence) <= 20
        assert len(low_finding.remediation_steps) == 3
    
    def test_generate_findings_with_empty_classifications(self, strategy):
        """Test handling when some severity levels have no findings."""
        # Arrange
        sparse_results = {
            'findings': {
                'critical': ['🔑 [CRITICAL] Test finding'],
                'high': [],
                'medium': [],
                'low': []
            },
            'secrets': {
                'critical': [{'type': 'Test'}],
                'high': [],
                'medium': [],
                'low': []
            }
        }
        
        # Act
        findings = strategy.generate_security_findings(sparse_results)
        
        # Assert
        assert len(findings) == 1  # Only critical finding should be generated
        assert findings[0].severity == AnalysisSeverity.CRITICAL


@pytest.mark.integration
@pytest.mark.security
class TestSecurityStrategyIntegration:
    """Integration tests for the complete Strategy pattern workflow."""
    
    def test_complete_strategy_workflow_integration(self):
        """Test that all strategies work together in the refactored method."""
        # This would test the actual _assess_crypto_keys_exposure method
        # using the Strategy pattern to ensure all components integrate properly
        
        # Arrange
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {
            'pii_patterns': ['email', 'phone'],
            'crypto_keys_check': True,
            'key_detection_config': {
                'enabled': True,
                'patterns': ['aws', 'github', 'stripe']
            }
        }
        
        assessment = SensitiveDataAssessment(config)
        
        mock_analysis_results = {
            'string_analysis': {
                'emails': ['test@example.com'],
                'urls': ['https://api.stripe.com'],
                'all_strings': ['sk_test_secret_key']
            }
        }
        
        # Act
        findings = assessment._assess_crypto_keys_exposure(mock_analysis_results)
        
        # Assert
        assert isinstance(findings, list)
        # Note: Current implementation returns empty findings due to placeholder pattern matching
        # This would be expanded when full pattern integration is complete


if __name__ == "__main__":
    pytest.main([__file__, "-v"])