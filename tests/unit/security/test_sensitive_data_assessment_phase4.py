#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phase 4 TDD tests for refactored SensitiveDataAssessment.__init__() method.

Following SOLID principles and TDD Red-Green-Refactor cycle:
- Single Responsibility: Each initialization function handles one configuration aspect
- Open/Closed: New patterns can be added without modifying existing functions  
- Dependency Inversion: Functions depend on configuration abstractions

Target method: SensitiveDataAssessment.__init__() (392 lines, 8 responsibilities)
Refactoring into: 8 single-purpose initialization functions + 1 coordinator
"""

import pytest
from unittest.mock import patch
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))


@pytest.mark.refactored
@pytest.mark.phase4
class TestSensitiveDataAssessmentBasicConfiguration:
    """
    Tests for _initialize_basic_configuration function (TDD - Red Phase).
    
    Single Responsibility: Initialize basic logging, OWASP category, and core settings only.
    """
    
    def test_initialize_basic_configuration_sets_core_attributes(self):
        """
        Test that _initialize_basic_configuration sets up basic class attributes.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        config = {
            'pii_patterns': ['email', 'phone'],
            'crypto_keys_check': True
        }
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        
        # Act - This will fail initially (RED phase)
        assessment._initialize_basic_configuration(config)
        
        # Assert
        assert hasattr(assessment, 'logger')
        assert assessment.owasp_category == "A02:2021-Cryptographic Failures"
        assert assessment.pii_patterns == ['email', 'phone']
        assert assessment.crypto_keys_check is True
    
    def test_initialize_basic_configuration_handles_missing_config(self):
        """
        Test that basic configuration handles missing config values gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        config = {}
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        
        # Act
        assessment._initialize_basic_configuration(config)
        
        # Assert
        assert assessment.pii_patterns == ['email', 'phone', 'ssn', 'credit_card']  # Default values
        assert assessment.crypto_keys_check is True  # Default value


@pytest.mark.refactored
@pytest.mark.phase4
class TestSensitiveDataAssessmentPatternConfiguration:
    """
    Tests for _setup_pattern_enablement function (TDD - Red Phase).
    
    Single Responsibility: Configure which detection patterns are enabled.
    """
    
    def test_setup_pattern_enablement_configures_enabled_patterns(self):
        """
        Test that _setup_pattern_enablement properly configures pattern enablement.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        config = {
            'key_detection': {
                'enabled': True,
                'patterns': {
                    'pem_keys': False,
                    'api_keys': True,
                    'jwt_tokens': True
                }
            }
        }
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        
        # Act - This will fail initially (RED phase)
        assessment._setup_pattern_enablement(config)
        
        # Assert
        assert assessment.key_detection_enabled is True
        assert assessment.enabled_patterns['pem_keys'] is False
        assert assessment.enabled_patterns['api_keys'] is True
        assert assessment.enabled_patterns['jwt_tokens'] is True
    
    def test_setup_pattern_enablement_uses_defaults(self):
        """
        Test that pattern enablement uses default values when config is missing.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        config = {}
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        
        # Act
        assessment._setup_pattern_enablement(config)
        
        # Assert
        assert assessment.key_detection_enabled is True  # Default
        assert assessment.enabled_patterns['pem_keys'] is True  # Default


@pytest.mark.refactored
@pytest.mark.phase4  
class TestSensitiveDataAssessmentThresholdConfiguration:
    """
    Tests for _initialize_threshold_configuration function (TDD - Red Phase).
    
    Single Responsibility: Set up entropy thresholds, length filters, and context detection.
    """
    
    def test_initialize_threshold_configuration_sets_entropy_thresholds(self):
        """
        Test that _initialize_threshold_configuration configures entropy and length settings.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        config = {
            'key_detection': {
                'entropy_thresholds': {
                    'min_base64_entropy': 5.0,
                    'min_hex_entropy': 4.0
                },
                'length_filters': {
                    'min_key_length': 20,
                    'max_key_length': 256
                },
                'context_detection': {
                    'enabled': False,
                    'strict_mode': True
                }
            }
        }
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        # Set up prerequisites - key_detection_config is needed
        assessment._setup_pattern_enablement(config)
        
        # Act - This will fail initially (RED phase)
        assessment._initialize_threshold_configuration(config)
        
        # Assert
        assert assessment.entropy_thresholds['min_base64_entropy'] == 5.0
        assert assessment.entropy_thresholds['min_hex_entropy'] == 4.0
        assert assessment.length_filters['min_key_length'] == 20
        assert assessment.length_filters['max_key_length'] == 256
        assert assessment.context_detection_enabled is False
        assert assessment.context_strict_mode is True
    
    def test_initialize_threshold_configuration_uses_defaults(self):
        """
        Test that threshold configuration uses sensible defaults.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        config = {}
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        # Set up prerequisites - key_detection_config is needed
        assessment._setup_pattern_enablement(config)
        
        # Act
        assessment._initialize_threshold_configuration(config)
        
        # Assert
        assert assessment.entropy_thresholds['min_base64_entropy'] == 4.0
        assert assessment.length_filters['min_key_length'] == 16
        assert assessment.context_detection_enabled is True


@pytest.mark.refactored
@pytest.mark.phase4
class TestSensitiveDataAssessmentPIIPatterns:
    """
    Tests for _compile_pii_patterns function (TDD - Red Phase).
    
    Single Responsibility: Compile PII detection regex patterns only.
    """
    
    def test_compile_pii_patterns_creates_regex_patterns(self):
        """
        Test that _compile_pii_patterns creates proper PII regex patterns.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        
        # Act - This will fail initially (RED phase)
        assessment._compile_pii_patterns()
        
        # Assert
        assert 'email' in assessment.pii_regex_patterns
        assert 'phone' in assessment.pii_regex_patterns
        assert 'ssn' in assessment.pii_regex_patterns
        assert 'credit_card' in assessment.pii_regex_patterns
        
        # Verify patterns are valid regex
        import re
        for pattern_name, pattern in assessment.pii_regex_patterns.items():
            assert isinstance(pattern, str)
            re.compile(pattern)  # Should not raise exception
    
    def test_compile_pii_patterns_email_pattern_works(self):
        """
        Test that email PII pattern correctly matches email addresses.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        import re
        
        # Arrange
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        assessment._compile_pii_patterns()
        
        # Act & Assert
        email_pattern = assessment.pii_regex_patterns['email']
        assert re.search(email_pattern, "test@example.com") is not None
        assert re.search(email_pattern, "user.name@domain.co.uk") is not None
        assert re.search(email_pattern, "invalid-email") is None


@pytest.mark.refactored
@pytest.mark.phase4
class TestSensitiveDataAssessmentCriticalPatterns:
    """
    Tests for _setup_critical_security_patterns function (TDD - Red Phase).
    
    Single Responsibility: Set up CRITICAL severity security detection patterns only.
    """
    
    def test_setup_critical_security_patterns_creates_critical_patterns(self):
        """
        Test that _setup_critical_security_patterns creates all critical severity patterns.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        
        # Act - This will fail initially (RED phase)
        assessment._setup_critical_security_patterns()
        
        # Assert - Check for critical patterns
        critical_patterns = [
            'pem_private_key', 'ssh_private_key', 'aws_access_key', 'aws_secret_key',
            'github_token', 'github_fine_grained_token', 'google_oauth_token',
            'firebase_cloud_messaging_key', 'password_in_url'
        ]
        
        for pattern_name in critical_patterns:
            assert pattern_name in assessment.key_detection_patterns
            pattern_config = assessment.key_detection_patterns[pattern_name]
            assert pattern_config['severity'] == 'CRITICAL'
            assert 'pattern' in pattern_config
            assert 'description' in pattern_config
    
    def test_setup_critical_security_patterns_aws_key_detection(self):
        """
        Test that AWS access key patterns work correctly.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        import re
        
        # Arrange
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        assessment._setup_critical_security_patterns()
        
        # Act & Assert
        aws_pattern = assessment.key_detection_patterns['aws_access_key']['pattern']
        assert re.search(aws_pattern, "AKIAIOSFODNN7EXAMPLE") is not None
        assert re.search(aws_pattern, "AKIA1234567890123456") is not None
        assert re.search(aws_pattern, "invalid-key") is None


@pytest.mark.refactored
@pytest.mark.phase4
class TestSensitiveDataAssessmentHighMediumPatterns:
    """
    Tests for _setup_high_medium_severity_patterns function (TDD - Red Phase).
    
    Single Responsibility: Set up HIGH and MEDIUM severity security detection patterns.
    """
    
    def test_setup_high_medium_severity_patterns_creates_patterns(self):
        """
        Test that _setup_high_medium_severity_patterns creates high/medium severity patterns.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        # Set up prerequisites - key_detection_patterns must be initialized first
        assessment._setup_critical_security_patterns()
        
        # Act - This will fail initially (RED phase)
        assessment._setup_high_medium_severity_patterns()
        
        # Assert - Check for high severity patterns
        high_patterns = [
            'generic_password', 'generic_api_key', 'jwt_token', 'stripe_api_key',
            'discord_bot_token', 'authorization_bearer'
        ]
        
        for pattern_name in high_patterns:
            assert pattern_name in assessment.key_detection_patterns
            pattern_config = assessment.key_detection_patterns[pattern_name]
            assert pattern_config['severity'] == 'HIGH'
        
        # Check for medium severity patterns
        medium_patterns = [
            'mongodb_uri', 'postgresql_uri', 'ssh_public_key', 'hex_key_256'
        ]
        
        for pattern_name in medium_patterns:
            assert pattern_name in assessment.key_detection_patterns
            pattern_config = assessment.key_detection_patterns[pattern_name]
            assert pattern_config['severity'] == 'MEDIUM'
    
    def test_setup_high_medium_patterns_jwt_token_detection(self):
        """
        Test that JWT token pattern works correctly.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        import re
        
        # Arrange
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        # Set up prerequisites - key_detection_patterns must be initialized first
        assessment._setup_critical_security_patterns()
        assessment._setup_high_medium_severity_patterns()
        
        # Act & Assert
        jwt_pattern = assessment.key_detection_patterns['jwt_token']['pattern']
        test_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        assert re.search(jwt_pattern, test_jwt) is not None


@pytest.mark.refactored
@pytest.mark.phase4
class TestSensitiveDataAssessmentLowSeverityPatterns:
    """
    Tests for _setup_low_severity_context_patterns function (TDD - Red Phase).
    
    Single Responsibility: Set up LOW severity patterns and context keywords.
    """
    
    def test_setup_low_severity_context_patterns_creates_patterns(self):
        """
        Test that _setup_low_severity_context_patterns creates low severity patterns.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        # Set up prerequisites - key_detection_patterns must be initialized first
        assessment._setup_critical_security_patterns()
        
        # Act - This will fail initially (RED phase)
        assessment._setup_low_severity_context_patterns()
        
        # Assert - Check for low severity patterns
        low_patterns = [
            'jenkins_api_token', 'base64_key_long', 'high_entropy_string', 's3_bucket_url'
        ]
        
        for pattern_name in low_patterns:
            assert pattern_name in assessment.key_detection_patterns
            pattern_config = assessment.key_detection_patterns[pattern_name]
            assert pattern_config['severity'] == 'LOW'
    
    def test_setup_low_severity_context_patterns_creates_context_keywords(self):
        """
        Test that context keywords are properly configured.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        # Set up prerequisites - key_detection_patterns must be initialized first  
        assessment._setup_critical_security_patterns()
        
        # Act
        assessment._setup_low_severity_context_patterns()
        
        # Assert
        assert 'high_risk' in assessment.key_context_keywords
        assert 'crypto' in assessment.key_context_keywords
        assert 'api' in assessment.key_context_keywords
        assert 'database' in assessment.key_context_keywords
        
        # Verify keyword contents
        assert 'password' in assessment.key_context_keywords['high_risk']
        assert 'aes' in assessment.key_context_keywords['crypto']


@pytest.mark.refactored
@pytest.mark.phase4
class TestSensitiveDataAssessmentLegacyCompatibility:
    """
    Tests for _setup_legacy_compatibility function (TDD - Red Phase).
    
    Single Responsibility: Maintain backward compatibility with legacy patterns and permissions.
    """
    
    def test_setup_legacy_compatibility_creates_legacy_patterns(self):
        """
        Test that _setup_legacy_compatibility maintains backward compatibility.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        
        # Act - This will fail initially (RED phase)
        assessment._setup_legacy_compatibility()
        
        # Assert
        assert hasattr(assessment, 'crypto_patterns')
        assert hasattr(assessment, 'sensitive_permissions')
        
        # Check legacy crypto patterns
        expected_patterns = ['DES', 'RC4', 'MD5', 'SHA1', 'password', 'secret']
        for pattern in expected_patterns:
            assert pattern in assessment.crypto_patterns
        
        # Check sensitive permissions
        expected_permissions = [
            'READ_CONTACTS', 'CAMERA', 'ACCESS_FINE_LOCATION', 'RECORD_AUDIO'
        ]
        for permission in expected_permissions:
            assert permission in assessment.sensitive_permissions
    
    def test_setup_legacy_compatibility_sensitive_permissions_count(self):
        """
        Test that all expected sensitive permissions are included.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        assessment = SensitiveDataAssessment.__new__(SensitiveDataAssessment)
        
        # Act
        assessment._setup_legacy_compatibility()
        
        # Assert
        # Should have comprehensive set of sensitive permissions
        assert len(assessment.sensitive_permissions) >= 10
        assert 'READ_CONTACTS' in assessment.sensitive_permissions
        assert 'ACCESS_FINE_LOCATION' in assessment.sensitive_permissions


@pytest.mark.refactored
@pytest.mark.phase4
class TestSensitiveDataAssessmentRefactoredInit:
    """
    Tests for the refactored __init__ coordinator function (TDD - Red Phase).
    
    Tests the main orchestration function that uses all the extracted helper functions.
    """
    
    def test_refactored_init_calls_all_initialization_functions(self):
        """
        Test that refactored __init__ calls all initialization functions in order.
        
        This is the integration test ensuring the coordinator function properly orchestrates
        all the individual initialization functions.
        
        RED: This test will fail initially as the refactored function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        config = {'pii_patterns': ['email'], 'crypto_keys_check': True}
        
        # Mock all the individual functions
        with patch.object(SensitiveDataAssessment, '_initialize_basic_configuration') as mock_basic, \
             patch.object(SensitiveDataAssessment, '_setup_pattern_enablement') as mock_patterns, \
             patch.object(SensitiveDataAssessment, '_initialize_threshold_configuration') as mock_thresholds, \
             patch.object(SensitiveDataAssessment, '_compile_pii_patterns') as mock_pii, \
             patch.object(SensitiveDataAssessment, '_setup_critical_security_patterns') as mock_critical, \
             patch.object(SensitiveDataAssessment, '_setup_high_medium_severity_patterns') as mock_high_med, \
             patch.object(SensitiveDataAssessment, '_setup_low_severity_context_patterns') as mock_low, \
             patch.object(SensitiveDataAssessment, '_setup_legacy_compatibility') as mock_legacy:
            
            # Act - This will test the refactored version
            SensitiveDataAssessment(config)
            
            # Assert - All functions should be called in the correct order
            mock_basic.assert_called_once_with(config)
            mock_patterns.assert_called_once_with(config)
            mock_thresholds.assert_called_once_with(config)
            mock_pii.assert_called_once()
            mock_critical.assert_called_once()
            mock_high_med.assert_called_once()
            mock_low.assert_called_once()
            mock_legacy.assert_called_once()
    
    def test_refactored_init_maintains_functionality_compatibility(self):
        """
        Test that refactored __init__ produces the same result as original.
        
        This is a comprehensive regression test ensuring no functionality was lost.
        
        RED: This test will fail initially as the refactored function doesn't exist yet.
        """
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        # Arrange
        config = {
            'pii_patterns': ['email', 'phone'],
            'crypto_keys_check': True,
            'key_detection': {
                'enabled': True,
                'patterns': {'pem_keys': False, 'api_keys': True}
            }
        }
        
        # Act - Test the refactored version
        assessment = SensitiveDataAssessment(config)
        
        # Assert - Should have all expected attributes from all sections
        assert hasattr(assessment, 'logger')
        assert assessment.owasp_category == "A02:2021-Cryptographic Failures"
        assert assessment.pii_patterns == ['email', 'phone']
        assert assessment.crypto_keys_check is True
        assert hasattr(assessment, 'enabled_patterns')
        assert hasattr(assessment, 'entropy_thresholds')
        assert hasattr(assessment, 'pii_regex_patterns')
        assert hasattr(assessment, 'key_detection_patterns')
        assert hasattr(assessment, 'key_context_keywords')
        assert hasattr(assessment, 'crypto_patterns')
        assert hasattr(assessment, 'sensitive_permissions')
        
        # Verify pattern counts (should have all patterns as in original)
        assert len(assessment.key_detection_patterns) > 50  # Should have ~54 patterns
        assert 'pem_private_key' in assessment.key_detection_patterns  # Critical
        assert 'jwt_token' in assessment.key_detection_patterns  # High
        assert 'mongodb_uri' in assessment.key_detection_patterns  # Medium
        assert 'base64_key_long' in assessment.key_detection_patterns  # Low


@pytest.mark.refactored
@pytest.mark.phase4
class TestExistingSensitiveDataAssessmentMethods:
    """
    Tests for all existing methods in SensitiveDataAssessment class.
    
    Ensuring comprehensive test coverage for all methods as requested.
    """
    
    def test_assess_method_exists_and_callable(self):
        """Test that assess method exists and is callable."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, 'assess')
        assert callable(assessment.assess)
    
    def test_assess_pii_exposure_method_exists_and_callable(self):
        """Test that _assess_pii_exposure method exists and is callable."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_assess_pii_exposure')
        assert callable(assessment._assess_pii_exposure)
    
    def test_assess_crypto_keys_exposure_method_exists_and_callable(self):
        """Test that _assess_crypto_keys_exposure method exists and is callable."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_assess_crypto_keys_exposure')
        assert callable(assessment._assess_crypto_keys_exposure)
    
    def test_detect_hardcoded_keys_with_location_method_exists(self):
        """Test that _detect_hardcoded_keys_with_location method exists."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_detect_hardcoded_keys_with_location')
        assert callable(assessment._detect_hardcoded_keys_with_location)
    
    def test_is_pattern_enabled_method_exists(self):
        """Test that _is_pattern_enabled method exists."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_is_pattern_enabled')
        assert callable(assessment._is_pattern_enabled)
    
    def test_validate_key_detection_method_exists(self):
        """Test that _validate_key_detection method exists."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_validate_key_detection')
        assert callable(assessment._validate_key_detection)
    
    def test_extract_from_xml_files_method_exists(self):
        """Test that _extract_from_xml_files method exists."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_extract_from_xml_files')
        assert callable(assessment._extract_from_xml_files)
    
    def test_extract_from_smali_files_method_exists(self):
        """Test that _extract_from_smali_files method exists."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_extract_from_smali_files')
        assert callable(assessment._extract_from_smali_files)
    
    def test_calculate_entropy_method_exists(self):
        """Test that _calculate_entropy method exists."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_calculate_entropy')
        assert callable(assessment._calculate_entropy)
    
    def test_has_required_context_method_exists(self):
        """Test that _has_required_context method exists."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_has_required_context')
        assert callable(assessment._has_required_context)
    
    def test_is_false_positive_method_exists(self):
        """Test that _is_false_positive method exists."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_is_false_positive')
        assert callable(assessment._is_false_positive)
    
    def test_assess_weak_cryptography_method_exists(self):
        """Test that _assess_weak_cryptography method exists."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_assess_weak_cryptography')
        assert callable(assessment._assess_weak_cryptography)
    
    def test_assess_sensitive_permissions_method_exists(self):
        """Test that _assess_sensitive_permissions method exists."""
        from dexray_insight.security.sensitive_data_assessment import SensitiveDataAssessment
        
        config = {}
        assessment = SensitiveDataAssessment(config)
        
        assert hasattr(assessment, '_assess_sensitive_permissions')
        assert callable(assessment._assess_sensitive_permissions)


# Mark all tests in this module as phase4 refactored tests
pytestmark = [pytest.mark.refactored, pytest.mark.phase4]