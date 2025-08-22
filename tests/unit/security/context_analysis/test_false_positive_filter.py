#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

from src.dexray_insight.security.context_analysis.false_positive_filter import FalsePositiveFilter
from src.dexray_insight.security.context_analysis.models.context_models import (
    CodeContext, FalsePositiveIndicator, CodeLocation
)


class TestFalsePositiveFilter:
    """Test cases for FalsePositiveFilter"""
    
    @pytest.fixture
    def filter_instance(self):
        """Create a FalsePositiveFilter instance for testing"""
        return FalsePositiveFilter()
    
    @pytest.fixture
    def sample_google_api_finding(self):
        """Sample Google API key finding for testing"""
        return {
            'type': 'Google API Key (AIza format)',
            'value': 'AIzaSyTestKey123456789012345678901234',
            'severity': 'CRITICAL',
            'pattern_name': 'google_api_key_aiza',
            'location': 'strings.xml',
            'file_path': '/app/src/main/res/values/strings.xml',
            'line_number': None
        }
    
    @pytest.fixture
    def sample_test_api_finding(self):
        """Sample test API key finding for testing"""
        return {
            'type': 'Generic API Key',
            'value': 'test_api_key_12345',
            'severity': 'HIGH',
            'pattern_name': 'generic_api_key',
            'location': 'Test code',
            'file_path': '/app/src/test/java/ApiTest.java',
            'line_number': 25
        }
    
    def test_initialization(self, filter_instance):
        """Test FalsePositiveFilter initialization"""
        assert filter_instance is not None
        assert hasattr(filter_instance, 'placeholder_patterns')
        assert hasattr(filter_instance, 'test_indicators')
        assert hasattr(filter_instance, 'android_system_patterns')
    
    def test_is_placeholder_value_common_placeholders(self, filter_instance):
        """Test detection of common placeholder values"""
        placeholders = [
            "YOUR_API_KEY",
            "INSERT_KEY_HERE",
            "REPLACE_WITH_YOUR_KEY",
            "your_api_key_here",
            "test_api_key",
            "example_key_123",
            "dummy_secret_key",
            "placeholder_token"
        ]
        
        for placeholder in placeholders:
            assert filter_instance.is_placeholder_value(placeholder) is True
    
    def test_is_placeholder_value_real_keys(self, filter_instance):
        """Test that real keys are not detected as placeholders"""
        real_keys = [
            "AIzaSyDRKQ9d6kfsoZT2lUnZcZnBYvH69HExNPE",  # Real Google API key format
            "sk_live_51HyMz2LkdIwHu7ix1Hm8g2fvNx8K",       # Real Stripe key format
            "ghp_1234567890abcdef1234567890abcdef12345678",  # Real GitHub token format
            "AKIAIOSFODNN7EXAMPLE1234567890ABCDEF",         # Real AWS key format
        ]
        
        for key in real_keys:
            assert filter_instance.is_placeholder_value(key) is False
    
    def test_is_android_system_string_positive_cases(self, filter_instance):
        """Test detection of Android system strings"""
        android_strings = [
            "Landroid/view/View",
            "Ljava/lang/String",
            "Landroidx/fragment/app/Fragment",
            "com.android.settings.MainActivity",
            "androidx.core.content.ContextCompat",
            "android.permission.INTERNET",
            "setContentView",
            "findViewById"
        ]
        
        for android_string in android_strings:
            assert filter_instance.is_android_system_string(android_string) is True
    
    def test_is_android_system_string_negative_cases(self, filter_instance):
        """Test that non-Android strings are not detected as system strings"""
        non_android_strings = [
            "AIzaSyDRKQ9d6kfsoZT2lUnZcZnBYvH69HExNPE",
            "https://api.example.com/v1/users",
            "user_secret_key_12345",
            "database_connection_string"
        ]
        
        for string in non_android_strings:
            assert filter_instance.is_android_system_string(string) is False
    
    def test_is_test_context_file_path_indicators(self, filter_instance):
        """Test test context detection based on file paths"""
        test_file_paths = [
            "/app/src/test/java/com/example/ApiTest.java",
            "/app/src/androidTest/java/com/example/MainActivityTest.java",
            "/app/src/main/java/com/example/MockDataProvider.java",
            "/app/build/intermediates/test_data/test_config.xml"
        ]
        
        for file_path in test_file_paths:
            code_context = CodeContext(file_path=file_path)
            assert filter_instance.is_test_context(code_context) is True
    
    def test_is_test_context_class_name_indicators(self, filter_instance):
        """Test test context detection based on class names"""
        test_class_names = ["ApiManagerTest", "MockService", "FakeDataProvider", "StubNetworkClient"]
        
        for class_name in test_class_names:
            code_context = CodeContext(class_names={class_name})
            assert filter_instance.is_test_context(code_context) is True
    
    def test_is_test_context_import_indicators(self, filter_instance):
        """Test test context detection based on imports"""
        test_imports = [
            "org.junit.Test",
            "org.mockito.Mock", 
            "androidx.test.ext.junit.runners.AndroidJUnit4",
            "org.robolectric.RobolectricTestRunner"
        ]
        
        for import_stmt in test_imports:
            code_context = CodeContext(imports={import_stmt})
            assert filter_instance.is_test_context(code_context) is True
    
    def test_is_test_context_negative_cases(self, filter_instance):
        """Test that production code is not detected as test context"""
        production_context = CodeContext(
            file_path="/app/src/main/java/com/example/ApiManager.java",
            class_names={"ApiManager", "NetworkService"},
            imports={"java.net.HttpURLConnection", "android.content.Context"}
        )
        
        assert filter_instance.is_test_context(production_context) is False
    
    def test_calculate_entropy_high_entropy_strings(self, filter_instance):
        """Test entropy calculation for high entropy strings"""
        high_entropy_strings = [
            "AIzaSyDRKQ9d6kfsoZT2lUnZcZnBYvH69HExNPE",  # Google API key
            "sk_live_51HyMz2LkdIwHu7ixHm8g2fvNx8K",        # Stripe key
            "ghp_1234567890abcdef1234567890abcdef",        # GitHub token
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"        # JWT token
        ]
        
        for string in high_entropy_strings:
            entropy = filter_instance.calculate_entropy(string)
            assert entropy > 4.0  # High entropy threshold
    
    def test_calculate_entropy_low_entropy_strings(self, filter_instance):
        """Test entropy calculation for low entropy strings"""
        low_entropy_strings = [
            "test_api_key",
            "your_key_here",
            "1111111111111111",
            "aaaaaaaaaaaaaaaa",
            "password123"
        ]
        
        for string in low_entropy_strings:
            entropy = filter_instance.calculate_entropy(string)
            assert entropy < 4.0  # Low entropy threshold
    
    def test_has_high_entropy_positive_cases(self, filter_instance):
        """Test high entropy detection for positive cases"""
        high_entropy_strings = [
            "AIzaSyDRKQ9d6kfsoZT2lUnZcZnBYvH69HExNPE",
            "3c9e4b5f7a8d2e1c6b9a5f8e2d1c4b7a9e6f3c8d",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ]
        
        for string in high_entropy_strings:
            assert filter_instance.has_high_entropy(string, min_entropy=4.0) is True
    
    def test_has_high_entropy_negative_cases(self, filter_instance):
        """Test high entropy detection for negative cases"""
        low_entropy_strings = [
            "test_key_123",
            "your_api_key_here",
            "000000000000000000000000",
            "abcdefghijklmnopqrstuvwx"
        ]
        
        for string in low_entropy_strings:
            assert filter_instance.has_high_entropy(string, min_entropy=4.0) is False
    
    def test_get_false_positive_indicators_placeholder(self, filter_instance):
        """Test false positive indicator generation for placeholder values"""
        finding = {
            'value': 'YOUR_API_KEY_HERE',
            'type': 'Generic API Key',
            'location': 'configuration'
        }
        
        code_context = CodeContext()
        indicators = filter_instance.get_false_positive_indicators(finding, code_context)
        
        assert len(indicators) > 0
        placeholder_indicators = [i for i in indicators if i.indicator_type == 'placeholder_value']
        assert len(placeholder_indicators) > 0
        assert placeholder_indicators[0].confidence > 0.8
    
    def test_get_false_positive_indicators_test_context(self, filter_instance):
        """Test false positive indicator generation for test context"""
        finding = {
            'value': 'test_secret_key_12345',
            'type': 'Generic Secret',
            'location': 'test file'
        }
        
        code_context = CodeContext(
            file_path="/app/src/test/java/ApiTest.java",
            class_names={"ApiTest"}
        )
        
        indicators = filter_instance.get_false_positive_indicators(finding, code_context)
        
        test_indicators = [i for i in indicators if i.indicator_type == 'test_context']
        assert len(test_indicators) > 0
        assert test_indicators[0].confidence > 0.7
    
    def test_get_false_positive_indicators_android_system(self, filter_instance):
        """Test false positive indicator generation for Android system strings"""
        finding = {
            'value': 'Landroidx/fragment/app/FragmentManager',
            'type': 'High entropy string',
            'location': 'DEX file'
        }
        
        code_context = CodeContext()
        indicators = filter_instance.get_false_positive_indicators(finding, code_context)
        
        android_indicators = [i for i in indicators if i.indicator_type == 'android_system_string']
        assert len(android_indicators) > 0
        assert android_indicators[0].confidence > 0.9
    
    def test_get_false_positive_indicators_low_entropy(self, filter_instance):
        """Test false positive indicator generation for low entropy strings"""
        finding = {
            'value': 'test_key_123456',
            'type': 'Potential key',
            'location': 'source code'
        }
        
        code_context = CodeContext()
        indicators = filter_instance.get_false_positive_indicators(finding, code_context)
        
        entropy_indicators = [i for i in indicators if i.indicator_type == 'low_entropy']
        assert len(entropy_indicators) > 0
        assert entropy_indicators[0].confidence > 0.6
    
    def test_calculate_false_positive_probability_high_confidence_indicators(self, filter_instance):
        """Test false positive probability calculation with high confidence indicators"""
        indicators = [
            FalsePositiveIndicator(
                indicator_type='placeholder_value',
                indicator_value='YOUR_API_KEY',
                confidence=0.95,
                description='Placeholder detected',
                source='pattern_matching'
            ),
            FalsePositiveIndicator(
                indicator_type='test_context',
                indicator_value='test file',
                confidence=0.8,
                description='Test context detected',
                source='file_analysis'
            )
        ]
        
        probability = filter_instance.calculate_false_positive_probability(indicators)
        assert probability > 0.8  # High probability due to strong indicators
    
    def test_calculate_false_positive_probability_low_confidence_indicators(self, filter_instance):
        """Test false positive probability calculation with low confidence indicators"""
        indicators = [
            FalsePositiveIndicator(
                indicator_type='entropy_check',
                indicator_value='medium entropy',
                confidence=0.3,
                description='Medium entropy detected',
                source='entropy_analysis'
            )
        ]
        
        probability = filter_instance.calculate_false_positive_probability(indicators)
        assert probability < 0.5  # Lower probability due to weak indicators
    
    def test_calculate_false_positive_probability_no_indicators(self, filter_instance):
        """Test false positive probability calculation with no indicators"""
        indicators = []
        probability = filter_instance.calculate_false_positive_probability(indicators)
        assert probability == 0.1  # Default low probability when no indicators
    
    def test_filter_finding_high_false_positive_probability(self, filter_instance, sample_test_api_finding):
        """Test filtering of findings with high false positive probability"""
        code_context = CodeContext(
            file_path="/app/src/test/java/ApiTest.java",
            class_names={"ApiTest"}
        )
        
        contextual_finding = filter_instance.filter_finding(sample_test_api_finding, code_context)
        
        assert contextual_finding.context_metadata.false_positive_probability > 0.7
        assert len(contextual_finding.false_positive_indicators) > 0
        assert contextual_finding.is_likely_false_positive is True
    
    def test_filter_finding_low_false_positive_probability(self, filter_instance, sample_google_api_finding):
        """Test filtering of legitimate findings with low false positive probability"""
        code_context = CodeContext(
            file_path="/app/src/main/java/ApiManager.java",
            class_names={"ApiManager"},
            location_type=CodeLocation.SOURCE_CODE
        )
        
        contextual_finding = filter_instance.filter_finding(sample_google_api_finding, code_context)
        
        assert contextual_finding.context_metadata.false_positive_probability < 0.5
        assert contextual_finding.is_likely_false_positive is False
    
    def test_filter_findings_batch_processing(self, filter_instance):
        """Test batch filtering of multiple findings"""
        findings = [
            {
                'type': 'Test Secret',
                'value': 'test_key_123',
                'location': 'test file',
                'file_path': '/app/src/test/java/Test.java'
            },
            {
                'type': 'Google API Key',
                'value': 'AIzaSyRealKey123456789012345678901234',
                'location': 'production code',
                'file_path': '/app/src/main/java/ApiManager.java'
            },
            {
                'type': 'Android System String',
                'value': 'Landroidx/core/view/ViewCompat',
                'location': 'DEX analysis',
                'file_path': None
            }
        ]
        
        code_contexts = [
            CodeContext(file_path='/app/src/test/java/Test.java', class_names={'Test'}),
            CodeContext(file_path='/app/src/main/java/ApiManager.java', class_names={'ApiManager'}),
            CodeContext()
        ]
        
        filtered_findings = filter_instance.filter_findings(findings, code_contexts)
        
        assert len(filtered_findings) == 3
        
        # Test finding should have high FP probability
        test_finding = filtered_findings[0]
        assert test_finding.is_likely_false_positive is True
        
        # Real API key should have low FP probability
        api_finding = filtered_findings[1]
        assert api_finding.is_likely_false_positive is False
        
        # Android system string should have high FP probability
        android_finding = filtered_findings[2]
        assert android_finding.is_likely_false_positive is True
    
    def test_filter_findings_mismatched_lengths(self, filter_instance):
        """Test error handling when findings and contexts lists have different lengths"""
        findings = [{'type': 'test', 'value': 'test'}]
        contexts = []  # Empty contexts list
        
        with pytest.raises(ValueError, match="Number of findings and contexts must match"):
            filter_instance.filter_findings(findings, contexts)


if __name__ == '__main__':
    pytest.main([__file__])