#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

from src.dexray_insight.security.context_analysis.models.contextual_finding import (
    ContextualFinding, ContextMetadata, UsageContext, ContextConfidence, 
    SecretUsageType, RiskLevel
)
from src.dexray_insight.security.context_analysis.models.context_models import (
    CodeContext, RiskContext, FalsePositiveIndicator, CodeLocation, ProtectionLevel
)


class TestUsageContext:
    """Test cases for UsageContext model"""
    
    def test_usage_context_initialization_defaults(self):
        """Test UsageContext initializes with correct defaults"""
        context = UsageContext()
        
        assert context.usage_type == SecretUsageType.UNKNOWN
        assert context.is_encrypted is False
        assert context.is_obfuscated is False
        assert context.has_validation is False
        assert context.access_pattern == ""
        assert context.surrounding_variables == []
        assert context.method_context is None
        assert context.class_context is None
    
    def test_usage_context_initialization_with_values(self):
        """Test UsageContext initialization with specific values"""
        context = UsageContext(
            usage_type=SecretUsageType.HARDCODED_CONSTANT,
            is_encrypted=True,
            is_obfuscated=True,
            has_validation=True,
            access_pattern="getString(R.string.api_key)",
            surrounding_variables=["apiKey", "secretKey"],
            method_context="initializeAPI",
            class_context="ApiManager"
        )
        
        assert context.usage_type == SecretUsageType.HARDCODED_CONSTANT
        assert context.is_encrypted is True
        assert context.is_obfuscated is True
        assert context.has_validation is True
        assert context.access_pattern == "getString(R.string.api_key)"
        assert context.surrounding_variables == ["apiKey", "secretKey"]
        assert context.method_context == "initializeAPI"
        assert context.class_context == "ApiManager"
    
    def test_usage_context_to_dict(self):
        """Test UsageContext conversion to dictionary"""
        context = UsageContext(
            usage_type=SecretUsageType.ENVIRONMENT_VARIABLE,
            is_encrypted=True,
            surrounding_variables=["env_var", "config_key"]
        )
        
        result = context.to_dict()
        
        _expected = {
            'usage_type': 'environment_variable',
            'is_encrypted': True,
            'is_obfuscated': False,
            'has_validation': False,
            'access_pattern': '',
            'surrounding_variables': ['env_var', 'config_key'],
            'method_context': None,
            'class_context': None
        }
        
        assert result == _expected


class TestContextMetadata:
    """Test cases for ContextMetadata model"""
    
    def test_context_metadata_initialization_defaults(self):
        """Test ContextMetadata initializes with correct defaults"""
        metadata = ContextMetadata()
        
        assert metadata.analysis_confidence == ContextConfidence.MEDIUM
        assert metadata.false_positive_probability == 0.5
        assert metadata.risk_correlation_score == 0.0
        assert metadata.behavior_correlation == []
        assert metadata.api_correlation == []
        assert metadata.context_analysis_version == "1.0"
        assert metadata.analysis_timestamp is None
    
    def test_context_metadata_to_dict(self):
        """Test ContextMetadata conversion to dictionary"""
        metadata = ContextMetadata(
            analysis_confidence=ContextConfidence.HIGH,
            false_positive_probability=0.2,
            risk_correlation_score=0.8,
            behavior_correlation=["network_usage", "file_access"],
            api_correlation=["HttpURLConnection", "FileInputStream"]
        )
        
        result = metadata.to_dict()
        
        _expected = {
            'analysis_confidence': 'high',
            'false_positive_probability': 0.2,
            'risk_correlation_score': 0.8,
            'behavior_correlation': ['network_usage', 'file_access'],
            'api_correlation': ['HttpURLConnection', 'FileInputStream'],
            'context_analysis_version': '1.0',
            'analysis_timestamp': None
        }
        
        assert result == _expected


class TestContextualFinding:
    """Test cases for ContextualFinding model"""
    
    def test_contextual_finding_initialization(self):
        """Test ContextualFinding initialization"""
        original_finding = {
            'type': 'Google API Key',
            'value': 'AIzaSyTestKey123456789012345678901234',
            'severity': 'CRITICAL',
            'location': 'strings.xml'
        }
        
        finding = ContextualFinding(original_finding=original_finding)
        
        assert finding.original_finding == original_finding
        assert isinstance(finding.usage_context, UsageContext)
        assert isinstance(finding.context_metadata, ContextMetadata)
        assert finding.adjusted_severity is None
        assert finding.adjusted_risk_level == RiskLevel.MODERATE
        assert finding.contextual_evidence == []
        assert finding.remediation_priority == 5
        assert finding.false_positive_indicators == []
    
    def test_is_likely_false_positive_true(self):
        """Test is_likely_false_positive returns True for high FP probability"""
        finding = ContextualFinding(
            original_finding={'type': 'test'},
            context_metadata=ContextMetadata(false_positive_probability=0.8)
        )
        
        assert finding.is_likely_false_positive is True
    
    def test_is_likely_false_positive_false(self):
        """Test is_likely_false_positive returns False for low FP probability"""
        finding = ContextualFinding(
            original_finding={'type': 'test'},
            context_metadata=ContextMetadata(false_positive_probability=0.3)
        )
        
        assert finding.is_likely_false_positive is False
    
    def test_requires_immediate_attention_true(self):
        """Test requires_immediate_attention for critical risk, low FP probability"""
        finding = ContextualFinding(
            original_finding={'type': 'test'},
            adjusted_risk_level=RiskLevel.CRITICAL,
            context_metadata=ContextMetadata(false_positive_probability=0.2)
        )
        
        assert finding.requires_immediate_attention is True
    
    def test_requires_immediate_attention_false_high_fp(self):
        """Test requires_immediate_attention false for high FP probability"""
        finding = ContextualFinding(
            original_finding={'type': 'test'},
            adjusted_risk_level=RiskLevel.CRITICAL,
            context_metadata=ContextMetadata(false_positive_probability=0.9)
        )
        
        assert finding.requires_immediate_attention is False
    
    def test_requires_immediate_attention_false_low_risk(self):
        """Test requires_immediate_attention false for low risk"""
        finding = ContextualFinding(
            original_finding={'type': 'test'},
            adjusted_risk_level=RiskLevel.LOW,
            context_metadata=ContextMetadata(false_positive_probability=0.2)
        )
        
        assert finding.requires_immediate_attention is False
    
    def test_get_contextual_description_false_positive(self):
        """Test contextual description for likely false positive"""
        finding = ContextualFinding(
            original_finding={'type': 'Google API Key'},
            usage_context=UsageContext(usage_type=SecretUsageType.TEST_VALUE),
            context_metadata=ContextMetadata(false_positive_probability=0.9)
        )
        
        description = finding.get_contextual_description()
        assert description == "Google API Key (Likely False Positive - Test Value)"
    
    def test_get_contextual_description_critical_risk(self):
        """Test contextual description for critical risk"""
        finding = ContextualFinding(
            original_finding={'type': 'AWS Secret Key'},
            usage_context=UsageContext(usage_type=SecretUsageType.HARDCODED_CONSTANT),
            adjusted_risk_level=RiskLevel.CRITICAL,
            context_metadata=ContextMetadata(false_positive_probability=0.1)
        )
        
        description = finding.get_contextual_description()
        assert description == "AWS Secret Key (Critical Risk - Hardcoded Constant)"
    
    def test_get_contextual_description_normal(self):
        """Test contextual description for normal case"""
        finding = ContextualFinding(
            original_finding={'type': 'API Key'},
            usage_context=UsageContext(usage_type=SecretUsageType.CONFIGURATION_VALUE),
            adjusted_risk_level=RiskLevel.MODERATE,
            context_metadata=ContextMetadata(false_positive_probability=0.3)
        )
        
        description = finding.get_contextual_description()
        assert description == "API Key (Configuration Value)"
    
    def test_to_dict_comprehensive(self):
        """Test comprehensive to_dict conversion"""
        original_finding = {'type': 'Test Secret', 'value': 'test123'}
        usage_context = UsageContext(usage_type=SecretUsageType.TEST_VALUE)
        metadata = ContextMetadata(false_positive_probability=0.9)
        
        finding = ContextualFinding(
            original_finding=original_finding,
            usage_context=usage_context,
            context_metadata=metadata,
            adjusted_severity='LOW',
            adjusted_risk_level=RiskLevel.LOW,
            contextual_evidence=['Test context detected'],
            remediation_priority=2,
            false_positive_indicators=['test pattern detected']
        )
        
        result = finding.to_dict()
        
        assert result['original_finding'] == original_finding
        assert result['usage_context'] == usage_context.to_dict()
        assert result['context_metadata'] == metadata.to_dict()
        assert result['adjusted_severity'] == 'LOW'
        assert result['adjusted_risk_level'] == 'low'
        assert result['contextual_evidence'] == ['Test context detected']
        assert result['remediation_priority'] == 2
        assert result['false_positive_indicators'] == ['test pattern detected']
        assert result['is_likely_false_positive'] is True
        assert result['requires_immediate_attention'] is False
        assert 'Test Secret (Likely False Positive - Test Value)' in result['contextual_description']
    
    def test_from_original_finding(self):
        """Test creation from original finding"""
        original_finding = {
            'type': 'GitHub Token',
            'value': 'ghp_test123456789012345678901234567890',
            'severity': 'HIGH'
        }
        
        finding = ContextualFinding.from_original_finding(original_finding)
        
        assert finding.original_finding == original_finding
        assert isinstance(finding.usage_context, UsageContext)
        assert isinstance(finding.context_metadata, ContextMetadata)


class TestCodeContext:
    """Test cases for CodeContext model"""
    
    def test_code_context_initialization_defaults(self):
        """Test CodeContext initializes with correct defaults"""
        context = CodeContext()
        
        assert context.location_type == CodeLocation.UNKNOWN
        assert context.file_path is None
        assert context.line_number is None
        assert context.surrounding_lines == []
        assert context.variable_names == set()
        assert context.method_signatures == []
        assert context.class_names == set()
        assert context.package_names == set()
        assert context.imports == set()
        assert context.annotations == []
        assert context.comments == []
        assert context.protection_level == ProtectionLevel.NONE
    
    def test_has_test_indicators_file_path(self):
        """Test test indicators detection in file path"""
        context = CodeContext(file_path="/app/src/test/java/com/example/ApiTest.java")
        assert context.has_test_indicators() is True
        
        context = CodeContext(file_path="/app/src/main/java/com/example/ApiManager.java")
        assert context.has_test_indicators() is False
    
    def test_has_test_indicators_class_names(self):
        """Test test indicators detection in class names"""
        context = CodeContext(class_names={"ApiManagerTest", "MockDataProvider"})
        assert context.has_test_indicators() is True
        
        context = CodeContext(class_names={"ApiManager", "DataProvider"})
        assert context.has_test_indicators() is False
    
    def test_has_test_indicators_imports(self):
        """Test test indicators detection in imports"""
        context = CodeContext(imports={"org.junit.Test", "org.mockito.Mock"})
        assert context.has_test_indicators() is True
        
        context = CodeContext(imports={"java.net.HttpURLConnection", "android.content.Context"})
        assert context.has_test_indicators() is False
    
    def test_has_configuration_indicators_file_path(self):
        """Test configuration indicators detection in file path"""
        context = CodeContext(file_path="/app/src/main/res/values/strings.xml")
        assert context.has_configuration_indicators() is False  # strings.xml not in config indicators
        
        context = CodeContext(file_path="/app/build.gradle")
        assert context.has_configuration_indicators() is True
    
    def test_has_configuration_indicators_variables(self):
        """Test configuration indicators detection in variable names"""
        context = CodeContext(variable_names={"API_CONFIG", "DEFAULT_SETTINGS"})
        assert context.has_configuration_indicators() is True
        
        context = CodeContext(variable_names={"userName", "password"})
        assert context.has_configuration_indicators() is False
    
    def test_get_encryption_indicators(self):
        """Test encryption indicators detection"""
        context = CodeContext(
            imports={"javax.crypto.Cipher", "java.security.KeyStore"},
            method_signatures=["encryptData(String data)", "generateSecretKey()"],
            surrounding_lines=["cipher.doFinal(data)", "KeyStore.getInstance(\"AndroidKeyStore\")"]
        )
        
        indicators = context.get_encryption_indicators()
        
        assert len(indicators) >= 3
        assert any("javax.crypto.Cipher" in indicator for indicator in indicators)
        assert any("KeyStore" in indicator for indicator in indicators)
        assert any("cipher.doFinal" in indicator for indicator in indicators)
    
    def test_to_dict_comprehensive(self):
        """Test comprehensive to_dict conversion"""
        context = CodeContext(
            location_type=CodeLocation.SOURCE_CODE,
            file_path="/app/src/main/java/ApiManager.java",
            line_number=42,
            surrounding_lines=["String apiKey = \"test\";", "HttpClient client = new HttpClient();"],
            variable_names={"apiKey", "client"},
            method_signatures=["initializeAPI()"],
            class_names={"ApiManager"},
            package_names={"com.example.api"},
            imports={"java.net.HttpURLConnection"},
            protection_level=ProtectionLevel.NONE
        )
        
        result = context.to_dict()
        
        assert result['location_type'] == 'source_code'
        assert result['file_path'] == '/app/src/main/java/ApiManager.java'
        assert result['line_number'] == 42
        assert result['surrounding_lines'] == ["String apiKey = \"test\";", "HttpClient client = new HttpClient();"]
        assert set(result['variable_names']) == {"apiKey", "client"}
        assert result['method_signatures'] == ["initializeAPI()"]
        assert set(result['class_names']) == {"ApiManager"}
        assert set(result['package_names']) == {"com.example.api"}
        assert set(result['imports']) == {"java.net.HttpURLConnection"}
        assert result['protection_level'] == 'none'
        assert 'has_test_indicators' in result
        assert 'has_configuration_indicators' in result
        assert 'encryption_indicators' in result


class TestRiskContext:
    """Test cases for RiskContext model"""
    
    def test_risk_context_initialization_defaults(self):
        """Test RiskContext initializes with correct defaults"""
        context = RiskContext()
        
        assert context.network_usage_detected is False
        assert context.privileged_api_usage is False
        assert context.external_service_communication is False
        assert context.permission_escalation_potential is False
        assert context.data_exfiltration_risk is False
        assert context.correlated_behavior_patterns == []
        assert context.related_api_calls == []
        assert context.suspicious_permissions == []
        assert context.risk_multipliers == {}
    
    def test_calculate_risk_score_minimal(self):
        """Test risk score calculation with minimal risk"""
        context = RiskContext()
        score = context.calculate_risk_score()
        assert score == 0.5  # Base score
    
    def test_calculate_risk_score_high_risk(self):
        """Test risk score calculation with high risk factors"""
        context = RiskContext(
            network_usage_detected=True,
            privileged_api_usage=True,
            external_service_communication=True,
            permission_escalation_potential=True,
            data_exfiltration_risk=True
        )
        
        score = context.calculate_risk_score()
        _expected = 0.5 + 0.2 + 0.3 + 0.25 + 0.4 + 0.5  # 2.15, capped at 1.0
        assert score == 1.0
    
    def test_calculate_risk_score_with_multipliers(self):
        """Test risk score calculation with multipliers"""
        context = RiskContext(
            network_usage_detected=True,  # 0.5 + 0.2 = 0.7
            risk_multipliers={'crypto_usage': 1.5, 'admin_permissions': 1.2}
        )
        
        score = context.calculate_risk_score()
        _expected = 0.7 * 1.5 * 1.2  # 1.26, capped at 1.0
        assert score == 1.0
    
    def test_get_primary_risk_factors(self):
        """Test primary risk factors identification"""
        context = RiskContext(
            network_usage_detected=True,
            data_exfiltration_risk=True,
            privileged_api_usage=True
        )
        
        factors = context.get_primary_risk_factors()
        
        assert "Data exfiltration potential" in factors
        assert "Privileged API usage" in factors
        assert "Network communication" in factors
        assert len(factors) == 3
    
    def test_to_dict_comprehensive(self):
        """Test comprehensive to_dict conversion"""
        context = RiskContext(
            network_usage_detected=True,
            privileged_api_usage=True,
            correlated_behavior_patterns=["network_access", "file_system_access"],
            related_api_calls=["HttpURLConnection.connect", "File.createNewFile"],
            suspicious_permissions=["INTERNET", "WRITE_EXTERNAL_STORAGE"],
            risk_multipliers={'test_factor': 1.5}
        )
        
        result = context.to_dict()
        
        assert result['network_usage_detected'] is True
        assert result['privileged_api_usage'] is True
        assert result['correlated_behavior_patterns'] == ["network_access", "file_system_access"]
        assert result['related_api_calls'] == ["HttpURLConnection.connect", "File.createNewFile"]
        assert result['suspicious_permissions'] == ["INTERNET", "WRITE_EXTERNAL_STORAGE"]
        assert result['risk_multipliers'] == {'test_factor': 1.5}
        assert 'risk_score' in result
        assert 'primary_risk_factors' in result


class TestFalsePositiveIndicator:
    """Test cases for FalsePositiveIndicator model"""
    
    def test_false_positive_indicator_initialization(self):
        """Test FalsePositiveIndicator initialization"""
        indicator = FalsePositiveIndicator(
            indicator_type="test_pattern",
            indicator_value="contains 'test' keyword",
            confidence=0.8,
            description="Found test keyword in variable name",
            source="code_analysis"
        )
        
        assert indicator.indicator_type == "test_pattern"
        assert indicator.indicator_value == "contains 'test' keyword"
        assert indicator.confidence == 0.8
        assert indicator.description == "Found test keyword in variable name"
        assert indicator.source == "code_analysis"
    
    def test_false_positive_indicator_to_dict(self):
        """Test FalsePositiveIndicator to_dict conversion"""
        indicator = FalsePositiveIndicator(
            indicator_type="placeholder_value",
            indicator_value="YOUR_API_KEY_HERE",
            confidence=0.95,
            description="Placeholder API key detected",
            source="pattern_matching"
        )
        
        result = indicator.to_dict()
        
        _expected = {
            'indicator_type': 'placeholder_value',
            'indicator_value': 'YOUR_API_KEY_HERE',
            'confidence': 0.95,
            'description': 'Placeholder API key detected',
            'source': 'pattern_matching'
        }
        
        assert result == _expected


if __name__ == '__main__':
    pytest.main([__file__])