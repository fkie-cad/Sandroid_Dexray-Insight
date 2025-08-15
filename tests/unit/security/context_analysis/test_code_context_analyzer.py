#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
from unittest.mock import Mock, patch

from src.dexray_insight.security.context_analysis.code_context_analyzer import CodeContextAnalyzer
from src.dexray_insight.security.context_analysis.models.context_models import (
    CodeContext, CodeLocation, ProtectionLevel
)


class TestCodeContextAnalyzer:
    """Test cases for CodeContextAnalyzer"""
    
    @pytest.fixture
    def analyzer(self):
        """Create a CodeContextAnalyzer instance for testing"""
        return CodeContextAnalyzer()
    
    @pytest.fixture
    def sample_string_data(self):
        """Sample string analysis data for testing"""
        return {
            'all_strings': [
                'AIzaSyTestKey123456789012345678901234',
                'https://api.example.com/v1/users',
                'test_secret_key',
                'Landroidx/core/content/ContextCompat',
                'String apiKey = "AIzaSyTestKey123456789012345678901234";',
                'private static final String API_KEY = "secret_key_here";',
                'BuildConfig.GOOGLE_API_KEY'
            ],
            'emails': ['test@example.com'],
            'urls': ['https://api.example.com/v1/users'],
            'domains': ['example.com'],
            'ip_addresses': ['192.168.1.1']
        }
    
    @pytest.fixture
    def sample_behavior_analysis(self):
        """Sample behavior analysis data for testing"""
        return {
            'androguard_objects': {
                'mode': 'deep',
                'apk_obj': Mock(),
                'dex_obj': [Mock()]
            }
        }
    
    def test_initialization(self, analyzer):
        """Test CodeContextAnalyzer initialization"""
        assert analyzer is not None
        assert hasattr(analyzer, 'logger')
    
    def test_analyze_string_context_xml_location(self, analyzer):
        """Test context analysis for XML-located strings"""
        finding = {
            'value': 'AIzaSyTestKey123456789012345678901234',
            'location': 'XML element text',
            'file_path': '/app/src/main/res/values/strings.xml',
            'line_number': None
        }
        
        analysis_results = {
            'string_analysis': {
                'all_strings': ['AIzaSyTestKey123456789012345678901234', 'other_string'],
                'emails': [],
                'urls': [],
                'domains': [],
                'ip_addresses': []
            },
            'behaviour_analysis': {
                'deep_analysis': {'strings': []}
            }
        }
        
        context = analyzer.analyze_string_context(finding, analysis_results)
        
        assert isinstance(context, CodeContext)
        assert context.location_type == CodeLocation.RESOURCE_FILE
        assert context.file_path == '/app/src/main/res/values/strings.xml'
        assert 'xml' in context.file_path.lower()
    
    def test_analyze_string_context_java_source(self, analyzer):
        """Test context analysis for Java source code"""
        finding = {
            'value': 'secret_api_key_123',
            'location': 'All extracted strings',
            'file_path': '/app/src/main/java/com/example/ApiManager.java',
            'line_number': 42
        }
        
        analysis_results = {
            'string_analysis': {
                'all_strings': ['secret_api_key_123', 'other_string'],
                'emails': [],
                'urls': [],
                'domains': [],
                'ip_addresses': []
            },
            'behaviour_analysis': {
                'deep_analysis': {'strings': []}
            }
        }
        
        context = analyzer.analyze_string_context(finding, analysis_results)
        
        assert context.location_type == CodeLocation.SOURCE_CODE
        assert context.file_path == '/app/src/main/java/com/example/ApiManager.java'
        assert context.line_number == 42
    
    def test_analyze_string_context_test_file(self, analyzer):
        """Test context analysis for test files"""
        finding = {
            'value': 'test_api_key',
            'location': 'String analysis',
            'file_path': '/app/src/test/java/com/example/ApiTest.java',
            'line_number': 25
        }
        
        analysis_results = {
            'string_analysis': {
                'all_strings': ['test_api_key', 'other_string'],
                'emails': [],
                'urls': [],
                'domains': [],
                'ip_addresses': []
            }
        }
        
        context = analyzer.analyze_string_context(finding, analysis_results)
        
        assert context.location_type == CodeLocation.TEST_CODE
        assert context.file_path == '/app/src/test/java/com/example/ApiTest.java'
    
    def test_analyze_string_context_build_script(self, analyzer):
        """Test context analysis for build scripts"""
        finding = {
            'value': 'gradle_api_key',
            'location': 'Configuration',
            'file_path': '/app/build.gradle',
            'line_number': 15
        }
        
        analysis_results = {
            'string_analysis': {
                'all_strings': ['gradle_api_key', 'other_string'],
                'emails': [],
                'urls': [],
                'domains': [],
                'ip_addresses': []
            }
        }
        
        context = analyzer.analyze_string_context(finding, analysis_results)
        
        assert context.location_type == CodeLocation.BUILD_SCRIPT
        assert context.file_path == '/app/build.gradle'
    
    def test_determine_location_type_xml_files(self, analyzer):
        """Test location type determination for XML files"""
        xml_files = [
            '/app/src/main/res/values/strings.xml',
            '/app/src/main/res/layout/activity_main.xml',
            '/app/src/main/AndroidManifest.xml'
        ]
        
        for xml_file in xml_files:
            location_type = analyzer._determine_location_type(xml_file)
            assert location_type == CodeLocation.RESOURCE_FILE
    
    def test_determine_location_type_java_files(self, analyzer):
        """Test location type determination for Java source files"""
        java_files = [
            '/app/src/main/java/com/example/MainActivity.java',
            '/app/src/main/java/com/example/api/ApiManager.java'
        ]
        
        for java_file in java_files:
            location_type = analyzer._determine_location_type(java_file)
            assert location_type == CodeLocation.SOURCE_CODE
    
    def test_determine_location_type_test_files(self, analyzer):
        """Test location type determination for test files"""
        test_files = [
            '/app/src/test/java/com/example/ApiTest.java',
            '/app/src/androidTest/java/com/example/MainActivityTest.java',
            '/app/src/main/java/com/example/MockDataProvider.java'
        ]
        
        for test_file in test_files:
            location_type = analyzer._determine_location_type(test_file)
            assert location_type == CodeLocation.TEST_CODE
    
    def test_determine_location_type_build_files(self, analyzer):
        """Test location type determination for build files"""
        build_files = [
            '/app/build.gradle',
            '/app/app/build.gradle',
            '/app/gradle.properties',
            '/app/settings.gradle'
        ]
        
        for build_file in build_files:
            location_type = analyzer._determine_location_type(build_file)
            assert location_type == CodeLocation.BUILD_SCRIPT
    
    def test_determine_location_type_config_files(self, analyzer):
        """Test location type determination for configuration files"""
        config_files = [
            '/app/src/main/assets/config.properties',
            '/app/src/main/res/raw/config.json',
            '/app/proguard-rules.pro'
        ]
        
        for config_file in config_files:
            location_type = analyzer._determine_location_type(config_file)
            assert location_type == CodeLocation.CONFIGURATION_FILE
    
    def test_extract_surrounding_context_from_strings(self, analyzer, sample_string_data):
        """Test extraction of surrounding context from string analysis"""
        target_string = 'AIzaSyTestKey123456789012345678901234'
        
        context = analyzer._extract_surrounding_context_from_strings(target_string, sample_string_data)
        
        assert 'String apiKey' in context.surrounding_lines[0]
        assert 'apiKey' in context.variable_names
        assert len(context.surrounding_lines) > 0
    
    def test_extract_surrounding_context_build_config(self, analyzer, sample_string_data):
        """Test extraction of BuildConfig context"""
        target_string = 'BuildConfig.GOOGLE_API_KEY'
        
        context = analyzer._extract_surrounding_context_from_strings(target_string, sample_string_data)
        
        assert 'BuildConfig' in context.class_names
        assert 'GOOGLE_API_KEY' in context.variable_names
        assert context.protection_level == ProtectionLevel.BUILD_TIME_INJECTION
    
    def test_parse_java_like_code_variable_declaration(self, analyzer):
        """Test parsing of Java-like variable declarations"""
        code_line = 'private static final String API_KEY = "secret_key_here";'
        
        context = analyzer._parse_java_like_code(code_line, CodeContext())
        
        assert 'API_KEY' in context.variable_names
        assert 'String' in context.class_names
        assert code_line in context.surrounding_lines
    
    def test_parse_java_like_code_method_call(self, analyzer):
        """Test parsing of Java-like method calls"""
        code_line = 'HttpURLConnection conn = apiClient.createConnection(url, apiKey);'
        
        context = analyzer._parse_java_like_code(code_line, CodeContext())
        
        assert 'conn' in context.variable_names
        assert 'apiClient' in context.variable_names
        assert 'apiKey' in context.variable_names
        assert 'createConnection' in context.method_signatures[0]
        assert 'HttpURLConnection' in context.class_names
    
    def test_parse_java_like_code_imports(self, analyzer):
        """Test parsing of import statements"""
        code_line = 'import javax.crypto.Cipher;'
        
        context = analyzer._parse_java_like_code(code_line, CodeContext())
        
        assert 'javax.crypto.Cipher' in context.imports
        assert 'Cipher' in context.class_names
    
    def test_parse_java_like_code_package_declaration(self, analyzer):
        """Test parsing of package declarations"""
        code_line = 'package com.example.api.security;'
        
        context = analyzer._parse_java_like_code(code_line, CodeContext())
        
        assert 'com.example.api.security' in context.package_names
    
    def test_parse_java_like_code_class_declaration(self, analyzer):
        """Test parsing of class declarations"""
        code_line = 'public class ApiManager extends BaseManager {'
        
        context = analyzer._parse_java_like_code(code_line, CodeContext())
        
        assert 'ApiManager' in context.class_names
        assert 'BaseManager' in context.class_names
    
    def test_parse_java_like_code_annotation(self, analyzer):
        """Test parsing of annotations"""
        code_line = '@Override'
        
        context = analyzer._parse_java_like_code(code_line, CodeContext())
        
        assert '@Override' in context.annotations
    
    def test_parse_java_like_code_comment(self, analyzer):
        """Test parsing of comments"""
        code_lines = [
            '// This is a single line comment',
            '/* Multi-line comment */',
            '* Documentation comment'
        ]
        
        for code_line in code_lines:
            context = analyzer._parse_java_like_code(code_line, CodeContext())
            assert len(context.comments) > 0
    
    def test_detect_protection_level_encryption_indicators(self, analyzer):
        """Test detection of encryption protection level"""
        context_with_crypto = CodeContext(
            imports={'javax.crypto.Cipher', 'java.security.KeyStore'},
            method_signatures=['encrypt(String data)', 'generateKey()'],
            surrounding_lines=['cipher.doFinal(data)', 'KeyStore keystore = KeyStore.getInstance("AndroidKeyStore")']
        )
        
        protection_level = analyzer._detect_protection_level(context_with_crypto)
        assert protection_level == ProtectionLevel.ENCRYPTION
    
    def test_detect_protection_level_environment_variables(self, analyzer):
        """Test detection of environment variable protection level"""
        context_with_env = CodeContext(
            variable_names={'System.getenv', 'BuildConfig'},
            surrounding_lines=['String key = System.getenv("API_KEY")', 'BuildConfig.SECRET_KEY']
        )
        
        protection_level = analyzer._detect_protection_level(context_with_env)
        assert protection_level in [ProtectionLevel.ENVIRONMENT, ProtectionLevel.BUILD_TIME_INJECTION]
    
    def test_detect_protection_level_obfuscation(self, analyzer):
        """Test detection of obfuscation protection level"""
        context_with_obfuscation = CodeContext(
            method_signatures=['Base64.decode()', 'decode()'],
            surrounding_lines=['Base64.decode(encodedKey)', 'deobfuscate(obfuscatedSecret)'],
            variable_names={'base64', 'encoded', 'obfuscated'}
        )
        
        protection_level = analyzer._detect_protection_level(context_with_obfuscation)
        assert protection_level == ProtectionLevel.OBFUSCATION
    
    def test_detect_protection_level_secure_storage(self, analyzer):
        """Test detection of secure storage protection level"""
        context_with_keystore = CodeContext(
            class_names={'KeyStore', 'SharedPreferences'},
            method_signatures=['getSharedPreferences()', 'keyStore.getKey()'],
            surrounding_lines=['KeyStore.getInstance("AndroidKeyStore")', 'preferences.getString("encrypted_key")']
        )
        
        protection_level = analyzer._detect_protection_level(context_with_keystore)
        assert protection_level == ProtectionLevel.SECURE_STORAGE
    
    def test_detect_protection_level_no_protection(self, analyzer):
        """Test detection when no protection is present"""
        context_plain = CodeContext(
            surrounding_lines=['String apiKey = "plain_text_key";'],
            variable_names={'apiKey'}
        )
        
        protection_level = analyzer._detect_protection_level(context_plain)
        assert protection_level == ProtectionLevel.NONE
    
    def test_enhance_context_with_behavior_analysis_deep_mode(self, analyzer, sample_behavior_analysis):
        """Test context enhancement with deep behavior analysis"""
        base_context = CodeContext()
        
        enhanced_context = analyzer._enhance_context_with_behavior_analysis(base_context, sample_behavior_analysis)
        
        # Should maintain the original context properties
        assert enhanced_context.location_type == base_context.location_type
        # Additional enhancements would be tested based on actual implementation
    
    def test_enhance_context_with_behavior_analysis_fast_mode(self, analyzer):
        """Test context enhancement with fast behavior analysis (limited enhancement)"""
        behavior_analysis = {
            'androguard_objects': {
                'mode': 'fast'
            }
        }
        
        base_context = CodeContext()
        enhanced_context = analyzer._enhance_context_with_behavior_analysis(base_context, behavior_analysis)
        
        # In fast mode, minimal enhancement should occur
        assert enhanced_context.location_type == base_context.location_type
    
    def test_enhance_context_with_behavior_analysis_no_behavior_data(self, analyzer):
        """Test context enhancement when no behavior analysis data is available"""
        base_context = CodeContext(file_path='/app/test.java')
        
        enhanced_context = analyzer._enhance_context_with_behavior_analysis(base_context, {})
        
        # Should return original context unchanged when no behavior data
        assert enhanced_context.file_path == base_context.file_path
        assert enhanced_context.location_type == base_context.location_type
    
    def test_analyze_string_context_comprehensive_integration(self, analyzer, sample_string_data):
        """Test comprehensive string context analysis integration"""
        finding = {
            'value': 'AIzaSyTestKey123456789012345678901234',
            'location': 'All extracted strings (including XML)',
            'file_path': '/app/src/main/java/com/example/ApiManager.java',
            'line_number': 42
        }
        
        analysis_results = {
            'string_analysis': sample_string_data,
            'behaviour_analysis': {
                'androguard_objects': {'mode': 'fast'}
            }
        }
        
        context = analyzer.analyze_string_context(finding, analysis_results)
        
        # Verify comprehensive analysis results
        assert context.location_type == CodeLocation.SOURCE_CODE
        assert context.file_path == finding['file_path']
        assert context.line_number == finding['line_number']
        assert len(context.surrounding_lines) > 0
        assert len(context.variable_names) > 0
        assert context.protection_level in ProtectionLevel
    
    def test_edge_case_empty_finding(self, analyzer):
        """Test handling of empty or malformed findings"""
        empty_finding = {}
        analysis_results = {}
        
        context = analyzer.analyze_string_context(empty_finding, analysis_results)
        
        assert isinstance(context, CodeContext)
        assert context.location_type == CodeLocation.UNKNOWN
    
    def test_edge_case_missing_analysis_results(self, analyzer):
        """Test handling when analysis results are missing"""
        finding = {
            'value': 'test_key',
            'location': 'unknown'
        }
        
        context = analyzer.analyze_string_context(finding, {})
        
        assert isinstance(context, CodeContext)
        assert context.location_type == CodeLocation.UNKNOWN


if __name__ == '__main__':
    pytest.main([__file__])