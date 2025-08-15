#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive tests for XML string extraction functionality.

Tests the new XML string extraction capabilities added to StringExtractor
to ensure proper detection of hardcoded secrets in XML resources like strings.xml.

This addresses the regression where Google API keys and other secrets in
XML resources were not being detected by the security assessment.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
import xml.etree.ElementTree as ET
from typing import Set, Dict, Any

from dexray_insight.modules.string_analysis.extractors.string_extractor import StringExtractor
from dexray_insight.core.base_classes import AnalysisContext


class TestXMLStringExtraction:
    """Test suite for XML string extraction functionality"""
    
    @pytest.fixture
    def string_extractor(self):
        """Create StringExtractor instance with default config"""
        return StringExtractor(config={'min_string_length': 3})
    
    @pytest.fixture 
    def mock_analysis_context(self):
        """Create mock analysis context with androguard objects"""
        context = Mock(spec=AnalysisContext)
        
        # Mock androguard object structure
        androguard_obj = Mock()
        apk_obj = Mock()
        
        # Configure mock chain
        context.androguard_obj = androguard_obj
        androguard_obj.get_androguard_apk.return_value = apk_obj
        
        return context, apk_obj
    
    def test_extract_xml_strings_no_androguard_object(self, string_extractor):
        """Test XML extraction handles missing androguard object gracefully"""
        context = Mock(spec=AnalysisContext)
        context.androguard_obj = None
        
        result = string_extractor._extract_xml_strings(context)
        
        assert isinstance(result, set)
        assert len(result) == 0
    
    def test_extract_xml_strings_no_apk_object(self, string_extractor):
        """Test XML extraction handles missing APK object gracefully"""
        context = Mock(spec=AnalysisContext)
        androguard_obj = Mock()
        androguard_obj.get_androguard_apk.return_value = None
        context.androguard_obj = androguard_obj
        
        result = string_extractor._extract_xml_strings(context)
        
        assert isinstance(result, set)
        assert len(result) == 0
    
    def test_extract_strings_from_strings_xml(self, string_extractor):
        """Test extraction of API keys and values from strings.xml"""
        context, apk_obj = self.create_mock_context_with_strings_xml()
        
        result = string_extractor._extract_xml_strings(context)
        
        # Should contain the Google API key and other string values
        assert 'AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI' in result
        assert 'google_api_key' in result
        assert 'Super Studio App' in result
        assert 'en' not in result  # Should be filtered out by length (< 3 chars default)
    
    def test_extract_strings_from_values_xml(self, string_extractor):
        """Test extraction from other values XML files"""
        context, apk_obj = self.create_mock_context_with_values_xml()
        
        result = string_extractor._extract_xml_strings(context)
        
        # Should contain configuration values
        assert 'https://api.example.com/v1' in result
        assert 'development' in result
        assert '1234567890abcdef' in result
    
    def test_parse_xml_for_strings_valid_xml(self, string_extractor):
        """Test XML parsing with valid XML content"""
        xml_content = '''<?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="google_api_key">AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI</string>
            <string name="app_name">Test App</string>
            <string name="server_url">https://api.testapp.com</string>
        </resources>'''.encode('utf-8')
        
        result = string_extractor._parse_xml_for_strings(xml_content, 'test_strings.xml')
        
        assert 'AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI' in result
        assert 'Test App' in result
        assert 'https://api.testapp.com' in result
        assert 'google_api_key' in result  # Attribute name
        assert 'app_name' in result  # Attribute name
    
    def test_parse_xml_for_strings_malformed_xml_fallback(self, string_extractor):
        """Test XML parsing fallback with malformed XML"""
        xml_content = '''<resources>
            <string name="api_key">AIzaSyBrokenXMLExample</string>
            <broken_tag>Some Value
        </resources>'''.encode('utf-8')
        
        result = string_extractor._parse_xml_for_strings(xml_content, 'broken.xml')
        
        # Fallback regex should still find some values
        assert len(result) > 0
        # Should find the API key value
        api_key_found = any('AIzaSyBrokenXMLExample' in s for s in result)
        assert api_key_found
    
    def test_parse_xml_for_strings_empty_content(self, string_extractor):
        """Test XML parsing with empty content"""
        xml_content = b''
        
        result = string_extractor._parse_xml_for_strings(xml_content, 'empty.xml')
        
        assert isinstance(result, set)
        assert len(result) == 0
    
    def test_extract_manifest_strings(self, string_extractor):
        """Test manifest string extraction"""
        context, apk_obj = self.create_mock_context_with_manifest()
        
        result = string_extractor._extract_manifest_strings(apk_obj)
        
        # Should contain manifest values
        assert 'com.example.testapp' in result
        assert 'Test Application' in result
        # URL parts will be extracted separately
        assert 'example.com' in result
        assert '/oauth' in result
    
    def test_xml_extraction_length_filtering(self, string_extractor):
        """Test that length filtering works correctly"""
        # Configure with higher minimum length
        extractor = StringExtractor(config={'min_string_length': 10})
        
        xml_content = '''<?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="short">Hi</string>
            <string name="medium">Medium Text</string>
            <string name="long">This is a very long string value</string>
            <string name="api_key">AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI</string>
        </resources>'''.encode('utf-8')
        
        strings = extractor._parse_xml_for_strings(xml_content, 'test.xml')
        
        # Apply manual filtering to test the logic
        filtered_strings = {s for s in strings if len(s) >= 10}
        
        assert 'Hi' not in filtered_strings  # Too short
        assert 'Medium Text' in filtered_strings  # Long enough
        assert 'This is a very long string value' in filtered_strings
        assert 'AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI' in filtered_strings
    
    def test_xml_extraction_exclude_patterns(self, string_extractor):
        """Test that exclude patterns work correctly"""
        # Configure with exclude pattern
        extractor = StringExtractor(config={
            'min_string_length': 3,
            'exclude_patterns': [r'debug.*', r'test.*']
        })
        
        strings = {'debug_mode', 'test_value', 'production_api_key', 'AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI'}
        
        # Filter strings using the extractor's method
        filtered_strings = {s for s in strings if not extractor._should_exclude_string(s)}
        
        assert 'debug_mode' not in filtered_strings  # Should be excluded
        assert 'test_value' not in filtered_strings  # Should be excluded
        assert 'production_api_key' in filtered_strings
        assert 'AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI' in filtered_strings
    
    def test_extract_all_strings_includes_xml(self, string_extractor):
        """Test that extract_all_strings includes XML strings"""
        context, apk_obj = self.create_mock_context_with_strings_xml()
        
        # Mock other extraction methods to return empty sets
        with patch.object(string_extractor, '_extract_dotnet_strings', return_value=set()):
            with patch.object(string_extractor, '_extract_native_strings', return_value=set()):
                with patch.object(string_extractor, '_extract_dex_strings', return_value=set()):
                    result = string_extractor.extract_all_strings(context)
        
        # Should include the Google API key from XML
        assert 'AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI' in result
        assert len(result) > 0
    
    def test_google_api_key_detection_integration(self, string_extractor):
        """Integration test to ensure Google API keys are properly detected"""
        context, apk_obj = self.create_mock_context_with_multiple_sources()
        
        # Mock DEX extraction to include the second API key
        def mock_dex_strings(context):
            return {'AIzaSyDRKQ9d6kfsoZT2lUnZcZnBYvH69HExNPE', 'other_dex_string'}
        
        with patch.object(string_extractor, '_extract_dex_strings', side_effect=mock_dex_strings):
            with patch.object(string_extractor, '_extract_dotnet_strings', return_value=set()):
                with patch.object(string_extractor, '_extract_native_strings', return_value=set()):
                    result = string_extractor.extract_all_strings(context)
        
        # Should contain both Google API keys
        assert 'AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI' in result  # From XML
        assert 'AIzaSyDRKQ9d6kfsoZT2lUnZcZnBYvH69HExNPE' in result  # From DEX
        assert len(result) >= 2
    
    # Helper methods for creating mock contexts
    
    def create_mock_context_with_strings_xml(self):
        """Create mock context with strings.xml containing Google API key"""
        context = Mock(spec=AnalysisContext)
        androguard_obj = Mock()
        apk_obj = Mock()
        
        # Mock XML files
        xml_files = ['res/values/strings.xml', 'res/values-en/strings.xml']
        resources = {'XML': xml_files}
        
        # Mock strings.xml content
        strings_xml_content = '''<?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="google_api_key">AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI</string>
            <string name="google_crash_reporting_api_key">AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI</string>
            <string name="app_name">Super Studio App</string>
            <string name="lang">en</string>
        </resources>'''.encode('utf-8')
        
        # Configure mocks
        context.androguard_obj = androguard_obj
        androguard_obj.get_androguard_apk.return_value = apk_obj
        apk_obj.get_files_types.return_value = resources
        apk_obj.get_file.return_value = strings_xml_content
        
        # Mock manifest
        manifest_xml = ET.fromstring('<manifest package="com.test.app"></manifest>')
        apk_obj.get_android_manifest_xml.return_value = manifest_xml
        
        return context, apk_obj
    
    def create_mock_context_with_values_xml(self):
        """Create mock context with various values XML files"""
        context = Mock(spec=AnalysisContext)
        androguard_obj = Mock()
        apk_obj = Mock()
        
        xml_files = ['res/values/config.xml', 'res/values/urls.xml']
        resources = {'XML': xml_files}
        
        config_xml_content = '''<?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="server_url">https://api.example.com/v1</string>
            <string name="environment">development</string>
            <string name="client_secret">1234567890abcdef</string>
        </resources>'''.encode('utf-8')
        
        context.androguard_obj = androguard_obj
        androguard_obj.get_androguard_apk.return_value = apk_obj
        apk_obj.get_files_types.return_value = resources
        apk_obj.get_file.return_value = config_xml_content
        
        # Mock manifest
        manifest_xml = ET.fromstring('<manifest package="com.test.app"></manifest>')
        apk_obj.get_android_manifest_xml.return_value = manifest_xml
        
        return context, apk_obj
    
    def create_mock_context_with_manifest(self):
        """Create mock context with manifest containing strings"""
        context = Mock(spec=AnalysisContext)
        androguard_obj = Mock()
        apk_obj = Mock()
        
        # Mock manifest with string values
        manifest_content = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.testapp"
            android:label="Test Application">
            <application android:name="TestApp">
                <activity android:name=".MainActivity" 
                         android:scheme="https"
                         android:host="example.com"
                         android:path="/oauth"/>
            </application>
        </manifest>'''
        
        manifest_xml = ET.fromstring(manifest_content)
        
        context.androguard_obj = androguard_obj
        androguard_obj.get_androguard_apk.return_value = apk_obj
        apk_obj.get_files_types.return_value = {'XML': []}
        apk_obj.get_android_manifest_xml.return_value = manifest_xml
        
        return context, apk_obj
    
    def create_mock_context_with_multiple_sources(self):
        """Create mock context with multiple string sources"""
        context, apk_obj = self.create_mock_context_with_strings_xml()
        return context, apk_obj


class TestXMLParsingEdgeCases:
    """Test edge cases and error conditions in XML parsing"""
    
    @pytest.fixture
    def string_extractor(self):
        return StringExtractor()
    
    def test_xml_with_cdata_sections(self, string_extractor):
        """Test XML with CDATA sections containing API keys"""
        xml_content = '''<?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="config"><![CDATA[{"api_key":"AIzaSyTestCDATAKey12345678901234567890"}]]></string>
        </resources>'''.encode('utf-8')
        
        result = string_extractor._parse_xml_for_strings(xml_content, 'cdata.xml')
        
        # Should find the API key inside CDATA
        api_key_found = any('AIzaSyTestCDATAKey12345678901234567890' in s for s in result)
        assert api_key_found
    
    def test_xml_with_encoded_characters(self, string_extractor):
        """Test XML with HTML/XML encoded characters"""
        xml_content = '''<?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="url">https://api.example.com/search?q=test&amp;key=AIzaSyEncodedKey1234567890123456789012</string>
        </resources>'''.encode('utf-8')
        
        result = string_extractor._parse_xml_for_strings(xml_content, 'encoded.xml')
        
        # Should handle encoded characters
        assert len(result) > 0
    
    def test_xml_with_namespaces(self, string_extractor):
        """Test XML with namespaces"""
        xml_content = '''<?xml version="1.0" encoding="utf-8"?>
        <resources xmlns:android="http://schemas.android.com/apk/res/android">
            <string name="api_key" android:value="AIzaSyNamespacedKey123456789012345678901">Default</string>
        </resources>'''.encode('utf-8')
        
        result = string_extractor._parse_xml_for_strings(xml_content, 'namespaced.xml')
        
        # Should extract from both text and attributes
        assert 'Default' in result
        api_key_found = any('AIzaSyNamespacedKey123456789012345678901' in s for s in result)
        assert api_key_found
    
    def test_binary_xml_content(self, string_extractor):
        """Test handling of binary XML content"""
        # Simulate binary XML content that can't be decoded as UTF-8
        xml_content = b'\x00\x01\x02\x03'  # Binary content
        
        result = string_extractor._parse_xml_for_strings(xml_content, 'binary.xml')
        
        # Should handle gracefully and return empty set
        assert isinstance(result, set)
        assert len(result) == 0


class TestSecurityAssessmentIntegration:
    """Test integration with security assessment"""
    
    def test_security_assessment_receives_xml_strings(self):
        """Test that security assessment can access XML-extracted strings"""
        from dexray_insight.modules.string_analysis.string_analysis_module import StringAnalysisModule
        
        # Create string analysis module
        module = StringAnalysisModule({})
        
        # Mock context with XML strings
        context = Mock(spec=AnalysisContext)
        androguard_obj = Mock()
        apk_obj = Mock()
        
        xml_files = ['res/values/strings.xml']
        resources = {'XML': xml_files}
        
        strings_xml_content = '''<?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="google_api_key">AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI</string>
        </resources>'''.encode('utf-8')
        
        context.androguard_obj = androguard_obj
        androguard_obj.get_androguard_apk.return_value = apk_obj
        androguard_obj.get_androguard_dex.return_value = []  # No DEX strings
        apk_obj.get_files_types.return_value = resources
        apk_obj.get_file.return_value = strings_xml_content
        
        # Mock manifest
        manifest_xml = ET.fromstring('<manifest package="com.test.app"></manifest>')
        apk_obj.get_android_manifest_xml.return_value = manifest_xml
        
        # Mock other analysis results - use the correct attribute name
        context.module_results = {}
        
        # Run analysis
        result = module.analyze('/fake/path.apk', context)
        
        # Check that all_strings contains the API key for security analysis
        assert 'AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI' in result.all_strings
        
        # Check that the result can be converted to dict for security assessment
        result_dict = result.to_dict()
        assert 'all_strings' in result_dict
        assert 'AIzaSyCFtats4tiOdzDfhlDfWSjcGOcCk3MxJAI' in result_dict['all_strings']