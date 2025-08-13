#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for ApktoolDetectionEngine

Tests cover all major functionality including:
- Configuration parsing and validation
- Library definition loading and updating
- Pattern-based detection
- Properties file detection
- BuildConfig.smali detection
- Error handling and edge cases
"""

import tempfile
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

# Import the class under test
from dexray_insight.modules.library_detection.engines.apktool_detection_engine import ApktoolDetectionEngine
from dexray_insight.results.LibraryDetectionResults import (
    DetectedLibrary, LibraryDetectionMethod, LibraryCategory, 
    RiskLevel
)


class TestApktoolDetectionEngine(unittest.TestCase):
    """Test suite for ApktoolDetectionEngine"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_logger = Mock()
        self.test_config = {
            'apktool_detection': {
                'enable_pattern_detection': True,
                'enable_properties_detection': True,
                'enable_buildconfig_detection': True,
                'auto_update_definitions': False,
                'libsmali_url': 'https://example.com/libsmali.jsonl',
                'libinfo_url': 'https://example.com/libinfo.jsonl',
                'libsmali_path': './test_libsmali.jsonl',
                'libinfo_path': './test_libinfo.jsonl'
            }
        }
        
        # Sample library definitions for testing
        self.sample_libsmali = [
            {
                "id": "test_library_1",
                "path": "/com/example/testlib",
                "name": "Test Library 1",
                "type": "utility",
                "url": "https://example.com/testlib1"
            },
            {
                "id": "test_library_2", 
                "path": "/com/ads/testads",
                "name": "Test Ads Library",
                "type": "ads",
                "url": "https://example.com/testads"
            }
        ]
        
        self.sample_libinfo = [
            {
                "id": "test_library_1",
                "details": "A test utility library",
                "anti": [],
                "license": "MIT"
            },
            {
                "id": "test_library_2",
                "details": "A test advertising library",
                "anti": ["tracking", "ads"],
                "license": "Proprietary"
            }
        ]
        
    def test_init_default_config(self):
        """Test initialization with default configuration"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        # Test default values
        self.assertTrue(engine.enable_pattern_detection)
        self.assertTrue(engine.enable_properties_detection)
        self.assertTrue(engine.enable_buildconfig_detection)
        self.assertEqual(engine.libsmali_path, './libsmali.jsonl')
        self.assertEqual(engine.libinfo_path, './libinfo.jsonl')
        
    def test_init_custom_config(self):
        """Test initialization with custom configuration"""
        engine = ApktoolDetectionEngine(self.test_config, self.mock_logger)
        
        # Test custom values
        self.assertTrue(engine.enable_pattern_detection)
        self.assertFalse(engine.config['auto_update_definitions'])
        self.assertEqual(engine.libsmali_path, './test_libsmali.jsonl')
        self.assertEqual(engine.libinfo_path, './test_libinfo.jsonl')
        
    def test_is_available_no_context(self):
        """Test availability check with no context"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        mock_context = Mock()
        mock_context.temporal_paths = None
        
        result = engine.is_available(mock_context)
        self.assertFalse(result)
        
    def test_is_available_no_apktool_dir(self):
        """Test availability check with no apktool directory"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        mock_context = Mock()
        mock_temporal_paths = Mock()
        mock_temporal_paths.apktool_dir = None
        mock_context.temporal_paths = mock_temporal_paths
        
        result = engine.is_available(mock_context)
        self.assertFalse(result)
        
    def test_is_available_empty_apktool_dir(self):
        """Test availability check with empty apktool directory"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            apktool_dir = Path(temp_dir)
            
            mock_context = Mock()
            mock_temporal_paths = Mock()
            mock_temporal_paths.apktool_dir = apktool_dir
            mock_context.temporal_paths = mock_temporal_paths
            
            result = engine.is_available(mock_context)
            self.assertFalse(result)
            
    def test_is_available_valid_apktool_dir(self):
        """Test availability check with valid apktool directory"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            apktool_dir = Path(temp_dir)
            # Create some files to make directory non-empty
            (apktool_dir / "AndroidManifest.xml").touch()
            
            mock_context = Mock()
            mock_temporal_paths = Mock()
            mock_temporal_paths.apktool_dir = apktool_dir
            mock_context.temporal_paths = mock_temporal_paths
            
            result = engine.is_available(mock_context)
            self.assertTrue(result)
            
    @patch('builtins.open', create=True)
    def test_load_jsonl_valid_file(self, mock_file):
        """Test loading valid JSONL file"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        # Mock file content
        jsonl_content = ['{"id": "test", "name": "Test Library"}\n']
        mock_file.return_value.__enter__.return_value = iter(jsonl_content)
        
        result = engine._load_jsonl('test.jsonl')
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['id'], 'test')
        self.assertEqual(result[0]['name'], 'Test Library')
        
    @patch('builtins.open', create=True)
    def test_load_jsonl_invalid_json(self, mock_file):
        """Test loading JSONL file with invalid JSON"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        # Mock file with invalid JSON
        jsonl_content = ['{"id": "test", "name": "Test Library"}\n', 'invalid json line\n']
        mock_file.return_value.__enter__.return_value = iter(jsonl_content)
        
        result = engine._load_jsonl('test.jsonl')
        
        # Should return only valid entries
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['id'], 'test')
        
    def test_find_smali_roots(self):
        """Test finding smali root directories"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            apktool_dir = Path(temp_dir)
            
            # Create various directories
            (apktool_dir / "smali").mkdir()
            (apktool_dir / "smali_classes2").mkdir() 
            (apktool_dir / "smali_classes3").mkdir()
            (apktool_dir / "not_smali").mkdir()
            (apktool_dir / "res").mkdir()
            
            roots = engine._find_smali_roots(apktool_dir)
            
            # Should find 3 smali directories
            self.assertEqual(len(roots), 3)
            root_names = [root.name for root in roots]
            self.assertIn("smali", root_names)
            self.assertIn("smali_classes2", root_names)
            self.assertIn("smali_classes3", root_names)
            self.assertNotIn("not_smali", root_names)
            
    def test_lib_dir_exists(self):
        """Test checking if library directory exists"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            apktool_dir = Path(temp_dir)
            
            # Create smali structure
            smali_dir = apktool_dir / "smali"
            smali_dir.mkdir()
            (smali_dir / "com" / "example" / "testlib").mkdir(parents=True)
            
            # Test existing path
            self.assertTrue(engine._lib_dir_exists(apktool_dir, "/com/example/testlib"))
            
            # Test non-existing path  
            self.assertFalse(engine._lib_dir_exists(apktool_dir, "/com/nonexistent/lib"))
            
    def test_parse_smali_int(self):
        """Test parsing smali integer values"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        # Test decimal
        self.assertEqual(engine._parse_smali_int("123"), "123")
        self.assertEqual(engine._parse_smali_int("-456"), "-456")
        
        # Test hex
        self.assertEqual(engine._parse_smali_int("0xff"), "255")
        self.assertEqual(engine._parse_smali_int("0x10"), "16")
        self.assertEqual(engine._parse_smali_int("-0x10"), "-16")
        
        # Test invalid
        self.assertIsNone(engine._parse_smali_int("invalid"))
        self.assertIsNone(engine._parse_smali_int(""))
        self.assertIsNone(engine._parse_smali_int(None))
        
    def test_map_type_to_category(self):
        """Test mapping library type to category"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        # Test known mappings
        self.assertEqual(engine._map_type_to_category("ads"), LibraryCategory.ADVERTISING)
        self.assertEqual(engine._map_type_to_category("analytics"), LibraryCategory.ANALYTICS)
        self.assertEqual(engine._map_type_to_category("utility"), LibraryCategory.UTILITY)
        
        # Test case insensitivity
        self.assertEqual(engine._map_type_to_category("ADS"), LibraryCategory.ADVERTISING)
        
        # Test unknown type
        self.assertEqual(engine._map_type_to_category("unknown_type"), LibraryCategory.UNKNOWN)
        
    def test_create_detected_library_from_definition(self):
        """Test creating DetectedLibrary from JSONL definition"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        definition = {
            "id": "test_lib",
            "name": "Test Library",
            "type": "utility",
            "url": "https://example.com",
            "license": "MIT",
            "anti": ["tracking"]
        }
        
        library = engine._create_detected_library_from_definition(
            definition, LibraryDetectionMethod.PATTERN_MATCHING, "/com/test/lib"
        )
        
        self.assertIsNotNone(library)
        self.assertEqual(library.name, "Test Library")
        self.assertEqual(library.package_name, "test_lib")
        self.assertEqual(library.category, LibraryCategory.UTILITY)
        self.assertEqual(library.detection_method, LibraryDetectionMethod.PATTERN_MATCHING)
        self.assertEqual(library.url, "https://example.com")
        self.assertEqual(library.license, "MIT")
        self.assertEqual(library.anti_features, ["tracking"])
        self.assertEqual(library.risk_level, RiskLevel.MEDIUM)  # Has anti-features
        
    def test_deduplicate_libraries(self):
        """Test library deduplication"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        # Create duplicate libraries with different confidence scores
        lib1 = DetectedLibrary(
            name="Test Library",
            package_name="com.test.lib",
            confidence=0.8,
            evidence=["Evidence 1"]
        )
        
        lib2 = DetectedLibrary(
            name="Test Library", 
            package_name="com.test.lib",
            confidence=0.9,
            evidence=["Evidence 2"]
        )
        
        lib3 = DetectedLibrary(
            name="Different Library",
            package_name="com.different.lib", 
            confidence=0.7,
            evidence=["Evidence 3"]
        )
        
        libraries = [lib1, lib2, lib3]
        deduplicated = engine._deduplicate_libraries(libraries)
        
        # Should keep lib2 (higher confidence) and lib3
        self.assertEqual(len(deduplicated), 2)
        
        # Find the Test Library entry
        test_lib = next(lib for lib in deduplicated if lib.name == "Test Library")
        self.assertEqual(test_lib.confidence, 0.9)
        
    def test_scan_properties_valid_file(self):
        """Test scanning properties files"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            apktool_dir = Path(temp_dir)
            
            # Create a properties file
            props_file = apktool_dir / "test.properties"
            props_content = """version=1.2.3
client=test-library
description=Test library
"""
            with open(props_file, 'w') as f:
                f.write(props_content)
                
            errors = []
            libraries = engine._scan_properties(apktool_dir, errors)
            
            self.assertEqual(len(libraries), 1)
            self.assertEqual(libraries[0].name, "test-library")
            self.assertEqual(libraries[0].version, "1.2.3")
            self.assertEqual(libraries[0].detection_method, LibraryDetectionMethod.FILE_ANALYSIS)
            self.assertEqual(len(errors), 0)
            
    def test_scan_buildconfig_smali(self):
        """Test scanning BuildConfig.smali files"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            apktool_dir = Path(temp_dir)
            
            # Create BuildConfig.smali file
            buildconfig_file = apktool_dir / "BuildConfig.smali"
            buildconfig_content = """.class public final Lcom/example/library/BuildConfig;
.super Ljava/lang/Object;

.field public static final APPLICATION_ID:Ljava/lang/String; = "com.example.library"
.field public static final VERSION_NAME:Ljava/lang/String; = "2.1.0"
.field public static final VERSION_CODE:I = 0x15
"""
            with open(buildconfig_file, 'w') as f:
                f.write(buildconfig_content)
                
            errors = []
            libraries = engine._scan_buildconfig_smali(apktool_dir, errors)
            
            self.assertEqual(len(libraries), 1)
            self.assertEqual(libraries[0].name, "com.example.library")
            self.assertEqual(libraries[0].version, "2.1.0")
            self.assertEqual(libraries[0].detection_method, LibraryDetectionMethod.BUILDCONFIG_ANALYSIS)
            self.assertEqual(len(errors), 0)
            
    @patch('requests.get')
    def test_download_file_success(self, mock_get):
        """Test successful file download"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        # Mock successful response
        mock_response = Mock()
        mock_response.text = '{"test": "data"}'
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.jsonl"
            
            engine._download_file("https://example.com/test.jsonl", str(test_file))
            
            # Verify file was created with correct content
            self.assertTrue(test_file.exists())
            with open(test_file, 'r') as f:
                content = f.read()
            self.assertEqual(content, '{"test": "data"}')
            
    @patch('requests.get')
    def test_download_file_failure(self, mock_get):
        """Test file download failure"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        # Mock failed response
        mock_get.side_effect = Exception("Network error")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.jsonl"
            
            # Should raise exception
            with self.assertRaises(Exception):
                engine._download_file("https://example.com/test.jsonl", str(test_file))
                
    @patch('os.path.getmtime')
    @patch('os.path.exists')
    @patch('time.time')
    def test_should_update_file(self, mock_time, mock_exists, mock_getmtime):
        """Test file update decision logic"""
        engine = ApktoolDetectionEngine({}, self.mock_logger)
        
        # Test non-existent file
        mock_exists.return_value = False
        result = engine._should_update_file("test.jsonl", "https://example.com")
        self.assertTrue(result)
        
        # Test old file (> 7 days)
        mock_exists.return_value = True
        mock_time.return_value = 1000000  # Current time
        mock_getmtime.return_value = 1000000 - (8 * 24 * 3600)  # 8 days ago
        result = engine._should_update_file("test.jsonl", "https://example.com")
        self.assertTrue(result)
        
        # Test recent file (< 7 days)
        mock_getmtime.return_value = 1000000 - (5 * 24 * 3600)  # 5 days ago
        result = engine._should_update_file("test.jsonl", "https://example.com")
        self.assertFalse(result)


class TestApktoolDetectionEngineIntegration(unittest.TestCase):
    """Integration tests for ApktoolDetectionEngine"""
    
    def setUp(self):
        """Set up integration test fixtures"""
        self.mock_logger = Mock()
        self.test_config = {
            'apktool_detection': {
                'enable_pattern_detection': True,
                'enable_properties_detection': True,
                'enable_buildconfig_detection': True,
                'auto_update_definitions': False
            }
        }
        
    def test_detect_libraries_integration(self):
        """Test full library detection integration"""
        engine = ApktoolDetectionEngine(self.test_config, self.mock_logger)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            apktool_dir = Path(temp_dir)
            
            # Create mock context
            mock_context = Mock()
            mock_temporal_paths = Mock()
            mock_temporal_paths.apktool_dir = apktool_dir
            mock_context.temporal_paths = mock_temporal_paths
            
            # Create some test files
            (apktool_dir / "AndroidManifest.xml").touch()
            
            # Create properties file
            props_file = apktool_dir / "test.properties"
            with open(props_file, 'w') as f:
                f.write("version=1.0.0\nclient=integration-test-lib\n")
                
            # Create BuildConfig.smali
            buildconfig_file = apktool_dir / "BuildConfig.smali"
            with open(buildconfig_file, 'w') as f:
                f.write(""".class public final Lcom/integration/test/BuildConfig;
.field public static final APPLICATION_ID:Ljava/lang/String; = "com.integration.test"
.field public static final VERSION_NAME:Ljava/lang/String; = "2.0.0"
""")
                
            errors = []
            libraries = engine.detect_libraries(mock_context, errors)
            
            # Should detect libraries from properties and BuildConfig
            self.assertGreaterEqual(len(libraries), 2)
            # Note: No expected error since pattern detection is disabled via auto_update_definitions: False


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)