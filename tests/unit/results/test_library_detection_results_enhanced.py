#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for enhanced LibraryDetectionResults functionality

Tests the new version analysis fields and formatting methods.
"""

import unittest
from src.dexray_insight.results.LibraryDetectionResults import (
    DetectedLibrary, LibraryDetectionMethod, LibraryCategory, LibrarySource
)


class TestDetectedLibraryEnhanced(unittest.TestCase):
    """Test enhanced DetectedLibrary functionality"""
    
    def test_version_analysis_fields(self):
        """Test new version analysis fields"""
        library = DetectedLibrary(
            name="Test Library",
            version="1.0.0",
            detection_method=LibraryDetectionMethod.FILE_ANALYSIS,
            years_behind=2.5,
            major_versions_behind=1,
            security_risk="HIGH",
            version_recommendation="Update immediately",
            version_analysis_date="2023-01-01T10:00:00",
            smali_path="/com/test/library/"
        )
        
        self.assertEqual(library.years_behind, 2.5)
        self.assertEqual(library.major_versions_behind, 1)
        self.assertEqual(library.security_risk, "HIGH")
        self.assertEqual(library.version_recommendation, "Update immediately")
        self.assertEqual(library.version_analysis_date, "2023-01-01T10:00:00")
        self.assertEqual(library.smali_path, "/com/test/library/")
    
    def test_to_dict_enhanced(self):
        """Test enhanced to_dict method includes new fields"""
        library = DetectedLibrary(
            name="Test Library",
            version="1.0.0",
            detection_method=LibraryDetectionMethod.FILE_ANALYSIS,
            years_behind=1.5,
            security_risk="MEDIUM",
            smali_path="/com/test/",
            url="https://example.com",
            license="MIT",
            anti_features=["tracking"]
        )
        
        result_dict = library.to_dict()
        
        # Check new fields are present
        self.assertEqual(result_dict['years_behind'], 1.5)
        self.assertEqual(result_dict['security_risk'], "MEDIUM")
        self.assertEqual(result_dict['smali_path'], "/com/test/")
        self.assertEqual(result_dict['url'], "https://example.com")
        self.assertEqual(result_dict['license'], "MIT")
        self.assertEqual(result_dict['anti_features'], ["tracking"])
    
    def test_format_version_output_with_version(self):
        """Test format_version_output with version information"""
        library = DetectedLibrary(
            name="Gson",
            version="2.8.5",
            detection_method=LibraryDetectionMethod.FILE_ANALYSIS,
            smali_path="/com/google/gson/",
            years_behind=2.1,
            security_risk="HIGH"
        )
        
        formatted = library.format_version_output()
        expected = "Gson (2.8.5): /com/google/gson/: 2.1 years behind ⚠️ HIGH RISK"
        self.assertEqual(formatted, expected)
    
    def test_format_version_output_without_version(self):
        """Test format_version_output without version information"""
        library = DetectedLibrary(
            name="Unknown Library",
            detection_method=LibraryDetectionMethod.PATTERN_MATCHING
        )
        
        formatted = library.format_version_output()
        expected = "Unknown Library: version unknown"
        self.assertEqual(formatted, expected)
    
    def test_format_version_output_various_risks(self):
        """Test format_version_output with different security risks"""
        base_library = DetectedLibrary(
            name="Test Library",
            version="1.0.0",
            detection_method=LibraryDetectionMethod.FILE_ANALYSIS,
            smali_path="/test/",
            years_behind=1.0
        )
        
        # Critical risk
        base_library.security_risk = "CRITICAL"
        formatted = base_library.format_version_output()
        self.assertIn("⚠️ CRITICAL", formatted)
        
        # High risk
        base_library.security_risk = "HIGH"
        formatted = base_library.format_version_output()
        self.assertIn("⚠️ HIGH RISK", formatted)
        
        # Medium risk
        base_library.security_risk = "MEDIUM"
        formatted = base_library.format_version_output()
        self.assertIn("⚠️ MEDIUM RISK", formatted)
        
        # Low risk (no indicator)
        base_library.security_risk = "LOW"
        formatted = base_library.format_version_output()
        self.assertNotIn("⚠️", formatted)
        
        # No risk info
        base_library.security_risk = None
        formatted = base_library.format_version_output()
        self.assertNotIn("⚠️", formatted)
    
    def test_format_version_output_without_smali_path(self):
        """Test format_version_output without smali path"""
        library = DetectedLibrary(
            name="Library",
            version="1.0.0",
            detection_method=LibraryDetectionMethod.BUILDCONFIG_ANALYSIS,
            years_behind=0.5,
            security_risk="LOW"
        )
        
        formatted = library.format_version_output()
        expected = "Library (1.0.0): 0.5 years behind"
        self.assertEqual(formatted, expected)
    
    def test_format_version_output_without_years_behind(self):
        """Test format_version_output without years behind information"""
        library = DetectedLibrary(
            name="Library",
            version="1.0.0",
            detection_method=LibraryDetectionMethod.PATTERN_MATCHING,
            smali_path="/test/"
        )
        
        formatted = library.format_version_output()
        expected = "Library (1.0.0): /test/"
        self.assertEqual(formatted, expected)
    
    def test_post_init_new_fields(self):
        """Test that __post_init__ handles new list fields"""
        library = DetectedLibrary(
            name="Test Library",
            detection_method=LibraryDetectionMethod.HEURISTIC
        )
        
        # All list fields should be initialized as empty lists
        self.assertEqual(library.evidence, [])
        self.assertEqual(library.classes_detected, [])
        self.assertEqual(library.matched_signatures, [])
        self.assertEqual(library.architectures, [])
        self.assertEqual(library.file_paths, [])
        self.assertEqual(library.vulnerabilities, [])
        self.assertEqual(library.anti_features, [])


class TestLibraryDetectionResultsIntegration(unittest.TestCase):
    """Integration tests for library detection results with version analysis"""
    
    def test_complete_library_with_version_analysis(self):
        """Test complete library object with all version analysis fields"""
        library = DetectedLibrary(
            name="OkHttp",
            package_name="com.squareup.okhttp3",
            version="3.12.0",
            category=LibraryCategory.NETWORKING,
            detection_method=LibraryDetectionMethod.BUILDCONFIG_ANALYSIS,
            confidence=0.9,
            evidence=["Found in BuildConfig.smali"],
            source=LibrarySource.SMALI_CLASSES,
            smali_path="/com/squareup/okhttp3/BuildConfig.smali",
            url="https://square.github.io/okhttp/",
            license="Apache-2.0",
            # Version analysis fields
            latest_version="4.12.0",
            years_behind=2.3,
            major_versions_behind=1,
            security_risk="HIGH",
            version_recommendation="Update to latest version for security fixes",
            version_analysis_date="2023-12-01T15:30:00"
        )
        
        # Test formatted output
        formatted = library.format_version_output()
        self.assertIn("OkHttp (3.12.0)", formatted)
        self.assertIn("BuildConfig.smali", formatted)
        self.assertIn("2.3 years behind", formatted)
        self.assertIn("⚠️ HIGH RISK", formatted)
        
        # Test dictionary export
        result_dict = library.to_dict()
        self.assertEqual(result_dict['latest_version'], "4.12.0")
        self.assertEqual(result_dict['years_behind'], 2.3)
        self.assertEqual(result_dict['major_versions_behind'], 1)
        self.assertEqual(result_dict['security_risk'], "HIGH")
        self.assertEqual(result_dict['version_recommendation'], "Update to latest version for security fixes")
        self.assertEqual(result_dict['version_analysis_date'], "2023-12-01T15:30:00")
        
        # Test that all fields are present in dict
        expected_fields = [
            'name', 'version', 'latest_version', 'years_behind', 
            'major_versions_behind', 'security_risk', 'version_recommendation',
            'version_analysis_date', 'smali_path', 'url', 'license'
        ]
        for field in expected_fields:
            self.assertIn(field, result_dict)
    
    def test_json_serialization_with_version_data(self):
        """Test that library can be properly serialized to JSON"""
        import json
        
        library = DetectedLibrary(
            name="Test Library",
            version="1.0.0",
            detection_method=LibraryDetectionMethod.FILE_ANALYSIS,
            years_behind=1.5,
            security_risk="MEDIUM",
            anti_features=["tracking", "ads"]
        )
        
        # Should be able to serialize to JSON
        json_str = json.dumps(library.to_dict(), indent=2)
        self.assertIn('"years_behind": 1.5', json_str)
        self.assertIn('"security_risk": "MEDIUM"', json_str)
        self.assertIn('"anti_features": ["tracking", "ads"]', json_str)
        
        # Should be able to deserialize
        parsed = json.loads(json_str)
        self.assertEqual(parsed['years_behind'], 1.5)
        self.assertEqual(parsed['security_risk'], "MEDIUM")
        self.assertEqual(parsed['anti_features'], ["tracking", "ads"])


if __name__ == '__main__':
    unittest.main(verbosity=2)