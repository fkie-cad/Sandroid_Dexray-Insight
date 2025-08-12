#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for VersionAnalyzer

Tests cover version parsing, comparison, analysis, and output formatting.
"""

import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from src.dexray_insight.modules.library_detection.utils.version_analyzer import (
    VersionAnalyzer, VersionAnalysisResult, VersionInfo
)


class TestVersionAnalyzer(unittest.TestCase):
    """Test suite for VersionAnalyzer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'version_analysis': {
                'enabled': True,
                'api_timeout': 5,
                'cache_duration_hours': 24
            }
        }
        self.analyzer = VersionAnalyzer(self.config)
    
    def test_normalize_version_semantic(self):
        """Test semantic version normalization"""
        # Standard semantic versions
        self.assertEqual(self.analyzer._normalize_version("1.2.3"), "1.2.3")
        self.assertEqual(self.analyzer._normalize_version("10.20.30"), "10.20.30")
        
        # With prefixes
        self.assertEqual(self.analyzer._normalize_version("v1.2.3"), "1.2.3")
        self.assertEqual(self.analyzer._normalize_version("V2.0.1"), "2.0.1")
        
        # With suffixes
        self.assertEqual(self.analyzer._normalize_version("1.2.3-alpha"), "1.2.3")
        self.assertEqual(self.analyzer._normalize_version("1.2.3.RELEASE"), "1.2.3")
        
        # Two-part versions
        self.assertEqual(self.analyzer._normalize_version("1.2"), "1.2.0")
        self.assertEqual(self.analyzer._normalize_version("10.5"), "10.5.0")
        
        # Single number versions
        self.assertEqual(self.analyzer._normalize_version("3"), "3.0.0")
        self.assertEqual(self.analyzer._normalize_version("15"), "15.0.0")
        
        # Invalid versions
        self.assertIsNone(self.analyzer._normalize_version(""))
        self.assertIsNone(self.analyzer._normalize_version(None))
        self.assertIsNone(self.analyzer._normalize_version("invalid"))
        self.assertIsNone(self.analyzer._normalize_version("abc.def.ghi"))
    
    def test_calculate_years_behind_with_date(self):
        """Test years behind calculation with actual release date"""
        current_version = "1.0.0"
        latest_version = "2.0.0"
        
        # 2 years ago
        release_date = datetime.now() - timedelta(days=730)
        
        years_behind = self.analyzer._calculate_years_behind(
            current_version, latest_version, release_date
        )
        
        self.assertAlmostEqual(years_behind, 2.0, delta=0.1)
    
    def test_calculate_years_behind_without_date(self):
        """Test years behind calculation without release date (estimation)"""
        # Major version difference
        years_behind = self.analyzer._calculate_years_behind("1.0.0", "3.0.0", None)
        self.assertEqual(years_behind, 2.0)  # 2 major versions * 1 year each
        
        # Minor version difference
        years_behind = self.analyzer._calculate_years_behind("1.0.0", "1.4.0", None)
        self.assertEqual(years_behind, 1.0)  # 4 minor versions * 0.25 years each
        
        # Mixed difference
        years_behind = self.analyzer._calculate_years_behind("1.0.0", "2.2.0", None)
        self.assertEqual(years_behind, 1.5)  # 1 major + 2 minor = 1.0 + 0.5
        
        # Current version is same or newer
        years_behind = self.analyzer._calculate_years_behind("2.0.0", "2.0.0", None)
        self.assertEqual(years_behind, 0.0)
        
        years_behind = self.analyzer._calculate_years_behind("2.1.0", "2.0.0", None)
        self.assertEqual(years_behind, 0.0)
    
    def test_calculate_major_versions_behind(self):
        """Test major versions behind calculation"""
        self.assertEqual(self.analyzer._calculate_major_versions_behind("1.0.0", "1.5.0"), 0)
        self.assertEqual(self.analyzer._calculate_major_versions_behind("1.0.0", "2.0.0"), 1)
        self.assertEqual(self.analyzer._calculate_major_versions_behind("1.0.0", "4.0.0"), 3)
        self.assertEqual(self.analyzer._calculate_major_versions_behind("2.0.0", "2.0.0"), 0)
        self.assertEqual(self.analyzer._calculate_major_versions_behind("3.0.0", "2.0.0"), 0)
    
    def test_assess_security_risk(self):
        """Test security risk assessment"""
        # Critical risk (3+ years behind)
        risk, recommendation = self.analyzer._assess_security_risk(3.5, 2, 0)
        self.assertEqual(risk, "CRITICAL")
        self.assertIn("Extremely outdated", recommendation)
        
        # High risk (2+ years behind)
        risk, recommendation = self.analyzer._assess_security_risk(2.2, 1, 0)
        self.assertEqual(risk, "HIGH")
        self.assertIn("Very outdated", recommendation)
        
        # Medium risk (1+ years behind)
        risk, recommendation = self.analyzer._assess_security_risk(1.3, 0, 0)
        self.assertEqual(risk, "MEDIUM")
        self.assertIn("Outdated", recommendation)
        
        # Low risk (0.5+ years behind)
        risk, recommendation = self.analyzer._assess_security_risk(0.7, 0, 0)
        self.assertEqual(risk, "LOW")
        self.assertIn("Slightly outdated", recommendation)
        
        # Current
        risk, recommendation = self.analyzer._assess_security_risk(0.1, 0, 0)
        self.assertEqual(risk, "LOW")
        self.assertIn("relatively current", recommendation)
        
        # Risk escalation with major versions
        risk, recommendation = self.analyzer._assess_security_risk(0.8, 3, 0)
        self.assertEqual(risk, "HIGH")  # Escalated from LOW
        self.assertIn("major versions behind", recommendation)
        
        # Risk escalation with vulnerabilities
        risk, recommendation = self.analyzer._assess_security_risk(0.3, 0, 2)
        self.assertEqual(risk, "MEDIUM")  # Escalated from LOW
        self.assertIn("vulnerabilities", recommendation)
    
    def test_format_version_output(self):
        """Test version output formatting"""
        analysis = VersionAnalysisResult(
            current_version="2.8.5",
            latest_version="2.10.1",
            years_behind=1.5,
            security_risk="MEDIUM"
        )
        
        formatted = self.analyzer.format_version_output(
            "Gson", analysis, "/com/google/gson/"
        )
        
        expected = "Gson (2.8.5): /com/google/gson/ : 1.5 years behind ⚠️ MEDIUM RISK"
        self.assertEqual(formatted, expected)
        
        # Without smali path
        formatted = self.analyzer.format_version_output("Gson", analysis)
        expected = "Gson (2.8.5): 1.5 years behind ⚠️ MEDIUM RISK"
        self.assertEqual(formatted, expected)
        
        # Critical risk
        analysis.security_risk = "CRITICAL"
        formatted = self.analyzer.format_version_output("Gson", analysis)
        self.assertIn("CRITICAL", formatted)
        
        # High risk
        analysis.security_risk = "HIGH"
        formatted = self.analyzer.format_version_output("Gson", analysis)
        self.assertIn("HIGH RISK", formatted)
        
        # No years behind data
        analysis.years_behind = None
        formatted = self.analyzer.format_version_output("Gson", analysis)
        self.assertIn("version analysis unavailable", formatted)
    
    @patch('requests.get')
    def test_check_maven_central_success(self, mock_get):
        """Test successful Maven Central API call"""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            'response': {
                'docs': [{
                    'latestVersion': '2.10.1',
                    'timestamp': 1609459200000  # 2021-01-01
                }]
            }
        }
        mock_get.return_value = mock_response
        
        version_info = self.analyzer._check_maven_central("Gson", "com.google.code.gson.gson")
        
        self.assertIsNotNone(version_info)
        self.assertEqual(version_info.version, "2.10.1")
        self.assertTrue(version_info.is_latest)
        self.assertIsInstance(version_info.release_date, datetime)
    
    @patch('requests.get')
    def test_check_maven_central_failure(self, mock_get):
        """Test Maven Central API failure"""
        mock_get.side_effect = Exception("API Error")
        
        version_info = self.analyzer._check_maven_central("Gson", "com.google.code.gson")
        self.assertIsNone(version_info)
    
    @patch('src.dexray_insight.modules.library_detection.utils.library_mappings.get_library_mapping')
    @patch('requests.get')
    def test_check_google_maven_success(self, mock_get, mock_mapping):
        """Test successful Google Maven API call for Play Services library"""
        # Mock library mapping
        mock_mapping_obj = Mock()
        mock_mapping_obj.maven_group_id = "com.google.android.gms"
        mock_mapping_obj.maven_artifact_id = "play-services-cast"
        mock_mapping.return_value = mock_mapping_obj
        
        # Mock successful XML response from Google Maven
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """<?xml version="1.0" encoding="UTF-8"?>
        <metadata>
            <versioning>
                <release>21.6.0</release>
                <latest>21.6.0</latest>
            </versioning>
        </metadata>"""
        mock_get.return_value = mock_response
        
        version_info = self.analyzer._check_google_maven("play-services-cast")
        
        self.assertIsNotNone(version_info)
        self.assertEqual(version_info.version, "21.6.0")
        self.assertTrue(version_info.is_latest)
    
    @patch('src.dexray_insight.modules.library_detection.utils.library_mappings.get_library_mapping')
    def test_check_google_maven_no_mapping(self, mock_mapping):
        """Test Google Maven when no library mapping exists"""
        mock_mapping.return_value = None
        
        version_info = self.analyzer._check_google_maven("unknown-library")
        self.assertIsNone(version_info)
    
    @patch('src.dexray_insight.modules.library_detection.utils.library_mappings.get_library_mapping')
    def test_check_google_maven_non_google_library(self, mock_mapping):
        """Test Google Maven skips non-Google libraries"""
        # Mock mapping for non-Google library
        mock_mapping_obj = Mock()
        mock_mapping_obj.maven_group_id = "com.example.thirdparty"
        mock_mapping_obj.maven_artifact_id = "some-library"
        mock_mapping.return_value = mock_mapping_obj
        
        version_info = self.analyzer._check_google_maven("some-library")
        self.assertIsNone(version_info)
    
    def test_get_known_google_versions(self):
        """Test fallback to known Google library versions"""
        # Test known Play Services library
        version_info = self.analyzer._get_known_google_versions(
            "com.google.android.gms", "play-services-cast"
        )
        self.assertIsNotNone(version_info)
        self.assertEqual(version_info.version, "21.6.0")
        self.assertTrue(version_info.is_latest)
        
        # Test known Firebase library
        version_info = self.analyzer._get_known_google_versions(
            "com.google.firebase", "firebase-messaging"
        )
        self.assertIsNotNone(version_info)
        self.assertEqual(version_info.version, "24.1.0")
        
        # Test unknown library
        version_info = self.analyzer._get_known_google_versions(
            "com.google.android.gms", "unknown-service"
        )
        self.assertIsNone(version_info)
    
    def test_cache_functionality(self):
        """Test version info caching"""
        # Create analyzer with short cache duration for testing
        config = {'version_analysis': {'cache_duration_hours': 0.001}}  # ~3.6 seconds
        analyzer = VersionAnalyzer(config)
        
        cache_key = "test_library"
        version_info = VersionInfo(version="1.0.0", is_latest=True)
        
        # Cache the version info
        analyzer._version_cache[cache_key] = version_info
        analyzer._cache_timestamps[cache_key] = datetime.now()
        
        # Should be valid immediately
        self.assertTrue(analyzer._is_cached_valid(cache_key))
        
        # Make cache timestamp old
        analyzer._cache_timestamps[cache_key] = datetime.now() - timedelta(hours=1)
        
        # Should be invalid now
        self.assertFalse(analyzer._is_cached_valid(cache_key))
    
    def test_disabled_version_checking(self):
        """Test behavior when version checking is disabled"""
        config = {'version_analysis': {'enabled': False}}
        analyzer = VersionAnalyzer(config)
        
        result = analyzer.analyze_library_version("Test Library", "1.0.0")
        
        self.assertEqual(result.current_version, "1.0.0")
        self.assertIsNone(result.latest_version)
        self.assertIsNone(result.years_behind)
        self.assertIn("disabled", result.recommendation)
    
    def test_security_only_version_analysis_enabled(self):
        """Test version analysis runs when security analysis is enabled"""
        config = {
            'version_analysis': {
                'enabled': True,
                'security_analysis_only': True
            }
        }
        analyzer = VersionAnalyzer(config, security_analysis_enabled=True)
        
        result = analyzer.analyze_library_version("Test Library", "1.0.0")
        
        self.assertEqual(result.current_version, "1.0.0")
        self.assertNotIn("only runs during security analysis", result.recommendation)
    
    def test_security_only_version_analysis_disabled(self):
        """Test version analysis skips when security analysis is disabled"""
        config = {
            'version_analysis': {
                'enabled': True,
                'security_analysis_only': True
            }
        }
        analyzer = VersionAnalyzer(config, security_analysis_enabled=False)
        
        result = analyzer.analyze_library_version("Test Library", "1.0.0")
        
        self.assertEqual(result.current_version, "1.0.0")
        self.assertIsNone(result.latest_version)
        self.assertIsNone(result.years_behind)
        self.assertIn("only runs during security analysis", result.recommendation)
        self.assertIn("use -s flag", result.recommendation)
    
    def test_security_only_false_always_runs(self):
        """Test version analysis always runs when security_analysis_only is False"""
        config = {
            'version_analysis': {
                'enabled': True,
                'security_analysis_only': False
            }
        }
        analyzer = VersionAnalyzer(config, security_analysis_enabled=False)
        
        result = analyzer.analyze_library_version("Test Library", "1.0.0")
        
        self.assertEqual(result.current_version, "1.0.0")
        self.assertNotIn("only runs during security analysis", result.recommendation)
        self.assertNotIn("disabled", result.recommendation)


class TestVersionAnalysisResult(unittest.TestCase):
    """Test suite for VersionAnalysisResult"""
    
    def test_post_init(self):
        """Test VersionAnalysisResult post-initialization"""
        result = VersionAnalysisResult(current_version="1.0.0")
        
        # analysis_date should be set automatically
        self.assertIsInstance(result.analysis_date, datetime)
        
        # Should be within the last few seconds
        time_diff = datetime.now() - result.analysis_date
        self.assertLess(time_diff.total_seconds(), 5)
    
    def test_custom_analysis_date(self):
        """Test VersionAnalysisResult with custom analysis date"""
        custom_date = datetime(2023, 1, 1)
        result = VersionAnalysisResult(
            current_version="1.0.0",
            analysis_date=custom_date
        )
        
        self.assertEqual(result.analysis_date, custom_date)


if __name__ == '__main__':
    unittest.main(verbosity=2)