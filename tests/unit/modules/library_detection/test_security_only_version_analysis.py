#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for Security-Only Version Analysis

Tests the new requirement that version analysis should only run during
security analysis (-s flag) while still allowing it to be disabled
within security analysis through configuration.
"""

import unittest
from unittest.mock import Mock, patch

from src.dexray_insight.modules.library_detection.utils.version_analyzer import (
    VersionAnalyzer, get_version_analyzer
)
from src.dexray_insight.modules.library_detection.engines.coordinator import LibraryDetectionCoordinator
from src.dexray_insight.core.base_classes import AnalysisContext
from src.dexray_insight.results.LibraryDetectionResults import (
    DetectedLibrary, LibraryCategory, LibraryDetectionMethod, 
    LibrarySource, RiskLevel
)


class TestSecurityOnlyVersionAnalysis(unittest.TestCase):
    """Test suite for security-only version analysis functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.base_config = {
            'version_analysis': {
                'enabled': True,
                'security_analysis_only': True,  # Default: only run during security analysis
                'api_timeout': 5,
                'cache_duration_hours': 24
            }
        }
        
        self.context_with_security = AnalysisContext(
            'test.apk',
            {
                'security': {'enable_owasp_assessment': True},
                'modules': {
                    'library_detection': {
                        'version_analysis': {
                            'enabled': True,
                            'security_analysis_only': True
                        }
                    }
                }
            }
        )
        
        self.context_without_security = AnalysisContext(
            'test.apk', 
            {
                'security': {'enable_owasp_assessment': False},
                'modules': {
                    'library_detection': {
                        'version_analysis': {
                            'enabled': True,
                            'security_analysis_only': True
                        }
                    }
                }
            }
        )
    
    def test_version_analyzer_with_security_analysis_enabled(self):
        """Test version analyzer runs when security analysis is enabled"""
        analyzer = VersionAnalyzer(
            config=self.base_config,
            security_analysis_enabled=True
        )
        
        # Should be enabled
        self.assertTrue(analyzer.enable_version_checking)
        self.assertTrue(analyzer.security_analysis_only)
        self.assertTrue(analyzer.security_analysis_enabled)
        
        # Should perform analysis
        result = analyzer.analyze_library_version("Test Library", "1.0.0")
        
        self.assertEqual(result.current_version, "1.0.0")
        self.assertNotIn("only runs during security analysis", result.recommendation)
    
    def test_version_analyzer_with_security_analysis_disabled(self):
        """Test version analyzer skips when security analysis is disabled"""
        analyzer = VersionAnalyzer(
            config=self.base_config,
            security_analysis_enabled=False
        )
        
        # Should be configured for security-only
        self.assertTrue(analyzer.enable_version_checking)
        self.assertTrue(analyzer.security_analysis_only)
        self.assertFalse(analyzer.security_analysis_enabled)
        
        # Should skip analysis
        result = analyzer.analyze_library_version("Test Library", "1.0.0")
        
        self.assertEqual(result.current_version, "1.0.0")
        self.assertIn("only runs during security analysis", result.recommendation)
        self.assertIn("use -s flag", result.recommendation)
        self.assertIsNone(result.latest_version)
        self.assertIsNone(result.years_behind)
    
    def test_version_analyzer_always_enabled_mode(self):
        """Test version analyzer runs always when security_analysis_only is False"""
        config = {
            'version_analysis': {
                'enabled': True,
                'security_analysis_only': False,  # Always run
                'api_timeout': 5,
                'cache_duration_hours': 24
            }
        }
        
        analyzer = VersionAnalyzer(
            config=config,
            security_analysis_enabled=False  # Even without security analysis
        )
        
        # Should be configured to run always
        self.assertTrue(analyzer.enable_version_checking)
        self.assertFalse(analyzer.security_analysis_only)
        self.assertFalse(analyzer.security_analysis_enabled)
        
        # Should perform analysis even without security analysis
        result = analyzer.analyze_library_version("Test Library", "1.0.0")
        
        self.assertEqual(result.current_version, "1.0.0")
        self.assertNotIn("only runs during security analysis", result.recommendation)
    
    def test_version_analysis_disabled_in_config(self):
        """Test version analyzer completely disabled in configuration"""
        config = {
            'version_analysis': {
                'enabled': False,  # Completely disabled
                'security_analysis_only': True,
                'api_timeout': 5,
                'cache_duration_hours': 24
            }
        }
        
        analyzer = VersionAnalyzer(
            config=config,
            security_analysis_enabled=True  # Even with security analysis
        )
        
        # Should be disabled regardless of security analysis
        self.assertFalse(analyzer.enable_version_checking)
        
        # Should skip analysis due to being disabled
        result = analyzer.analyze_library_version("Test Library", "1.0.0")
        
        self.assertEqual(result.current_version, "1.0.0")
        self.assertIn("disabled in configuration", result.recommendation)
    
    def test_get_version_analyzer_with_security_context(self):
        """Test get_version_analyzer factory function with security context"""
        config = {'version_analysis': {'enabled': True, 'security_analysis_only': True}}
        
        # With security analysis enabled
        analyzer_with_security = get_version_analyzer(config, security_analysis_enabled=True)
        self.assertTrue(analyzer_with_security.security_analysis_enabled)
        
        # Without security analysis enabled
        analyzer_without_security = get_version_analyzer(config, security_analysis_enabled=False)
        self.assertFalse(analyzer_without_security.security_analysis_enabled)
    
    def test_coordinator_print_version_results_with_security(self):
        """Test coordinator displays version results when security analysis is enabled"""
        mock_parent = Mock()
        mock_parent.logger = Mock()
        coordinator = LibraryDetectionCoordinator(mock_parent)
        
        # Create test library with version information
        test_library = DetectedLibrary(
            name="Test Library",
            category=LibraryCategory.UTILITY,
            detection_method=LibraryDetectionMethod.HEURISTIC,
            source=LibrarySource.SMALI_CLASSES,
            risk_level=RiskLevel.LOW
        )
        test_library.version = "1.0.0"
        test_library.years_behind = 2.5
        test_library.security_risk = "HIGH"
        
        libraries = [test_library]
        
        # Test with security analysis enabled
        with patch('builtins.print') as mock_print:
            coordinator._print_version_analysis_results(libraries, self.context_with_security)
            
            # Should print version analysis results
            print_calls = [call[0][0] for call in mock_print.call_args_list if call[0]]
            version_analysis_printed = any("LIBRARY VERSION ANALYSIS" in str(call) for call in print_calls)
            self.assertTrue(version_analysis_printed, "Version analysis should be printed with security analysis")
    
    def test_coordinator_skip_version_results_without_security(self):
        """Test coordinator skips version results when security analysis is disabled"""
        mock_parent = Mock()
        mock_parent.logger = Mock()
        coordinator = LibraryDetectionCoordinator(mock_parent)
        
        # Create test library with version information
        test_library = DetectedLibrary(
            name="Test Library",
            category=LibraryCategory.UTILITY,
            detection_method=LibraryDetectionMethod.HEURISTIC,
            source=LibrarySource.SMALI_CLASSES,
            risk_level=RiskLevel.LOW
        )
        test_library.version = "1.0.0"
        
        libraries = [test_library]
        
        # Test without security analysis
        with patch('builtins.print') as mock_print:
            coordinator._print_version_analysis_results(libraries, self.context_without_security)
            
            # Should not print version analysis results
            print_calls = [call[0][0] for call in mock_print.call_args_list if call[0]]
            version_analysis_printed = any("LIBRARY VERSION ANALYSIS" in str(call) for call in print_calls)
            self.assertFalse(version_analysis_printed, "Version analysis should be skipped without security analysis")
        
        # Should log appropriate message
        mock_parent.logger.info.assert_called_with("Version analysis only runs during security analysis (use -s flag)")
    
    def test_coordinator_version_analysis_disabled_in_config(self):
        """Test coordinator respects version analysis disabled in configuration"""
        mock_parent = Mock()
        mock_parent.logger = Mock()
        coordinator = LibraryDetectionCoordinator(mock_parent)
        
        # Create context with version analysis disabled
        context_disabled = AnalysisContext(
            'test.apk',
            {
                'security': {'enable_owasp_assessment': True},
                'modules': {
                    'library_detection': {
                        'version_analysis': {
                            'enabled': False,  # Disabled
                            'security_analysis_only': True
                        }
                    }
                }
            }
        )
        
        test_library = DetectedLibrary(
            name="Test Library",
            category=LibraryCategory.UTILITY,
            detection_method=LibraryDetectionMethod.HEURISTIC,
            source=LibrarySource.SMALI_CLASSES,
            risk_level=RiskLevel.LOW
        )
        test_library.version = "1.0.0"
        
        libraries = [test_library]
        
        # Test with version analysis disabled
        with patch('builtins.print') as mock_print:
            coordinator._print_version_analysis_results(libraries, context_disabled)
            
            # Should not print version analysis results
            print_calls = [call[0][0] for call in mock_print.call_args_list if call[0]]
            version_analysis_printed = any("LIBRARY VERSION ANALYSIS" in str(call) for call in print_calls)
            self.assertFalse(version_analysis_printed, "Version analysis should be skipped when disabled")
        
        # Should log appropriate message
        mock_parent.logger.info.assert_called_with("Version analysis disabled in configuration")
    
    def test_coordinator_version_analysis_always_mode(self):
        """Test coordinator works when version analysis is not security-only"""
        mock_parent = Mock()
        mock_parent.logger = Mock()
        coordinator = LibraryDetectionCoordinator(mock_parent)
        
        # Create context with security_analysis_only = False
        context_always = AnalysisContext(
            'test.apk',
            {
                'security': {'enable_owasp_assessment': False},  # Security disabled
                'modules': {
                    'library_detection': {
                        'version_analysis': {
                            'enabled': True,
                            'security_analysis_only': False  # Should run always
                        }
                    }
                }
            }
        )
        
        test_library = DetectedLibrary(
            name="Test Library",
            category=LibraryCategory.UTILITY,
            detection_method=LibraryDetectionMethod.HEURISTIC,
            source=LibrarySource.SMALI_CLASSES,
            risk_level=RiskLevel.LOW
        )
        test_library.version = "1.0.0"
        
        libraries = [test_library]
        
        # Test with security_analysis_only = False
        with patch('builtins.print') as mock_print:
            coordinator._print_version_analysis_results(libraries, context_always)
            
            # Should print version analysis results even without security analysis
            print_calls = [call[0][0] for call in mock_print.call_args_list if call[0]]
            version_analysis_printed = any("LIBRARY VERSION ANALYSIS" in str(call) for call in print_calls)
            self.assertTrue(version_analysis_printed, "Version analysis should run when security_analysis_only is False")
    
    def test_version_analyzer_priority_logic(self):
        """Test the priority logic: disabled > security-only > always-enabled"""
        # Test 1: Disabled takes highest priority
        config_disabled = {
            'version_analysis': {
                'enabled': False,
                'security_analysis_only': False  # This should be ignored
            }
        }
        analyzer = VersionAnalyzer(config_disabled, security_analysis_enabled=True)
        result = analyzer.analyze_library_version("Test", "1.0.0")
        self.assertIn("disabled in configuration", result.recommendation)
        
        # Test 2: Security-only when enabled=True, security_analysis_only=True, security_analysis_enabled=False
        config_security_only = {
            'version_analysis': {
                'enabled': True,
                'security_analysis_only': True
            }
        }
        analyzer = VersionAnalyzer(config_security_only, security_analysis_enabled=False)
        result = analyzer.analyze_library_version("Test", "1.0.0")
        self.assertIn("only runs during security analysis", result.recommendation)
        
        # Test 3: Always enabled when security_analysis_only=False
        config_always = {
            'version_analysis': {
                'enabled': True,
                'security_analysis_only': False
            }
        }
        analyzer = VersionAnalyzer(config_always, security_analysis_enabled=False)
        result = analyzer.analyze_library_version("Test", "1.0.0")
        # Should not contain either disabled or security-only messages
        self.assertNotIn("disabled in configuration", result.recommendation)
        self.assertNotIn("only runs during security analysis", result.recommendation)


class TestSecurityOnlyVersionAnalysisIntegration(unittest.TestCase):
    """Integration tests for security-only version analysis"""
    
    def test_apktool_detection_engine_security_context(self):
        """Test ApktoolDetectionEngine properly handles security context"""
        from src.dexray_insight.modules.library_detection.engines.apktool_detection_engine import ApktoolDetectionEngine
        
        # Create engine with standard config
        config = {
            'apktool_detection': {
                'enable_properties_detection': True
            },
            'version_analysis': {
                'enabled': True,
                'security_analysis_only': True
            }
        }
        
        engine = ApktoolDetectionEngine(config)
        
        # Test with security analysis enabled
        context_with_security = AnalysisContext(
            'test.apk',
            {
                'security': {'enable_owasp_assessment': True},
                'modules': {
                    'library_detection': {
                        'version_analysis': {
                            'enabled': True,
                            'security_analysis_only': True
                        }
                    }
                }
            }
        )
        
        # Create mock temporal paths to satisfy is_available check
        mock_temporal_paths = Mock()
        mock_apktool_dir = Mock()
        mock_apktool_dir.exists.return_value = True
        mock_apktool_dir.iterdir.return_value = ['some_file']  # Non-empty directory
        mock_temporal_paths.apktool_dir = mock_apktool_dir
        context_with_security.temporal_paths = mock_temporal_paths
        
        # Mock the detection methods to avoid actual file system operations
        with patch.object(engine, '_scan_lib_patterns', return_value=[]), \
             patch.object(engine, '_scan_properties', return_value=[]), \
             patch.object(engine, '_scan_buildconfig_smali', return_value=[]), \
             patch.object(engine, '_deduplicate_libraries', side_effect=lambda x: x):
            
            errors = []
            engine.detect_libraries(context_with_security, errors)
            
            # Should have created version analyzer with security context
            self.assertIsNotNone(engine.version_analyzer)
            self.assertTrue(engine.version_analyzer.security_analysis_enabled)
        
        # Test without security analysis
        context_without_security = AnalysisContext(
            'test.apk',
            {
                'security': {'enable_owasp_assessment': False},
                'modules': {
                    'library_detection': {
                        'version_analysis': {
                            'enabled': True,
                            'security_analysis_only': True
                        }
                    }
                }
            }
        )
        context_without_security.temporal_paths = mock_temporal_paths
        
        with patch.object(engine, '_scan_lib_patterns', return_value=[]), \
             patch.object(engine, '_scan_properties', return_value=[]), \
             patch.object(engine, '_scan_buildconfig_smali', return_value=[]), \
             patch.object(engine, '_deduplicate_libraries', side_effect=lambda x: x):
            
            errors = []
            engine.detect_libraries(context_without_security, errors)
            
            # Should have created version analyzer without security context
            self.assertIsNotNone(engine.version_analyzer)
            self.assertFalse(engine.version_analyzer.security_analysis_enabled)


if __name__ == '__main__':
    unittest.main(verbosity=2)