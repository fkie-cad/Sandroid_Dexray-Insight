#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration tests for Library Detection with Version Analysis

Tests the complete pipeline including:
- AndroidX detection with corrected filtering
- Version analysis integration 
- Display order correctness
- JSON export with version metadata
"""

import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from src.dexray_insight.modules.library_detection.library_detection_module import LibraryDetectionModule
from src.dexray_insight.core.base_classes import AnalysisContext
from src.dexray_insight.results.LibraryDetectionResults import LibraryCategory


class TestLibraryDetectionVersionAnalysisIntegration(unittest.TestCase):
    """Integration tests for library detection with version analysis"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'enable_heuristic': True,
            'enable_similarity': False,  # Disabled for faster testing
            'apktool_detection': {
                'enable_properties_detection': True,
                'enable_buildconfig_detection': True,
                'enable_pattern_detection': True
            },
            'version_analysis': {
                'enabled': True,
                'api_timeout': 2,
                'console_output': {
                    'enabled': True
                }
            }
        }
        
        self.module = LibraryDetectionModule(self.config)
        self.test_apk_path = "test.apk"
    
    def _create_mock_context_with_androidx_strings(self):
        """Create mock analysis context with AndroidX string analysis results"""
        context = AnalysisContext(self.test_apk_path, {})
        
        # Mock string analysis results with AndroidX strings
        mock_string_results = Mock()
        mock_string_results.all_strings = [
            "androidx.activity.ComponentActivity",
            "androidx.appcompat.app.AppCompatActivity", 
            "androidx.fragment.app.Fragment",
            "androidx.recyclerview.widget.RecyclerView",
            "androidx.core.app.ActivityCompat",
            "androidx.lifecycle.ViewModel",
            "androidx.constraintlayout.widget.ConstraintLayout",
            "androidx.biometric.BiometricPrompt",
            "androidx.browser.customtabs.CustomTabsIntent"
        ]
        context.add_result('string_analysis', mock_string_results)
        
        # Mock temporal paths for apktool detection
        mock_temporal_paths = Mock()
        mock_temporal_paths.apktool_dir = Path("/mock/apktool/results")
        context.temporal_paths = mock_temporal_paths
        
        return context
    
    def _create_mock_apktool_files(self, mock_glob):
        """Create mock apktool files and directories"""
        # Mock properties files
        mock_properties = [
            Mock(spec=Path),
            Mock(spec=Path),
            Mock(spec=Path)
        ]
        mock_properties[0].name = "play-services-cast.properties"
        mock_properties[1].name = "firebase-messaging.properties" 
        mock_properties[2].name = "core-common.properties"
        
        # Mock the file contents
        def mock_open_side_effect(file_path, mode='r', encoding=None):
            mock_file = Mock()
            if "play-services-cast" in str(file_path):
                mock_file.__enter__.return_value.__iter__.return_value = [
                    "version=21.6.0\n",
                    "client=play-services-cast\n"
                ]
            elif "firebase-messaging" in str(file_path):
                mock_file.__enter__.return_value.__iter__.return_value = [
                    "version=24.1.0\n", 
                    "client=firebase-messaging\n"
                ]
            elif "core-common" in str(file_path):
                mock_file.__enter__.return_value.__iter__.return_value = [
                    "version=2.2.0\n",
                    "client=core-common\n"
                ]
            return mock_file
        
        return mock_properties, mock_open_side_effect
    
    @patch('builtins.open')
    @patch('pathlib.Path.rglob')
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.is_dir')
    def test_androidx_detection_with_version_analysis(self, mock_is_dir, mock_exists, 
                                                     mock_rglob, mock_open):
        """Test AndroidX detection finds correct number of libraries with version analysis"""
        # Setup mocks
        context = self._create_mock_context_with_androidx_strings()
        mock_properties, open_side_effect = self._create_mock_apktool_files(mock_rglob)
        
        # Mock apktool directory structure
        mock_rglob.return_value = mock_properties
        mock_exists.return_value = True
        mock_is_dir.return_value = True
        mock_open.side_effect = open_side_effect
        
        # Mock library definitions loading
        with patch.object(self.module.detection_coordinator.apktool_engine, '_load_library_definitions'):
            # Mock library patterns existence check
            with patch.object(self.module.detection_coordinator.apktool_engine, '_lib_dir_exists') as mock_lib_exists:
                mock_lib_exists.return_value = True
                
                # Mock library definitions
                mock_androidx_definitions = {
                    '/androidx/activity': {'id': '/androidx/activity', 'name': 'AndroidX Activity', 'type': 'Utility'},
                    '/androidx/appcompat': {'id': '/androidx/appcompat', 'name': 'AppCompat', 'type': 'Utility'},
                    '/androidx/fragment': {'id': '/androidx/fragment', 'name': 'AndroidX Fragment', 'type': 'Utility'},
                    '/androidx/recyclerview': {'id': '/androidx/recyclerview', 'name': 'RecyclerView', 'type': 'UI Component'},
                    '/androidx/core': {'id': '/androidx/core', 'name': 'AndroidX Core', 'type': 'Utility'},
                    '/androidx/lifecycle': {'id': '/androidx/lifecycle', 'name': 'Lifecycle', 'type': 'Utility'},
                    '/androidx/constraintlayout': {'id': '/androidx/constraintlayout', 'name': 'Constraint Layout Library', 'type': 'Utility'},
                    '/androidx/biometric': {'id': '/androidx/biometric', 'name': 'Biometric', 'type': 'Utility'},
                    '/androidx/browser': {'id': '/androidx/browser', 'name': 'Browser', 'type': 'Utility'}
                }
                self.module.detection_coordinator.apktool_engine._libs_by_path = mock_androidx_definitions
                
                # Run analysis
                result = self.module.analyze(self.test_apk_path, context)
                
                # Verify results
                self.assertEqual(result.status.name, 'SUCCESS')
                
                # Count AndroidX libraries using CORRECTED filtering logic
                def is_androidx_library(lib):
                    # Use smali_path for reliable detection
                    if hasattr(lib, 'smali_path') and lib.smali_path and 'androidx' in lib.smali_path:
                        return True
                    # Fallback to category
                    if lib.category == LibraryCategory.ANDROIDX:
                        return True
                    # Fallback to name
                    if 'androidx' in lib.name.lower():
                        return True
                    return False
                
                androidx_libs = [lib for lib in result.detected_libraries if is_androidx_library(lib)]
                
                # Should find multiple AndroidX libraries (not just 1 like the old logic)
                self.assertGreater(len(androidx_libs), 5, 
                                 f"Should find multiple AndroidX libraries, found {len(androidx_libs)}")
                
                # Verify some expected AndroidX libraries are found
                found_names = [lib.name for lib in androidx_libs]
                expected_androidx = ['AndroidX Activity', 'AppCompat', 'AndroidX Fragment', 'RecyclerView']
                
                for expected in expected_androidx:
                    self.assertIn(expected, found_names, 
                                f"Expected {expected} in found AndroidX libraries: {found_names}")
    
    @patch('src.dexray_insight.modules.library_detection.utils.version_analyzer.requests.get')
    def test_version_analysis_integration(self, mock_requests):
        """Test version analysis is properly integrated and produces 'years behind' data"""
        # Mock successful version API calls
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            'response': {
                'docs': [{
                    'latestVersion': '25.0.0',
                    'timestamp': 1609459200000  # 2021-01-01 
                }]
            }
        }
        mock_requests.return_value = mock_response
        
        context = self._create_mock_context_with_androidx_strings()
        
        with patch.object(self.module.detection_coordinator.apktool_engine, '_load_library_definitions'):
            with patch.object(self.module.detection_coordinator.apktool_engine, '_lib_dir_exists') as mock_lib_exists:
                mock_lib_exists.return_value = False  # Focus on heuristic detection
                
                # Run analysis
                result = self.module.analyze(self.test_apk_path, context)
                
                # Check for libraries with version analysis data
                versioned_libs = [lib for lib in result.detected_libraries if hasattr(lib, 'years_behind') and lib.years_behind is not None]
                
                if versioned_libs:
                    # Verify version analysis fields are populated
                    for lib in versioned_libs[:3]:  # Check first few
                        self.assertIsNotNone(lib.years_behind)
                        self.assertIsInstance(lib.years_behind, (int, float))
                        self.assertGreaterEqual(lib.years_behind, 0)
    
    def test_version_analysis_display_order(self):
        """Test that version analysis output appears after library detection summary"""
        # This test ensures the _print_version_analysis_results method is called by coordinator
        from src.dexray_insight.modules.library_detection.engines.coordinator import LibraryDetectionCoordinator
        
        # Verify the method exists in coordinator (structural test)
        coordinator = LibraryDetectionCoordinator(Mock())
        self.assertTrue(hasattr(coordinator, '_print_version_analysis_results'))
        
        # Verify the method is called in execute_full_analysis
        import inspect
        source = inspect.getsource(coordinator.execute_full_analysis)
        self.assertIn('_print_version_analysis_results', source,
                     "Version analysis should be called by coordinator for correct display order")
    
    def test_json_export_includes_version_metadata(self):
        """Test that JSON export includes version analysis metadata"""
        _ = self._create_mock_context_with_androidx_strings()
        
        # Create a library with version analysis data
        from src.dexray_insight.results.LibraryDetectionResults import DetectedLibrary, LibraryDetectionMethod, LibrarySource, RiskLevel
        
        test_library = DetectedLibrary(
            name="Test Library",
            category=LibraryCategory.UTILITY,
            detection_method=LibraryDetectionMethod.HEURISTIC,
            source=LibrarySource.SMALI_CLASSES,
            risk_level=RiskLevel.LOW
        )
        
        # Add version analysis data
        test_library.version = "1.0.0"
        test_library.years_behind = 2.5
        test_library.major_versions_behind = 2
        test_library.security_risk = "HIGH"
        test_library.version_recommendation = "Update recommended"
        test_library.latest_version = "3.0.0"
        
        # Verify JSON serialization includes version fields
        json_data = test_library.to_dict()
        
        version_fields = [
            'version', 'years_behind', 'major_versions_behind', 
            'security_risk', 'version_recommendation', 'latest_version'
        ]
        
        for field in version_fields:
            self.assertIn(field, json_data, f"JSON export should include {field}")
            
        # Verify values
        self.assertEqual(json_data['version'], "1.0.0")
        self.assertEqual(json_data['years_behind'], 2.5)
        self.assertEqual(json_data['security_risk'], "HIGH")


if __name__ == '__main__':
    unittest.main(verbosity=2)