#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration tests for LibraryDetectionCoordinator with ApktoolDetectionEngine

Tests the integration between the coordinator and the new apktool detection engine,
ensuring proper orchestration and result aggregation.
"""

import tempfile
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from src.dexray_insight.modules.library_detection.engines.coordinator import LibraryDetectionCoordinator
from src.dexray_insight.modules.library_detection.engines.apktool_detection_engine import ApktoolDetectionEngine
from src.dexray_insight.results.LibraryDetectionResults import (
    DetectedLibrary, LibraryDetectionMethod, LibraryCategory, LibrarySource
)
from src.dexray_insight.core.base_classes import AnalysisContext, AnalysisStatus


class TestLibraryDetectionCoordinatorIntegration(unittest.TestCase):
    """Integration tests for LibraryDetectionCoordinator with ApktoolDetectionEngine"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create mock parent module
        self.mock_parent = Mock()
        self.mock_parent.name = "library_detection"
        self.mock_parent.logger = Mock()
        self.mock_parent.config = {
            'apktool_detection': {
                'enable_pattern_detection': True,
                'enable_properties_detection': True,
                'enable_buildconfig_detection': True,
                'auto_update_definitions': False
            }
        }
        self.mock_parent.enable_stage1 = True
        self.mock_parent.enable_stage2 = True
        self.mock_parent._deduplicate_libraries = lambda libs: libs  # No deduplication for testing
        
        # Create coordinator
        self.coordinator = LibraryDetectionCoordinator(self.mock_parent)
        
    def test_coordinator_initialization(self):
        """Test that coordinator properly initializes with apktool engine"""
        self.assertIsNotNone(self.coordinator.apktool_engine)
        self.assertIsInstance(self.coordinator.apktool_engine, ApktoolDetectionEngine)
        
    def test_execute_full_analysis_with_apktool(self):
        """Test full analysis execution including apktool detection"""
        # Mock the other engines to return empty results
        mock_heuristic_result = {
            'libraries': [self._create_test_library("Heuristic Lib", LibraryDetectionMethod.HEURISTIC)],
            'execution_time': 0.1
        }
        mock_similarity_result = {
            'libraries': [self._create_test_library("Similarity Lib", LibraryDetectionMethod.SIMILARITY)],
            'execution_time': 0.2
        }
        mock_native_result = {
            'libraries': [self._create_test_library("Native Lib", LibraryDetectionMethod.NATIVE)],
            'execution_time': 0.1
        }
        mock_androidx_result = {
            'libraries': [],
            'execution_time': 0.1
        }
        
        self.coordinator.heuristic_engine.execute_detection = Mock(return_value=mock_heuristic_result)
        self.coordinator.similarity_engine.execute_detection = Mock(return_value=mock_similarity_result)
        self.coordinator.native_engine.execute_detection = Mock(return_value=mock_native_result)
        self.coordinator.androidx_engine.execute_detection = Mock(return_value=mock_androidx_result)
        
        # Mock apktool engine
        mock_apktool_libraries = [
            self._create_test_library("Apktool Lib 1", LibraryDetectionMethod.PATTERN_MATCHING),
            self._create_test_library("Apktool Lib 2", LibraryDetectionMethod.FILE_ANALYSIS)
        ]
        self.coordinator.apktool_engine.is_available = Mock(return_value=True)
        self.coordinator.apktool_engine.detect_libraries = Mock(return_value=mock_apktool_libraries)
        
        # Create mock context
        context = self._create_mock_context_with_apktool()
        
        # Execute analysis
        result = self.coordinator.execute_full_analysis("/test/app.apk", context)
        
        # Verify results
        self.assertEqual(result.status, AnalysisStatus.SUCCESS)
        self.assertEqual(len(result.detected_libraries), 5)  # All engines + apktool
        
        # Verify apktool engine was called
        self.coordinator.apktool_engine.is_available.assert_called_once_with(context)
        self.coordinator.apktool_engine.detect_libraries.assert_called_once()
        
        # Verify log messages
        self.mock_parent.logger.info.assert_any_call("Apktool results available, running apktool-based detection")
        self.mock_parent.logger.info.assert_any_call("Apktool detection found 2 libraries")
        
    def test_execute_full_analysis_without_apktool(self):
        """Test full analysis execution when apktool is not available"""
        # Mock the other engines to return results
        mock_heuristic_result = {
            'libraries': [self._create_test_library("Heuristic Lib", LibraryDetectionMethod.HEURISTIC)],
            'execution_time': 0.1
        }
        mock_similarity_result = {'libraries': [], 'execution_time': 0.1}
        mock_native_result = {'libraries': [], 'execution_time': 0.1}
        mock_androidx_result = {'libraries': [], 'execution_time': 0.1}
        
        self.coordinator.heuristic_engine.execute_detection = Mock(return_value=mock_heuristic_result)
        self.coordinator.similarity_engine.execute_detection = Mock(return_value=mock_similarity_result)
        self.coordinator.native_engine.execute_detection = Mock(return_value=mock_native_result)
        self.coordinator.androidx_engine.execute_detection = Mock(return_value=mock_androidx_result)
        
        # Mock apktool engine as unavailable
        self.coordinator.apktool_engine.is_available = Mock(return_value=False)
        self.coordinator.apktool_engine.detect_libraries = Mock()
        
        # Create mock context without apktool
        context = self._create_mock_context_without_apktool()
        
        # Execute analysis
        result = self.coordinator.execute_full_analysis("/test/app.apk", context)
        
        # Verify results
        self.assertEqual(result.status, AnalysisStatus.SUCCESS)
        self.assertEqual(len(result.detected_libraries), 1)  # Only heuristic result
        
        # Verify apktool engine was checked but not executed
        self.coordinator.apktool_engine.is_available.assert_called_once_with(context)
        self.coordinator.apktool_engine.detect_libraries.assert_not_called()
        
        # Verify log messages
        self.mock_parent.logger.debug.assert_any_call("Apktool results not available, skipping apktool-based detection")
        
    def test_apktool_engine_error_handling(self):
        """Test error handling when apktool engine fails"""
        # Mock other engines
        mock_result = {'libraries': [], 'execution_time': 0.1}
        self.coordinator.heuristic_engine.execute_detection = Mock(return_value=mock_result)
        self.coordinator.similarity_engine.execute_detection = Mock(return_value=mock_result)
        self.coordinator.native_engine.execute_detection = Mock(return_value=mock_result)
        self.coordinator.androidx_engine.execute_detection = Mock(return_value=mock_result)
        
        # Mock apktool engine to raise exception
        self.coordinator.apktool_engine.is_available = Mock(return_value=True)
        self.coordinator.apktool_engine.detect_libraries = Mock(side_effect=Exception("Apktool engine failed"))
        
        context = self._create_mock_context_with_apktool()
        
        # Execute analysis
        result = self.coordinator.execute_full_analysis("/test/app.apk", context)
        
        # Analysis should continue despite apktool failure (other engines still ran)
        # The result should be successful since other engines completed successfully
        self.assertEqual(result.status, AnalysisStatus.SUCCESS)
        self.assertEqual(len(result.detected_libraries), 0)
        
    def _create_test_library(self, name: str, method: LibraryDetectionMethod) -> DetectedLibrary:
        """Create a test DetectedLibrary object"""
        return DetectedLibrary(
            name=name,
            detection_method=method,
            category=LibraryCategory.UTILITY,
            confidence=0.8,
            evidence=[f"Test evidence for {name}"],
            source=LibrarySource.SMALI_CLASSES
        )
        
    def _create_mock_context_with_apktool(self) -> AnalysisContext:
        """Create mock analysis context with apktool results"""
        context = Mock()
        
        # Create temporary directory structure
        temp_dir = Path(tempfile.mkdtemp())
        apktool_dir = temp_dir / "apktool"
        apktool_dir.mkdir()
        
        # Add some files to make it non-empty
        (apktool_dir / "AndroidManifest.xml").touch()
        (apktool_dir / "smali").mkdir()
        
        mock_temporal_paths = Mock()
        mock_temporal_paths.apktool_dir = apktool_dir
        context.temporal_paths = mock_temporal_paths
        
        return context
        
    def _create_mock_context_without_apktool(self) -> AnalysisContext:
        """Create mock analysis context without apktool results"""
        context = Mock()
        context.temporal_paths = None
        return context


class TestApktoolDetectionEngineCoordinatorIntegration(unittest.TestCase):
    """Test the specific integration between ApktoolDetectionEngine and coordinator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'apktool_detection': {
                'enable_pattern_detection': True,
                'enable_properties_detection': True,
                'enable_buildconfig_detection': True,
                'auto_update_definitions': False
            }
        }
        self.mock_logger = Mock()
        
    def test_apktool_engine_availability_check(self):
        """Test availability check integration"""
        engine = ApktoolDetectionEngine(self.config, self.mock_logger)
        
        # Test with no temporal paths
        context_no_paths = Mock()
        context_no_paths.temporal_paths = None
        self.assertFalse(engine.is_available(context_no_paths))
        
        # Test with empty temporal paths
        context_empty = Mock()
        mock_paths = Mock()
        mock_paths.apktool_dir = None
        context_empty.temporal_paths = mock_paths
        self.assertFalse(engine.is_available(context_empty))
        
        # Test with valid temporal paths
        with tempfile.TemporaryDirectory() as temp_dir:
            apktool_dir = Path(temp_dir)
            (apktool_dir / "test.txt").touch()  # Make non-empty
            
            context_valid = Mock()
            mock_paths = Mock()
            mock_paths.apktool_dir = apktool_dir
            context_valid.temporal_paths = mock_paths
            
            self.assertTrue(engine.is_available(context_valid))
            
    @patch('src.dexray_insight.modules.library_detection.engines.apktool_detection_engine.ApktoolDetectionEngine._load_library_definitions')
    def test_detect_libraries_orchestration(self, mock_load_defs):
        """Test library detection orchestration"""
        engine = ApktoolDetectionEngine(self.config, self.mock_logger)
        
        # Mock library definitions to avoid file I/O
        mock_load_defs.return_value = None
        engine._libs_by_path = {}  # Empty for this test
        
        with tempfile.TemporaryDirectory() as temp_dir:
            apktool_dir = Path(temp_dir)
            
            # Create test files for different detection approaches
            
            # 1. Properties file
            props_file = apktool_dir / "test.properties"
            with open(props_file, 'w') as f:
                f.write("version=1.0.0\nclient=test-properties-lib\n")
                
            # 2. BuildConfig.smali file
            buildconfig_file = apktool_dir / "BuildConfig.smali"
            with open(buildconfig_file, 'w') as f:
                f.write(""".class public final Lcom/test/BuildConfig;
.field public static final APPLICATION_ID:Ljava/lang/String; = "com.test.buildconfig"
.field public static final VERSION_NAME:Ljava/lang/String; = "2.0.0"
""")
            
            # Create mock context
            context = Mock()
            mock_paths = Mock()
            mock_paths.apktool_dir = apktool_dir
            context.temporal_paths = mock_paths
            
            errors = []
            libraries = engine.detect_libraries(context, errors)
            
            # Should detect libraries from properties and BuildConfig
            self.assertGreaterEqual(len(libraries), 2)
            
            # Verify different detection methods are used
            methods = {lib.detection_method for lib in libraries}
            method_values = {method.value for method in methods}
            self.assertIn(LibraryDetectionMethod.FILE_ANALYSIS.value, method_values)
            self.assertIn(LibraryDetectionMethod.BUILDCONFIG_ANALYSIS.value, method_values)
            
    def test_configuration_inheritance(self):
        """Test that configuration is properly inherited and used"""
        # Test with disabled detection methods
        disabled_config = {
            'apktool_detection': {
                'enable_pattern_detection': False,
                'enable_properties_detection': True,
                'enable_buildconfig_detection': False,
                'auto_update_definitions': False
            }
        }
        
        engine = ApktoolDetectionEngine(disabled_config, self.mock_logger)
        
        self.assertFalse(engine.enable_pattern_detection)
        self.assertTrue(engine.enable_properties_detection)
        self.assertFalse(engine.enable_buildconfig_detection)
        
        # Test that only enabled methods run
        with tempfile.TemporaryDirectory() as temp_dir:
            apktool_dir = Path(temp_dir)
            
            # Create files for all detection types
            props_file = apktool_dir / "test.properties"
            with open(props_file, 'w') as f:
                f.write("version=1.0.0\nclient=test-lib\n")
                
            buildconfig_file = apktool_dir / "BuildConfig.smali"
            with open(buildconfig_file, 'w') as f:
                f.write(""".class public final Lcom/test/BuildConfig;
.field public static final APPLICATION_ID:Ljava/lang/String; = "com.test"
""")
            
            context = Mock()
            mock_paths = Mock()
            mock_paths.apktool_dir = apktool_dir
            context.temporal_paths = mock_paths
            
            errors = []
            libraries = engine.detect_libraries(context, errors)
            
            # Should only detect from properties (buildconfig disabled)
            self.assertEqual(len(libraries), 1)
            self.assertEqual(libraries[0].detection_method.value, LibraryDetectionMethod.FILE_ANALYSIS.value)


if __name__ == '__main__':
    unittest.main(verbosity=2)